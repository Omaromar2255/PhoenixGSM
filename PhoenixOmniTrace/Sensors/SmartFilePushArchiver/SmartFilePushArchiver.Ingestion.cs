using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace PhoenixGSM.OmniTrace.Sensors;

public sealed partial class SmartFilePushArchiver
{
    /// <summary>
    /// Fast, non-blocking packet ingestion on the USB capture thread.
    /// Supports coalesced multi-file sync buffers and tiny files (e.g. 72-byte ASKSW.xml, trustedTime).
    /// </summary>
    public bool ProcessOutboundSyncOrBulkChunk(
        byte[] chunk,
        string dir,
        string epHex,
        uint actualUrbLength,
        out CapturedPushedFileRecord? completedRecord)
    {
        completedRecord = null;
        if (chunk == null || chunk.Length == 0 || dir != "OUT") return false;

        lock (_transferLock)
        {
            return ProcessChunkInternalLocked(chunk, epHex, actualUrbLength, depth: 0);
        }
    }

    private bool ProcessChunkInternalLocked(byte[] chunk, string epHex, uint actualUrbLength, int depth)
    {
        if (chunk == null || chunk.Length == 0 || depth > 8) return false;

        // 0. If the packet begins with a 24-byte ADB wire header (e.g. WRTE + payload in the same URB), strip the 24-byte header
        while (chunk.Length >= 24 && IsAdbWireHeader(chunk, 0))
        {
            if (chunk.Length == 24) return false;
            chunk = chunk[24..];
        }

        // Convert the ENTIRE chunk (up to 1024B) to ASCII so SEND tokens at offset > 160 are NEVER missed!
        string fullChunkAscii = Encoding.ASCII.GetString(chunk);
        string cleanLineTrimmed = fullChunkAscii.Trim('\r', '\n', '\0', ' ');

        // Never treat shell commands or host commands as raw file push chunks
        if (cleanLineTrimmed.StartsWith("shell:", StringComparison.OrdinalIgnoreCase) ||
            cleanLineTrimmed.StartsWith("host:", StringComparison.OrdinalIgnoreCase) ||
            cleanLineTrimmed.StartsWith("chmod ", StringComparison.OrdinalIgnoreCase) ||
            cleanLineTrimmed.StartsWith("rm ", StringComparison.OrdinalIgnoreCase) ||
            cleanLineTrimmed.StartsWith("ln ", StringComparison.OrdinalIgnoreCase) ||
            cleanLineTrimmed.StartsWith("cp ", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        string combined = _pendingHeaderBuffer + fullChunkAscii;

        bool hasSendToken = StartsWithAscii(chunk, "SEND") || FindAsciiTokenOffset(chunk, "SEND", 0, chunk.Length) >= 0;
        bool hasStatToken = StartsWithAscii(chunk, "STAT") || FindAsciiTokenOffset(chunk, "STAT", 0, Math.Min(chunk.Length, 64)) >= 0;

        // 1. Check for explicit SEND "/path,mode" anywhere in the chunk
        Match sendMatch = SendPathAndModeRegex.Match(combined);
        if (sendMatch.Success)
        {
            string matchedPath = sendMatch.Groups[1].Value.Trim();
            string matchedMode = sendMatch.Groups[2].Value.Trim();

            // Check if this SEND starts partway through the chunk (after the end of a previous file!)
            int sendTokenIdx = FindAsciiTokenOffset(chunk, "SEND", 0, chunk.Length);
            int pathIdxInChunk = fullChunkAscii.IndexOf(matchedPath, StringComparison.OrdinalIgnoreCase);
            int newFileStartOffset = sendTokenIdx >= 0 ? sendTokenIdx : (pathIdxInChunk >= 8 ? pathIdxInChunk - 8 : 0);

            if (_isInsideTransfer && !string.IsNullOrEmpty(_activeTargetPath) &&
                !string.Equals(_activeTargetPath, matchedPath, StringComparison.OrdinalIgnoreCase))
            {
                // If bytes before newFileStartOffset belong to the previous file, append them before flushing!
                if (newFileStartOffset > 0)
                {
                    int prevEnd = newFileStartOffset;
                    int prevDone = FindDoneTrailerOffset(chunk[..newFileStartOffset], 0);
                    if (prevDone >= 0) prevEnd = prevDone;
                    if (prevEnd > 0)
                    {
                        _activeUploadStream.Write(chunk, 0, prevEnd);
                        if (_firstHeaderSignature == null && _activeUploadStream.Length > 0)
                        {
                            byte[] prevArr = _activeUploadStream.ToArray();
                            _firstHeaderSignature = prevArr[..Math.Min(prevArr.Length, 64)];
                        }
                    }
                }

                EnqueueCurrentTransferForBackgroundSave(epHex, "NewSendStarted");

                if (newFileStartOffset > 0 && newFileStartOffset < chunk.Length)
                {
                    return ProcessChunkInternalLocked(chunk[newFileStartOffset..], epHex, (uint)(chunk.Length - newFileStartOffset), depth + 1);
                }
            }

            if (IsIgnoredNoiseFile(matchedPath))
            {
                _pendingHeaderBuffer = string.Empty;
                return false;
            }

            _activeTargetPath = matchedPath;
            _activeMode = matchedMode;
            _isInsideTransfer = true;
            _activeUploadStream.SetLength(0);
            _declaredDataSize = 0;
            _totalActualUrbBytes = 0;
            _firstHeaderSignature = null;
            _eagerSnapshotTask = null;
            _hadTruncatedUrb = actualUrbLength > chunk.Length;
            _pendingHeaderBuffer = string.Empty;
            _lastChunkTime = DateTime.UtcNow;

            int searchDataFrom = pathIdxInChunk >= 0 ? pathIdxInChunk + matchedPath.Length : 0;
            int dataIdx = FindDataHeaderOffset(chunk, searchDataFrom);
            if (dataIdx >= 0 && dataIdx + 8 <= chunk.Length)
            {
                uint dLen = BitConverter.ToUInt32(chunk, dataIdx + 4);
                if (dLen > 0 && dLen <= 64 * 1024 * 1024)
                {
                    _declaredDataSize += dLen;
                }

                int payloadStart = dataIdx + 8;
                bool isTruncatedPacket = actualUrbLength > chunk.Length;

                // Exact framing for small files (e.g. 72-byte ASKSW.xml where payloadStart + dLen <= chunk.Length)
                int exactDataEnd = (dLen > 0 && payloadStart + (long)dLen <= chunk.Length)
                    ? payloadStart + (int)dLen
                    : -1;

                int doneIdx = -1;
                if (exactDataEnd >= payloadStart && exactDataEnd + 4 <= chunk.Length &&
                    chunk[exactDataEnd] == 'D' && chunk[exactDataEnd + 1] == 'O' &&
                    chunk[exactDataEnd + 2] == 'N' && chunk[exactDataEnd + 3] == 'E')
                {
                    doneIdx = exactDataEnd;
                }
                else if (!isTruncatedPacket)
                {
                    doneIdx = FindDoneTrailerOffset(chunk, payloadStart);
                }

                int payloadEnd = (doneIdx >= payloadStart)
                    ? doneIdx
                    : (exactDataEnd >= payloadStart ? exactDataEnd : chunk.Length);

                if (payloadEnd > payloadStart)
                {
                    int count = payloadEnd - payloadStart;
                    _activeUploadStream.Write(chunk, payloadStart, count);

                    if (_firstHeaderSignature == null && count >= 1)
                    {
                        _firstHeaderSignature = chunk[payloadStart..(payloadStart + Math.Min(count, 64))];
                        StartEagerMidTransferSnapshot(_activeTargetPath, _firstHeaderSignature, _declaredDataSize > 0 ? _declaredDataSize : count);
                    }
                }

                _totalActualUrbBytes += Math.Max(actualUrbLength, (uint)chunk.Length);

                if (doneIdx >= payloadStart)
                {
                    EnqueueCurrentTransferForBackgroundSave(epHex, "SinglePacketSendDataDone");

                    // If another SEND/STAT follows DONE + 4-byte mtime in the same buffer, process it immediately!
                    int nextPos = doneIdx + 8;
                    if (nextPos < chunk.Length)
                    {
                        ProcessChunkInternalLocked(chunk[nextPos..], epHex, (uint)(chunk.Length - nextPos), depth + 1);
                    }
                    return true;
                }
            }

            return false;
        }

        // 2. Check for STAT path check preceding SEND
        if (hasStatToken || hasSendToken)
        {
            Match statMatch = StatPathRegex.Match(combined);
            if (statMatch.Success)
            {
                string statPath = statMatch.Groups[1].Value.Trim();
                if (!IsIgnoredNoiseFile(statPath))
                {
                    if (_isInsideTransfer && _activeUploadStream.Length > 0 &&
                        !string.IsNullOrEmpty(_activeTargetPath) &&
                        !string.Equals(_activeTargetPath, statPath, StringComparison.OrdinalIgnoreCase))
                    {
                        EnqueueCurrentTransferForBackgroundSave(epHex, "NewStatStarted");
                    }
                    _pendingStatPath = statPath;
                }
                _pendingHeaderBuffer = hasSendToken ? fullChunkAscii : string.Empty;
                _lastChunkTime = DateTime.UtcNow;
                return false;
            }

            _pendingHeaderBuffer = fullChunkAscii;
            _lastChunkTime = DateTime.UtcNow;
            return false;
        }

        // 3. Active transfer continuation chunk
        if (_isInsideTransfer || (!string.IsNullOrEmpty(_pendingStatPath) && StartsWithAscii(chunk, "DATA")))
        {
            if (!_isInsideTransfer)
            {
                _activeTargetPath = _pendingStatPath;
                _isInsideTransfer = true;
            }

            if (actualUrbLength > chunk.Length)
            {
                _hadTruncatedUrb = true;
            }

            _lastChunkTime = DateTime.UtcNow;
            _totalActualUrbBytes += Math.Max(actualUrbLength, (uint)chunk.Length);

            // Check for standalone DONE packet ("DONE" + 4-byte mtime)
            if (chunk.Length >= 8 && StartsWithAscii(chunk, "DONE"))
            {
                EnqueueCurrentTransferForBackgroundSave(epHex, "StandaloneDonePacket");
                if (chunk.Length > 8)
                {
                    ProcessChunkInternalLocked(chunk[8..], epHex, (uint)(chunk.Length - 8), depth + 1);
                }
                return true;
            }

            int payloadStart = 0;
            uint currentBlockDeclaredLen = 0;
            if (StartsWithAscii(chunk, "DATA") && chunk.Length >= 8)
            {
                uint dLen = BitConverter.ToUInt32(chunk, 4);
                if (dLen > 0 && dLen <= 64 * 1024 * 1024)
                {
                    _declaredDataSize += dLen;
                    currentBlockDeclaredLen = dLen;
                }
                payloadStart = 8;
            }

            bool isTruncatedPacket = actualUrbLength > chunk.Length;
            int exactDataEnd = (currentBlockDeclaredLen > 0 && payloadStart + (long)currentBlockDeclaredLen <= chunk.Length)
                ? payloadStart + (int)currentBlockDeclaredLen
                : -1;

            int doneIdx = -1;
            if (exactDataEnd >= payloadStart && exactDataEnd + 4 <= chunk.Length &&
                chunk[exactDataEnd] == 'D' && chunk[exactDataEnd + 1] == 'O' &&
                chunk[exactDataEnd + 2] == 'N' && chunk[exactDataEnd + 3] == 'E')
            {
                doneIdx = exactDataEnd;
            }
            else if (!isTruncatedPacket)
            {
                doneIdx = FindDoneTrailerOffset(chunk, payloadStart);
            }

            int payloadEnd = (doneIdx >= payloadStart)
                ? doneIdx
                : (exactDataEnd >= payloadStart ? exactDataEnd : chunk.Length);

            if (payloadEnd > payloadStart)
            {
                int count = payloadEnd - payloadStart;
                _activeUploadStream.Write(chunk, payloadStart, count);

                if (_firstHeaderSignature == null && count >= 1)
                {
                    _firstHeaderSignature = chunk[payloadStart..(payloadStart + Math.Min(count, 64))];
                    StartEagerMidTransferSnapshot(_activeTargetPath, _firstHeaderSignature, _declaredDataSize > 0 ? _declaredDataSize : count);
                }
            }

            if (doneIdx >= payloadStart)
            {
                EnqueueCurrentTransferForBackgroundSave(epHex, "DoneTrailerInChunk");
                int nextPos = doneIdx + 8;
                if (nextPos < chunk.Length)
                {
                    ProcessChunkInternalLocked(chunk[nextPos..], epHex, (uint)(chunk.Length - nextPos), depth + 1);
                }
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Non-blocking check when a shell command arrives.
    /// 1. Decodes inline Base64 file writes.
    /// 2. Flushes any active file transfer.
    /// 3. Passively verifies that any file referenced in /data/local/tmp/ (e.g. chmod 777 /data/local/tmp/retail/ASKSW.xml)
    ///    has been saved to CapturedArtifacts, recovering it from Host Disk if needed (ZERO adb.exe spawning!).
    /// </summary>
    public bool CheckShellCommandForInlineFileOrFlush(
        string shellCommand,
        int processId,
        string processName,
        out CapturedPushedFileRecord? completedRecord)
    {
        completedRecord = null;
        if (string.IsNullOrWhiteSpace(shellCommand)) return false;

        string trimmed = shellCommand.Trim();

        // 1. Inline Base64 file creation: echo '<base64>' | base64 -d > /path
        var b64Match = Base64EchoRegex.Match(trimmed);
        if (b64Match.Success)
        {
            string b64Str = b64Match.Groups[1].Value.Trim();
            string destPath = b64Match.Groups[2].Value.Trim();
            _ = Task.Run(() =>
            {
                try
                {
                    byte[] decoded = Convert.FromBase64String(b64Str);
                    if (decoded.Length > 0)
                    {
                        var rec = SaveSingleCleanFileToDisk(decoded, destPath, "0755", "Base64 Inline Stream");
                        if (rec != null) OnFileArchivedAsync?.Invoke(rec, "0x01");
                    }
                }
                catch { }
            });
        }

        // 2. Auto-flush active transfer if a shell command starts (chmod, unzip, pm install, etc.)
        lock (_transferLock)
        {
            if (_isInsideTransfer && !string.IsNullOrEmpty(_activeTargetPath))
            {
                EnqueueCurrentTransferForBackgroundSave("0x01", "ShellTransitionFlush");
            }
        }

        // 3. Passive Host-Disk Verification for any /data/local/tmp/ file referenced by chmod/cp/mv/unzip
        if (!trimmed.StartsWith("rm ", StringComparison.OrdinalIgnoreCase) &&
            !trimmed.Contains("rm -r", StringComparison.OrdinalIgnoreCase))
        {
            var matches = ShellFilePathRegex.Matches(trimmed);
            foreach (Match pm in matches)
            {
                string refPath = pm.Groups[1].Value.Trim();
                if (string.IsNullOrEmpty(refPath) || refPath.EndsWith("/") || IsIgnoredNoiseFile(refPath))
                    continue;

                if (!_savedFileSizesByPath.ContainsKey(refPath))
                {
                    _jobChannel.Writer.TryWrite(new PendingFileArchiveJob
                    {
                        TargetPath = refPath,
                        Mode = "0777",
                        WireBytes = [],
                        HeaderSignature = null,
                        EagerSnapshotTask = null,
                        TotalDeclaredBytes = 0,
                        TotalActualUrbBytes = 0,
                        HadTruncatedUrb = true,
                        EndpointHex = "0x01",
                        TriggerReason = "PassiveShellReferenceVerify"
                    });
                }
            }
        }

        return false;
    }

    /// <summary>
    /// Enqueues any active file upload to the background worker without blocking the caller.
    /// Ignores transient CLSE signals if chunks arrived within the last 350ms (mid-stream).
    /// </summary>
    public bool FlushIfActive(out CapturedPushedFileRecord? completedRecord, bool isClseSignal = false)
    {
        completedRecord = null;
        lock (_transferLock)
        {
            if (!_isInsideTransfer || string.IsNullOrEmpty(_activeTargetPath))
            {
                return false;
            }

            if (isClseSignal && (DateTime.UtcNow - _lastChunkTime).TotalMilliseconds < 350)
            {
                return false;
            }

            EnqueueCurrentTransferForBackgroundSave("0x01", isClseSignal ? "CLSE" : "ExplicitFlush");
            return false;
        }
    }

    private void EnqueueCurrentTransferForBackgroundSave(string epHex, string reason)
    {
        string targetPath = !string.IsNullOrWhiteSpace(_activeTargetPath) ? _activeTargetPath : _pendingStatPath;
        byte[] wireBytes = _activeUploadStream.ToArray();
        byte[]? sig = _firstHeaderSignature;
        Task<byte[]?>? eagerTask = _eagerSnapshotTask;
        string mode = _activeMode;
        long declared = _declaredDataSize;
        long actualUrb = _totalActualUrbBytes;
        bool truncated = _hadTruncatedUrb;

        _isInsideTransfer = false;
        _activeTargetPath = string.Empty;
        _pendingStatPath = string.Empty;
        _activeUploadStream.SetLength(0);
        _declaredDataSize = 0;
        _totalActualUrbBytes = 0;
        _firstHeaderSignature = null;
        _eagerSnapshotTask = null;
        _hadTruncatedUrb = false;
        _pendingHeaderBuffer = string.Empty;

        if (string.IsNullOrWhiteSpace(targetPath) || IsIgnoredNoiseFile(targetPath)) return;

        byte[] cleanWire = StripDoneTrailer(wireBytes);
        if (!truncated && declared > 0 && cleanWire.Length > declared)
        {
            cleanWire = cleanWire[..(int)declared];
        }

        _jobChannel.Writer.TryWrite(new PendingFileArchiveJob
        {
            TargetPath = targetPath,
            Mode = mode,
            WireBytes = cleanWire,
            HeaderSignature = sig,
            EagerSnapshotTask = eagerTask,
            TotalDeclaredBytes = declared,
            TotalActualUrbBytes = actualUrb,
            HadTruncatedUrb = truncated,
            EndpointHex = epHex,
            TriggerReason = reason
        });
    }
}
