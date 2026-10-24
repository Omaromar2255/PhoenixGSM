using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace PhoenixGSM.OmniTrace.Sensors;

public sealed partial class SmartFilePushArchiver
{
    private bool _isStreamedInstallTransfer = false;

    /// <summary>
    /// Fast, non-blocking packet ingestion on the USB capture thread (or USB ETW / Proxy stream).
    /// Supports BOTH:
    /// 1. Standard ADB Sync (`STAT` / `SEND` / `DATA` / `DONE`) file transfers.
    /// 2. Direct PC-to-Device Streamed APK Installations (`exec:cmd package install-write -S <size> ...`,
    ///    `abb_exec:package\0install-write\0-S\0<size>...`, `exec:pm install -S <size>`) where raw APK ZIP bytes (`PK\x03\x04`)
    ///    are streamed directly without `adb push` and without `SEND`/`DATA` headers!
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

    /// <summary>
    /// Direct CLI / Process interception hook for:
    /// - `adb push <localSource> <remoteTarget>`
    /// - `adb install [-r -t -d -g] <localApk>`
    /// - `adb install-multiple [-r -t -p] <base.apk> <split1.apk> ...`
    /// - `ideviceinstaller [-u <udid>] -i <localIpa>`
    /// Works whether the USB Kernel Filter is ON or OFF!
    /// </summary>
    public void NotifyAdbPushCommandLine(
        string? commandLine,
        int pid,
        int parentPid,
        string? executablePath,
        bool isKernelDriverActive)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return;

        var itemsToCapture = new List<(string LocalSource, string RemoteTarget, bool IsDirectAppInstall)>();

        if (AdbPushArtifactSensor.TryParseAdbPushCommand(commandLine, out string pushLocal, out string pushRemote))
        {
            itemsToCapture.Add((pushLocal, pushRemote, false));
        }
        else if (AdbPushArtifactSensor.TryParseDirectAppInstallCommand(commandLine, out var installFiles, out bool isAppleIpa))
        {
            foreach (string pkgFile in installFiles)
            {
                string fn = Path.GetFileName(pkgFile.Trim('"', '\'', ' '));
                if (string.IsNullOrWhiteSpace(fn)) continue;
                string virtualTarget = isAppleIpa
                    ? $"PublicStaging/{fn}"
                    : $"/data/app/streamed_install/{fn}";
                itemsToCapture.Add((pkgFile, virtualTarget, true));
            }
        }

        if (itemsToCapture.Count == 0) return;

        // Capture process working directories IMMEDIATELY before short-lived `adb.exe` / `ideviceinstaller.exe` exits
        string? pidCwd = pid > 4 ? TryGetProcessCurrentDirectory(pid) : null;
        string? parentCwd = parentPid > 4 ? TryGetProcessCurrentDirectory(parentPid) : null;
        string? exeDir = !string.IsNullOrWhiteSpace(executablePath) ? Path.GetDirectoryName(executablePath) : null;

        foreach (var item in itemsToCapture)
        {
            string localSource = item.LocalSource;
            string remoteTarget = item.RemoteTarget;
            bool isDirectInstall = item.IsDirectAppInstall;

            if (IsIgnoredNoiseFile(localSource)) continue;

            string localFileName = Path.GetFileName(localSource.Trim('"', '\'', ' '));
            remoteTarget = remoteTarget.Trim('"', '\'', ' ').Replace('\\', '/');
            if (remoteTarget.EndsWith("/") ||
                remoteTarget.Equals("/data/local/tmp", StringComparison.OrdinalIgnoreCase) ||
                remoteTarget.Equals("/sdcard", StringComparison.OrdinalIgnoreCase) ||
                remoteTarget.Equals("/tmp", StringComparison.OrdinalIgnoreCase))
            {
                remoteTarget = remoteTarget.TrimEnd('/') + "/" + localFileName;
            }

            if (IsIgnoredNoiseFile(remoteTarget)) continue;

            string dedupeKey = $"{pid}:{localSource}->{remoteTarget}";
            DateTime now = DateTime.UtcNow;
            if (_recentCliPushDedupe.TryGetValue(dedupeKey, out var prevTime) && (now - prevTime).TotalMilliseconds < 1500)
            {
                continue;
            }
            _recentCliPushDedupe[dedupeKey] = now;

            _ = Task.Run(async () =>
            {
                try
                {
                    string? resolvedPath = ResolveCliPushLocalFile(localSource, pidCwd, parentCwd, exeDir);
                    byte[]? fullBytes = null;

                    if (!string.IsNullOrEmpty(resolvedPath) && File.Exists(resolvedPath))
                    {
                        fullBytes = TryReadSharedFile(resolvedPath, expectedHeader: null);
                    }

                    if (fullBytes == null || fullBytes.Length == 0)
                    {
                        fullBytes = TryRecoverFromHostDisk(localFileName, headerSig: null);
                    }

                    if (fullBytes != null && fullBytes.Length > 0)
                    {
                        var entry = (resolvedPath ?? localSource, fullBytes, DateTime.UtcNow);
                        _recentCliPushByTarget[remoteTarget] = entry;
                        if (!string.IsNullOrWhiteSpace(localFileName))
                        {
                            _recentCliPushByTarget[localFileName] = entry;
                        }
                        if (isDirectInstall)
                        {
                            _recentCliPushByTarget["base.apk"] = entry;
                        }
                    }

                    int waitMs = (isKernelDriverActive && !isDirectInstall) ? 550 : 80;
                    await Task.Delay(waitMs).ConfigureAwait(false);

                    if (fullBytes == null || fullBytes.Length == 0) return;

                    bool alreadyHandledByWire = false;
                    lock (_transferLock)
                    {
                        if (_isInsideTransfer &&
                            (string.Equals(_activeTargetPath, remoteTarget, StringComparison.OrdinalIgnoreCase) ||
                             string.Equals(Path.GetFileName(_activeTargetPath), localFileName, StringComparison.OrdinalIgnoreCase)))
                        {
                            alreadyHandledByWire = true;
                        }
                    }

                    if (alreadyHandledByWire) return;

                    if (_latestInstanceByPath.TryGetValue(remoteTarget, out var latest) &&
                        latest.FileSize >= fullBytes.Length &&
                        File.Exists(latest.LocalSavedPath) &&
                        (DateTime.UtcNow - File.GetLastWriteTimeUtc(latest.LocalSavedPath)).TotalSeconds < 2.5)
                    {
                        return;
                    }

                    long seqId;
                    int uploadNum;
                    string sessionDir;
                    string sessionFolder;

                    lock (_transferLock)
                    {
                        seqId = Interlocked.Increment(ref _transferSequenceCounter);
                        int pCount = _uploadCountByTargetPath.AddOrUpdate(remoteTarget, 1, (_, prev) => prev + 1);
                        int nCount = !string.IsNullOrWhiteSpace(localFileName)
                            ? _uploadCountByFileName.AddOrUpdate(localFileName, 1, (_, prev) => prev + 1)
                            : pCount;
                        uploadNum = Math.Max(pCount, nCount);
                        sessionDir = CurrentSessionDirectory;
                        sessionFolder = CurrentSessionFolderName;
                    }

                    string vector = isDirectInstall
                        ? "Direct PC App Install Snapshot (Full APK/IPA)"
                        : (isKernelDriverActive
                            ? "Host CLI Push Snapshot (Full Verified)"
                            : "Host CLI Push (Filter-Free Direct Capture)");

                    var savedRecord = SaveSingleCleanFileToDisk(
                        fullBytes,
                        remoteTarget,
                        "0644",
                        vector,
                        sessionDir,
                        sessionFolder,
                        uploadNum,
                        seqId,
                        isCompleteCapture: true,
                        declaredSize: fullBytes.Length,
                        kernelDroppedDelta: 0);

                    if (savedRecord != null)
                    {
                        _savedTransfersById[seqId] = (
                            savedRecord.LocalSavedPath,
                            savedRecord.SavedFileName,
                            savedRecord.FileSizeBytes,
                            savedRecord.UploadSequenceNumber,
                            true);

                        _latestInstanceByPath[remoteTarget] = (
                            savedRecord.SavedFileName,
                            savedRecord.UploadSequenceNumber,
                            savedRecord.FileSizeBytes,
                            savedRecord.LocalSavedPath);

                        OnFileArchivedAsync?.Invoke(savedRecord, isDirectInstall ? "APP-INSTALL" : "ADB-CLI");
                    }
                }
                catch { }
            });
        }
    }

    private bool ProcessChunkInternalLocked(byte[] chunk, string epHex, uint actualUrbLength, int depth)
    {
        if (chunk == null || chunk.Length == 0 || depth > 8) return false;

        // 0. Strip any leading 24-byte ADB wire header (e.g. OPEN / WRTE + payload in the same URB)
        while (chunk.Length >= 24 && IsAdbWireHeader(chunk, 0))
        {
            if (chunk.Length == 24) return false;
            chunk = chunk[24..];
        }

        // Check for explicit ADB Sync QUIT command ("QUIT" + uint32 0)
        if (chunk.Length >= 8 && StartsWithAscii(chunk, "QUIT") && BitConverter.ToUInt32(chunk, 4) == 0)
        {
            if (_isInsideTransfer && !string.IsNullOrEmpty(_activeTargetPath))
            {
                EnqueueCurrentTransferForBackgroundSave(epHex, "QuitPacketFlush");
            }
            return false;
        }

        // 0B. Check for Direct Streamed APK Installation over `exec:`, `shell:`, or Android 11+ `abb_exec:` / `abb:`!
        if (chunk.Length >= 16 &&
            (StartsWithAscii(chunk, "exec:") || StartsWithAscii(chunk, "shell:") ||
             StartsWithAscii(chunk, "abb_exec:") || StartsWithAscii(chunk, "abb:")))
        {
            string normalizedCmd = DecodeAsciiPreservingAbbArguments(chunk, Math.Min(chunk.Length, 512));
            var streamInstallMatch = StreamedApkInstallWriteRegex.Match(normalizedCmd);
            if (streamInstallMatch.Success)
            {
                if (_isInsideTransfer && !string.IsNullOrEmpty(_activeTargetPath))
                {
                    EnqueueCurrentTransferForBackgroundSave(epHex, "NewStreamedInstallStarted");
                }

                string sizeStr = !string.IsNullOrEmpty(streamInstallMatch.Groups[1].Value)
                    ? streamInstallMatch.Groups[1].Value
                    : streamInstallMatch.Groups[4].Value;
                long.TryParse(sizeStr, out long declaredApkBytes);

                string splitOrApkName = streamInstallMatch.Groups[3].Value.Trim();
                if (string.IsNullOrWhiteSpace(splitOrApkName) || splitOrApkName == "-")
                {
                    splitOrApkName = "streamed_app.apk";
                }
                else if (!splitOrApkName.EndsWith(".apk", StringComparison.OrdinalIgnoreCase))
                {
                    splitOrApkName += ".apk";
                }

                string targetVirtualPath = $"/data/app/streamed_install/{splitOrApkName}";
                StartNewTransferStateLocked(targetVirtualPath, "0644", actualUrbLength, chunk.Length);
                _isStreamedInstallTransfer = true;

                if (declaredApkBytes > 0 && declaredApkBytes <= 512L * 1024 * 1024)
                {
                    _declaredDataSize = declaredApkBytes;
                    _activeDataBlockCount = 1;
                    _remainingInCurrentDataBlock = (int)Math.Min(declaredApkBytes, int.MaxValue);
                }

                return false;
            }
            else if (normalizedCmd.Contains("install-commit", StringComparison.OrdinalIgnoreCase) &&
                     _isInsideTransfer && _isStreamedInstallTransfer)
            {
                _sawExplicitDone = true;
                _doneAlreadyStripped = true;
                EnqueueCurrentTransferForBackgroundSave(epHex, "StreamedInstallCommitFlush");
                return true;
            }
        }

        // 0C. Handle raw binary APK stream chunks during a Streamed Install (`exec:cmd package install-write` / `abb_exec:package install-write`)
        if (_isInsideTransfer && _isStreamedInstallTransfer)
        {
            if (StartsWithAscii(chunk, "shell:") || StartsWithAscii(chunk, "host:") ||
                StartsWithAscii(chunk, "exec:") || StartsWithAscii(chunk, "abb_exec:") || StartsWithAscii(chunk, "abb:"))
            {
                EnqueueCurrentTransferForBackgroundSave(epHex, "StreamedInstallNextCommandFlush");
                return false;
            }

            if (actualUrbLength > chunk.Length)
            {
                _hadTruncatedUrb = true;
            }

            _lastChunkTime = DateTime.UtcNow;
            _totalActualUrbBytes += Math.Max(actualUrbLength, (uint)chunk.Length);

            _activeUploadStream.Write(chunk, 0, chunk.Length);
            if (_remainingInCurrentDataBlock > 0)
            {
                _remainingInCurrentDataBlock = Math.Max(0, _remainingInCurrentDataBlock - chunk.Length);
            }

            if (_firstHeaderSignature == null && _activeUploadStream.Length >= 4)
            {
                byte[] streamArr = _activeUploadStream.ToArray();
                _firstHeaderSignature = streamArr[..Math.Min(streamArr.Length, 256)];
                StartEagerMidTransferSnapshot(_activeTargetPath, _firstHeaderSignature, _declaredDataSize > 0 ? _declaredDataSize : streamArr.Length);
            }

            // If we received the full declared APK size on a non-truncated stream, or saw the ZIP EOCD trailer at the end of the transfer
            if ((!_hadTruncatedUrb && _declaredDataSize > 0 && _activeUploadStream.Length >= _declaredDataSize) ||
                (_declaredDataSize > 0 && _totalActualUrbBytes >= _declaredDataSize && HasValidZipEocd(chunk)))
            {
                _sawExplicitDone = true;
                _doneAlreadyStripped = true;
                EnqueueCurrentTransferForBackgroundSave(epHex, "StreamedInstallCompleted");
                return true;
            }

            return false;
        }

        string fullChunkAscii = Encoding.ASCII.GetString(chunk);
        string cleanLineTrimmed = fullChunkAscii.Trim('\r', '\n', '\0', ' ');

        // Only filter out shell/host commands when NOT inside an active binary transfer (or if the packet literally starts at offset 0 with "shell:" / "host:")
        if (!_isInsideTransfer)
        {
            if (cleanLineTrimmed.StartsWith("shell:", StringComparison.OrdinalIgnoreCase) ||
                cleanLineTrimmed.StartsWith("host:", StringComparison.OrdinalIgnoreCase) ||
                cleanLineTrimmed.StartsWith("chmod ", StringComparison.OrdinalIgnoreCase) ||
                cleanLineTrimmed.StartsWith("rm ", StringComparison.OrdinalIgnoreCase) ||
                cleanLineTrimmed.StartsWith("ln ", StringComparison.OrdinalIgnoreCase) ||
                cleanLineTrimmed.StartsWith("cp ", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }
        else if (StartsWithAscii(chunk, "shell:") || StartsWithAscii(chunk, "host:"))
        {
            EnqueueCurrentTransferForBackgroundSave(epHex, "ShellCommandPacketFlush");
            return false;
        }

        string combined = _pendingHeaderBuffer + fullChunkAscii;

        bool hasSendToken = StartsWithAscii(chunk, "SEND") || FindAsciiTokenOffset(chunk, "SEND", 0, chunk.Length) >= 0;
        bool hasStatToken = StartsWithAscii(chunk, "STAT") || FindAsciiTokenOffset(chunk, "STAT", 0, Math.Min(chunk.Length, 64)) >= 0;

        Match sendMatch = SendPathAndModeRegex.Match(combined);
        bool allowSendMatch = sendMatch.Success &&
                              (!_isInsideTransfer ||
                               StartsWithAscii(chunk, "SEND") ||
                               !string.IsNullOrEmpty(_pendingHeaderBuffer) ||
                               TryFindStructuredSendHeader(chunk, out _, out _, out _));

        // 1. Check for SEND "/path,mode"
        if (allowSendMatch)
        {
            string matchedPath = sendMatch.Groups[1].Value.Trim();
            string matchedMode = sendMatch.Groups[2].Value.Trim();

            int sendTokenIdx = FindAsciiTokenOffset(chunk, "SEND", 0, chunk.Length);
            int pathIdxInChunk = fullChunkAscii.IndexOf(matchedPath, StringComparison.OrdinalIgnoreCase);
            int newFileStartOffset = sendTokenIdx >= 0 ? sendTokenIdx : (pathIdxInChunk >= 8 ? pathIdxInChunk - 8 : 0);

            if (_isInsideTransfer && !string.IsNullOrEmpty(_activeTargetPath))
            {
                if (newFileStartOffset > 0)
                {
                    int prevEnd = newFileStartOffset;
                    int prevDone = FindDoneTrailerOffset(chunk[..newFileStartOffset], 0);
                    if (prevDone >= 0)
                    {
                        prevEnd = prevDone;
                        _sawExplicitDone = true;
                        _doneAlreadyStripped = true;
                    }
                    if (prevEnd > 0)
                    {
                        _activeUploadStream.Write(chunk, 0, prevEnd);
                        if (_firstHeaderSignature == null && _activeUploadStream.Length > 0)
                        {
                            byte[] prevArr = _activeUploadStream.ToArray();
                            _firstHeaderSignature = prevArr[..Math.Min(prevArr.Length, 256)];
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

            StartNewTransferStateLocked(matchedPath, matchedMode, actualUrbLength, chunk.Length);

            int searchDataFrom = pathIdxInChunk >= 0 ? pathIdxInChunk + matchedPath.Length : 0;
            int dataIdx = FindDataHeaderOffset(chunk, searchDataFrom);
            if (dataIdx >= 0 && dataIdx + 8 <= chunk.Length)
            {
                uint dLen = BitConverter.ToUInt32(chunk, dataIdx + 4);
                if (dLen > 0 && dLen <= 64 * 1024 * 1024)
                {
                    _declaredDataSize += dLen;
                    _activeDataBlockCount++;
                    _remainingInCurrentDataBlock = (int)dLen;
                    if (dLen > chunk.Length - (dataIdx + 8))
                    {
                        _hadTruncatedUrb = true;
                    }
                }

                int payloadStart = dataIdx + 8;
                bool isTruncatedPacket = actualUrbLength > chunk.Length;

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
                    _remainingInCurrentDataBlock = Math.Max(0, _remainingInCurrentDataBlock - count);

                    if (_firstHeaderSignature == null && count >= 1)
                    {
                        _firstHeaderSignature = chunk[payloadStart..(payloadStart + Math.Min(count, 256))];
                        StartEagerMidTransferSnapshot(_activeTargetPath, _firstHeaderSignature, _declaredDataSize > 0 ? _declaredDataSize : count);
                    }
                }

                _totalActualUrbBytes += Math.Max(actualUrbLength, (uint)chunk.Length);

                if (doneIdx >= payloadStart)
                {
                    _sawExplicitDone = true;
                    _doneAlreadyStripped = true;
                    EnqueueCurrentTransferForBackgroundSave(epHex, "SinglePacketSendDataDone");

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
        if ((!_isInsideTransfer || StartsWithAscii(chunk, "STAT") || StartsWithAscii(chunk, "SEND")) &&
            (hasStatToken || hasSendToken))
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

            if (!_isInsideTransfer)
            {
                _pendingHeaderBuffer = fullChunkAscii;
                _lastChunkTime = DateTime.UtcNow;
                return false;
            }
        }

        // 3. Active transfer continuation chunk
        if (_isInsideTransfer || (!string.IsNullOrEmpty(_pendingStatPath) && StartsWithAscii(chunk, "DATA")))
        {
            if (!_isInsideTransfer)
            {
                StartNewTransferStateLocked(_pendingStatPath, "33188", actualUrbLength, chunk.Length);
            }

            if (actualUrbLength > chunk.Length)
            {
                _hadTruncatedUrb = true;
            }

            _lastChunkTime = DateTime.UtcNow;
            _totalActualUrbBytes += Math.Max(actualUrbLength, (uint)chunk.Length);

            if (chunk.Length >= 8 && StartsWithAscii(chunk, "DONE") &&
                (chunk.Length == 8 || FindDoneTrailerOffset(chunk, 0) == 0))
            {
                _sawExplicitDone = true;
                _doneAlreadyStripped = true;
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
                    _activeDataBlockCount++;
                    _remainingInCurrentDataBlock = (int)dLen;
                    currentBlockDeclaredLen = dLen;
                    if (dLen > chunk.Length - 8 || _activeDataBlockCount > 1)
                    {
                        _hadTruncatedUrb = true;
                    }
                }
                payloadStart = 8;
            }
            else if (_remainingInCurrentDataBlock > 0 &&
                     _remainingInCurrentDataBlock + 8 <= chunk.Length &&
                     chunk[_remainingInCurrentDataBlock] == (byte)'D' &&
                     chunk[_remainingInCurrentDataBlock + 1] == (byte)'A' &&
                     chunk[_remainingInCurrentDataBlock + 2] == (byte)'T' &&
                     chunk[_remainingInCurrentDataBlock + 3] == (byte)'A')
            {
                int preLen = _remainingInCurrentDataBlock;
                _activeUploadStream.Write(chunk, 0, preLen);

                uint dLen = BitConverter.ToUInt32(chunk, preLen + 4);
                if (dLen > 0 && dLen <= 64 * 1024 * 1024)
                {
                    _declaredDataSize += dLen;
                    _activeDataBlockCount++;
                    _remainingInCurrentDataBlock = (int)dLen;
                    currentBlockDeclaredLen = dLen;
                    _hadTruncatedUrb = true;
                }
                payloadStart = preLen + 8;
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
            else if (!isTruncatedPacket || chunk.Length < 1024)
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
                if (_remainingInCurrentDataBlock > 0)
                {
                    _remainingInCurrentDataBlock = Math.Max(0, _remainingInCurrentDataBlock - count);
                }

                if (_firstHeaderSignature == null && _activeUploadStream.Length >= 1)
                {
                    byte[] streamArr = _activeUploadStream.ToArray();
                    _firstHeaderSignature = streamArr[..Math.Min(streamArr.Length, 256)];
                    StartEagerMidTransferSnapshot(_activeTargetPath, _firstHeaderSignature, _declaredDataSize > 0 ? _declaredDataSize : streamArr.Length);
                }
            }

            if (doneIdx >= payloadStart)
            {
                _sawExplicitDone = true;
                _doneAlreadyStripped = true;
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

    private void StartNewTransferStateLocked(string targetPath, string mode, uint actualUrbLength, int chunkLength)
    {
        _activeTargetPath = targetPath;
        _activeMode = string.IsNullOrWhiteSpace(mode) ? "33188" : mode;
        _isInsideTransfer = true;
        _isStreamedInstallTransfer = false;
        _activeUploadStream.SetLength(0);
        _declaredDataSize = 0;
        _totalActualUrbBytes = 0;
        _activeDataBlockCount = 0;
        _remainingInCurrentDataBlock = 0;
        _firstHeaderSignature = null;
        _eagerSnapshotTask = null;
        _hadTruncatedUrb = actualUrbLength > chunkLength;
        _sawExplicitDone = false;
        _doneAlreadyStripped = false;
        _pendingHeaderBuffer = string.Empty;
        _lastChunkTime = DateTime.UtcNow;
        _kernelDroppedAtTransferStart = Interlocked.Read(ref _latestKnownKernelDroppedPackets);

        _activeTransferSequenceId = Interlocked.Increment(ref _transferSequenceCounter);

        string fileName = Path.GetFileName(targetPath);
        int pathCount = _uploadCountByTargetPath.AddOrUpdate(targetPath, 1, (_, prev) => prev + 1);
        int nameCount = !string.IsNullOrWhiteSpace(fileName)
            ? _uploadCountByFileName.AddOrUpdate(fileName, 1, (_, prev) => prev + 1)
            : pathCount;

        _activeUploadSequenceNumber = Math.Max(pathCount, nameCount);
    }

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
            long seqId;
            int uploadNum;
            string sessionDir;
            string sessionFolder;

            lock (_transferLock)
            {
                seqId = Interlocked.Increment(ref _transferSequenceCounter);
                string fn = Path.GetFileName(destPath);
                int pCount = _uploadCountByTargetPath.AddOrUpdate(destPath, 1, (_, prev) => prev + 1);
                int nCount = !string.IsNullOrWhiteSpace(fn)
                    ? _uploadCountByFileName.AddOrUpdate(fn, 1, (_, prev) => prev + 1)
                    : pCount;
                uploadNum = Math.Max(pCount, nCount);
                sessionDir = CurrentSessionDirectory;
                sessionFolder = CurrentSessionFolderName;
            }

            _ = Task.Run(() =>
            {
                try
                {
                    byte[] decoded = Convert.FromBase64String(b64Str);
                    if (decoded.Length > 0)
                    {
                        var rec = SaveSingleCleanFileToDisk(
                            decoded,
                            destPath,
                            "0755",
                            "Base64 Inline Stream",
                            sessionDir,
                            sessionFolder,
                            uploadNum,
                            seqId,
                            isCompleteCapture: true,
                            declaredSize: decoded.Length,
                            kernelDroppedDelta: 0);
                        if (rec != null)
                        {
                            _latestInstanceByPath[destPath] = (rec.SavedFileName, rec.UploadSequenceNumber, rec.FileSizeBytes, rec.LocalSavedPath);
                            OnFileArchivedAsync?.Invoke(rec, "0x01");
                        }
                    }
                }
                catch { }
            });
        }

        // 2. Auto-flush active transfer if a genuine shell command starts (chmod, unzip, pm install, etc.)
        lock (_transferLock)
        {
            if (_isInsideTransfer && !string.IsNullOrEmpty(_activeTargetPath))
            {
                EnqueueCurrentTransferForBackgroundSave("0x01", "ShellTransitionFlush");
            }
        }

        // 3. Delayed Passive Host-Disk Verification
        if (!trimmed.StartsWith("rm ", StringComparison.OrdinalIgnoreCase) &&
            !trimmed.Contains("rm -r", StringComparison.OrdinalIgnoreCase))
        {
            var matches = ShellFilePathRegex.Matches(trimmed);
            foreach (Match pm in matches)
            {
                string refPath = pm.Groups[1].Value.Trim();
                if (string.IsNullOrEmpty(refPath) || refPath.EndsWith("/") || IsIgnoredNoiseFile(refPath))
                    continue;

                if (!_latestInstanceByPath.ContainsKey(refPath) && !_uploadCountByTargetPath.ContainsKey(refPath))
                {
                    _ = Task.Run(async () =>
                    {
                        await Task.Delay(400).ConfigureAwait(false);
                        if (_latestInstanceByPath.ContainsKey(refPath) || _uploadCountByTargetPath.ContainsKey(refPath))
                            return;

                        string fn = Path.GetFileName(refPath);
                        byte[]? exactToolFile = TryRecoverFromHostDisk(fn, headerSig: null);
                        if (exactToolFile != null && exactToolFile.Length > 0)
                        {
                            long seqId;
                            int uploadNum;
                            string sessionDir;
                            string sessionFolder;

                            lock (_transferLock)
                            {
                                if (_latestInstanceByPath.ContainsKey(refPath) || _uploadCountByTargetPath.ContainsKey(refPath))
                                    return;

                                seqId = Interlocked.Increment(ref _transferSequenceCounter);
                                int pCount = _uploadCountByTargetPath.AddOrUpdate(refPath, 1, (_, prev) => prev + 1);
                                int nCount = !string.IsNullOrWhiteSpace(fn)
                                    ? _uploadCountByFileName.AddOrUpdate(fn, 1, (_, prev) => prev + 1)
                                    : pCount;
                                uploadNum = Math.Max(pCount, nCount);
                                sessionDir = CurrentSessionDirectory;
                                sessionFolder = CurrentSessionFolderName;
                            }

                            var rec = SaveSingleCleanFileToDisk(
                                exactToolFile,
                                refPath,
                                "0777",
                                "Host Disk Verified (Shell Ref)",
                                sessionDir,
                                sessionFolder,
                                uploadNum,
                                seqId,
                                isCompleteCapture: true,
                                declaredSize: exactToolFile.Length,
                                kernelDroppedDelta: 0);
                            if (rec != null)
                            {
                                _latestInstanceByPath[refPath] = (rec.SavedFileName, rec.UploadSequenceNumber, rec.FileSizeBytes, rec.LocalSavedPath);
                                OnFileArchivedAsync?.Invoke(rec, "0x01");
                            }
                        }
                    });
                }
            }
        }

        return false;
    }

    public bool FlushIfActive(out CapturedPushedFileRecord? completedRecord, bool isClseSignal = false)
    {
        completedRecord = null;
        lock (_transferLock)
        {
            if (!_isInsideTransfer || string.IsNullOrEmpty(_activeTargetPath))
            {
                return false;
            }

            if (isClseSignal && !_isStreamedInstallTransfer && (DateTime.UtcNow - _lastChunkTime).TotalMilliseconds < 400)
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
        byte[]? sig = _firstHeaderSignature != null ? (byte[])_firstHeaderSignature.Clone() : null;
        Task<byte[]?>? eagerTask = _eagerSnapshotTask;
        string mode = _activeMode;
        long declared = _declaredDataSize;
        long actualUrb = _totalActualUrbBytes;
        int blockCount = _activeDataBlockCount;
        bool truncated = _hadTruncatedUrb;
        bool sawDone = _sawExplicitDone;
        bool doneStripped = _doneAlreadyStripped;
        long droppedNow = Interlocked.Read(ref _latestKnownKernelDroppedPackets);
        long droppedDelta = Math.Max(0, droppedNow - _kernelDroppedAtTransferStart);
        long seqId = _activeTransferSequenceId > 0 ? _activeTransferSequenceId : Interlocked.Increment(ref _transferSequenceCounter);
        int uploadNum = _activeUploadSequenceNumber > 0 ? _activeUploadSequenceNumber : 1;
        string sessionDir = CurrentSessionDirectory;
        string sessionFolder = CurrentSessionFolderName;

        _isInsideTransfer = false;
        _isStreamedInstallTransfer = false;
        _activeTargetPath = string.Empty;
        _pendingStatPath = string.Empty;
        _activeUploadStream.SetLength(0);
        _declaredDataSize = 0;
        _totalActualUrbBytes = 0;
        _activeDataBlockCount = 0;
        _remainingInCurrentDataBlock = 0;
        _firstHeaderSignature = null;
        _eagerSnapshotTask = null;
        _hadTruncatedUrb = false;
        _sawExplicitDone = false;
        _doneAlreadyStripped = false;
        _pendingHeaderBuffer = string.Empty;

        if (string.IsNullOrWhiteSpace(targetPath) || IsIgnoredNoiseFile(targetPath)) return;

        byte[] cleanWire = !doneStripped ? StripDoneTrailer(wireBytes) : wireBytes;
        if (!truncated && droppedDelta == 0 && blockCount <= 1 && declared > 0 && cleanWire.Length > declared)
        {
            cleanWire = cleanWire[..(int)declared];
        }

        if (declared > cleanWire.Length || blockCount > 1)
        {
            truncated = true;
        }

        _jobChannel.Writer.TryWrite(new PendingFileArchiveJob
        {
            TransferSequenceId = seqId,
            UploadSequenceNumber = uploadNum,
            SessionDirectory = sessionDir,
            SessionFolderName = sessionFolder,
            TargetPath = targetPath,
            Mode = mode,
            WireBytes = cleanWire,
            HeaderSignature = sig,
            EagerSnapshotTask = eagerTask,
            TotalDeclaredBytes = declared,
            TotalActualUrbBytes = actualUrb,
            DataBlockCount = blockCount,
            HadTruncatedUrb = truncated,
            SawExplicitDone = sawDone,
            KernelDroppedDelta = droppedDelta,
            EndpointHex = epHex,
            TriggerReason = reason
        });
    }
}
