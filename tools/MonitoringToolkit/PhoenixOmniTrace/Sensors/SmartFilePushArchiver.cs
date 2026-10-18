using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using PhoenixGSM.OmniTrace.Decoders;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.Sensors;

/// <summary>
/// Record representing a complete captured file pushed to the device via ADB or WinUSB.
/// Saves strictly ONE file per pushed artifact with its exact original name and full size.
/// </summary>
public sealed class CapturedPushedFileRecord
{
    public string TargetDevicePath { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
    public string FilePermissionMode { get; set; } = "33188";
    public string LocalSavedPath { get; set; } = string.Empty;
    public byte[] FileBytes { get; set; } = [];
    public long FileSizeBytes { get; set; }
    public long DeclaredDataSize { get; set; }
    public string Sha256 { get; set; } = string.Empty;
    public string Md5 { get; set; } = string.Empty;
    public string FileClassification { get; set; } = "Binary File";
    public string MagicDescription { get; set; } = string.Empty;
    public bool IsExecutableOrExploit { get; set; }
    public string CaptureVector { get; set; } = "USB Wire Stream";
    public string ProcessName { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string Summary { get; set; } = string.Empty;
    public string AdditionalDetails { get; set; } = string.Empty;
}

/// <summary>
/// Non-blocking background job for 100% passive, parallel full-size file recovery and disk saving.
/// </summary>
internal sealed class PendingFileArchiveJob
{
    public string TargetPath { get; init; } = string.Empty;
    public string Mode { get; init; } = "33188";
    public byte[] WireBytes { get; init; } = [];
    public byte[]? HeaderSignature { get; init; }
    public Task<byte[]?>? EagerSnapshotTask { get; init; }
    public long TotalDeclaredBytes { get; init; }
    public long TotalActualUrbBytes { get; init; }
    public bool HadTruncatedUrb { get; init; }
    public string EndpointHex { get; init; } = "0x01";
    public string TriggerReason { get; init; } = "DONE";
}

/// <summary>
/// LAYER 12C — 100% Passive High-Speed Parallel Smart File Push Archiver.
/// - ZERO USB interruption: Never spawns adb.exe, never runs "adb pull" or "adb shell ln -f",
///   and never competes with direct WinUSB tools (such as KEY-Tool.exe) for the USB handle.
/// - Captures files of ALL sizes from 1 byte (e.g. 72-byte ASKSW.xml, trustedTime) up to 64 MB (15MB R2.zip, 480KB AT).
/// - Handles multi-file coalesced USB buffers where a small file (like ASKSW.xml) starts at offset > 160
///   immediately after the previous file's DONE token in the same USB Bulk transfer.
/// - Strictly saves ONLY ONE file per pushed item with its exact original name and full size.
/// </summary>
public sealed class SmartFilePushArchiver : IDisposable
{
    public static readonly Regex SendPathAndModeRegex = new(
        @"((?:/data/local/tmp/|/data/|/sdcard/|/storage/|/system/|/vendor/|/tmp/)[A-Za-z0-9_\-\./]+),(\d+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public static readonly Regex StatPathRegex = new(
        @"(?:STAT|SEND).{0,8}?((?:/data/local/tmp/|/data/|/sdcard/|/storage/|/system/|/vendor/|/tmp/)[A-Za-z0-9_\-\./]+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Singleline);

    public static readonly Regex ShellFilePathRegex = new(
        @"((?:/data/local/tmp/|/data/system/)[A-Za-z0-9_\-\./]+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public static readonly Regex Base64EchoRegex = new(
        @"echo\s+['""]?([A-Za-z0-9+/=]{8,})['""]?\s*\|\s*(?:toybox\s+|busybox\s+)?base64\s+(?:-d|--decode)\s*>\s*([^\s;&|]+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private readonly object _transferLock = new();
    private readonly MemoryStream _activeUploadStream = new();
    private string _activeTargetPath = string.Empty;
    private string _pendingStatPath = string.Empty;
    private string _activeMode = "33188";
    private long _declaredDataSize = 0;
    private long _totalActualUrbBytes = 0;
    private byte[]? _firstHeaderSignature = null;
    private Task<byte[]?>? _eagerSnapshotTask = null;
    private bool _hadTruncatedUrb = false;
    private bool _isInsideTransfer = false;
    private string _pendingHeaderBuffer = string.Empty;
    private DateTime _lastChunkTime = DateTime.MinValue;

    private readonly ConcurrentDictionary<int, string> _candidatePids = new();
    private readonly ConcurrentDictionary<string, long> _savedFileSizesByPath = new(StringComparer.OrdinalIgnoreCase);
    private readonly Channel<PendingFileArchiveJob> _jobChannel;
    private readonly CancellationTokenSource _cts = new();

    /// <summary>
    /// Fired asynchronously from the background worker whenever a pushed file is saved or upgraded to full size.
    /// </summary>
    public event Action<CapturedPushedFileRecord, string>? OnFileArchivedAsync;

    public bool IsInsideTransfer
    {
        get { lock (_transferLock) return _isInsideTransfer; }
    }

    public string ActiveTargetPath
    {
        get { lock (_transferLock) return _activeTargetPath; }
    }

    public DateTime LastChunkTime
    {
        get { lock (_transferLock) return _lastChunkTime; }
    }

    public SmartFilePushArchiver()
    {
        _jobChannel = Channel.CreateUnbounded<PendingFileArchiveJob>(new UnboundedChannelOptions
        {
            SingleReader = false,
            SingleWriter = false
        });

        for (int i = 0; i < 2; i++)
        {
            _ = Task.Run(() => ProcessArchiveJobsLoopAsync(_cts.Token));
        }
    }

    public void RegisterCandidateProcess(int pid, string name)
    {
        if (pid > 4 && pid != Environment.ProcessId)
        {
            _candidatePids[pid] = name ?? string.Empty;
        }
    }

    #region P/Invoke Definitions for 64-Bit & 32-Bit Process RAM Carving
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const uint PROCESS_VM_READ = 0x0010;
    private const uint MEM_COMMIT = 0x1000;
    private const uint PAGE_NOACCESS = 0x01;
    private const uint PAGE_GUARD = 0x100;
    private const uint PAGE_READONLY = 0x02;
    private const uint PAGE_READWRITE = 0x04;
    private const uint PAGE_WRITECOPY = 0x08;
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    #endregion

    private static bool IsIgnoredNoiseFile(string pathOrName)
    {
        if (string.IsNullOrWhiteSpace(pathOrName)) return true;
        string fname = Path.GetFileName(pathOrName);
        if (string.IsNullOrWhiteSpace(fname)) return true;

        return fname.Equals("adb.log", StringComparison.OrdinalIgnoreCase) ||
               fname.StartsWith(".phx_keep_", StringComparison.OrdinalIgnoreCase) ||
               fname.StartsWith("phx_pull_", StringComparison.OrdinalIgnoreCase) ||
               fname.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase) ||
               fname.EndsWith(".etl", StringComparison.OrdinalIgnoreCase);
    }

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
    /// Starts an immediate, non-blocking background snapshot from Host Disk & Target Tool RAM
    /// at the exact moment the first DATA chunk starts flowing over USB.
    /// </summary>
    private void StartEagerMidTransferSnapshot(string targetPath, byte[]? signature, long estimatedSize)
    {
        if (string.IsNullOrWhiteSpace(targetPath) || _eagerSnapshotTask != null) return;
        string fileName = Path.GetFileName(targetPath);
        if (string.IsNullOrWhiteSpace(fileName)) return;

        byte[]? sigCopy = signature != null ? (byte[])signature.Clone() : null;
        long est = estimatedSize;

        _eagerSnapshotTask = Task.Run(() =>
        {
            byte[]? disk = TryRecoverFromHostDisk(fileName, sigCopy);
            if (disk != null && disk.Length > 0 && (est <= 0 || disk.Length >= est))
            {
                return disk;
            }

            byte[]? ram = TryCarveFileFromTargetProcessRam(sigCopy, est);
            if (ram != null && (disk == null || ram.Length > disk.Length))
            {
                return ram;
            }

            return disk;
        });
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

    /// <summary>
    /// Dedicated background worker loop: saves small non-truncated files (e.g. 72-byte ASKSW.xml)
    /// directly from WireBytes or Host Disk, and recovers truncated large files from Host Disk + Process RAM.
    /// </summary>
    private async Task ProcessArchiveJobsLoopAsync(CancellationToken token)
    {
        await foreach (var job in _jobChannel.Reader.ReadAllAsync(token))
        {
            try
            {
                string fileName = Path.GetFileName(job.TargetPath);
                if (string.IsNullOrWhiteSpace(fileName) || IsIgnoredNoiseFile(fileName)) continue;

                long existingSavedSize = _savedFileSizesByPath.TryGetValue(job.TargetPath, out long s) ? s : 0;

                byte[] bestBytes = job.WireBytes ?? [];
                string bestVector = "USB Wire Stream";

                // If the wire capture was NOT truncated and matches the exact declared DATA size (e.g. 72-byte ASKSW.xml),
                // wireBytes is already 100% complete! Only check Host Disk for an exact match, never overwrite with oversized RAM!
                bool wireIsCompleteExact = !job.HadTruncatedUrb &&
                                           bestBytes.Length > 0 &&
                                           (job.TotalDeclaredBytes <= 0 || bestBytes.Length == job.TotalDeclaredBytes);

                if (wireIsCompleteExact)
                {
                    byte[]? diskExact = TryRecoverFromHostDisk(fileName, job.HeaderSignature);
                    if (diskExact != null && diskExact.Length >= bestBytes.Length)
                    {
                        bestBytes = diskExact;
                        bestVector = "Host Disk Snapshot";
                    }
                }
                else
                {
                    // 1. Check Eager Mid-Transfer Snapshot first
                    if (job.EagerSnapshotTask != null)
                    {
                        try
                        {
                            byte[]? eagerBytes = await job.EagerSnapshotTask.ConfigureAwait(false);
                            if (eagerBytes != null && eagerBytes.Length > bestBytes.Length)
                            {
                                bestBytes = eagerBytes;
                                bestVector = "Eager Mid-Transfer RAM/Disk Snapshot";
                            }
                        }
                        catch { }
                    }

                    long expectedSize = job.TotalDeclaredBytes > 0
                        ? job.TotalDeclaredBytes
                        : job.TotalActualUrbBytes;

                    bool needsFullRecovery = job.HadTruncatedUrb ||
                                             bestBytes.Length == 0 ||
                                             (job.TotalDeclaredBytes > bestBytes.Length);

                    // 2. Run Host Disk + 64-bit/32-bit Target Process RAM carving in parallel
                    if (needsFullRecovery && (expectedSize == 0 || bestBytes.Length < expectedSize))
                    {
                        var diskTask = Task.Run(() => TryRecoverFromHostDisk(fileName, job.HeaderSignature), token);
                        var ramTask = Task.Run(() => TryCarveFileFromTargetProcessRam(job.HeaderSignature, expectedSize), token);

                        await Task.WhenAll(diskTask, ramTask).ConfigureAwait(false);

                        byte[]? diskBytes = diskTask.Result;
                        byte[]? ramBytes = ramTask.Result;

                        if (diskBytes != null && diskBytes.Length > bestBytes.Length)
                        {
                            bestBytes = diskBytes;
                            bestVector = "Host Disk Snapshot";
                        }
                        if (ramBytes != null && ramBytes.Length > bestBytes.Length)
                        {
                            bestBytes = ramBytes;
                            bestVector = "Process RAM Carve (Passive)";
                        }
                    }
                }

                // Allow saving any non-empty file >= 1 byte (including 72-byte ASKSW.xml and tiny trustedTime files!)
                if (bestBytes.Length == 0 || bestBytes.Length <= existingSavedSize)
                {
                    continue;
                }

                var savedRecord = SaveSingleCleanFileToDisk(bestBytes, job.TargetPath, job.Mode, bestVector);
                if (savedRecord != null)
                {
                    _savedFileSizesByPath[job.TargetPath] = bestBytes.Length;
                    OnFileArchivedAsync?.Invoke(savedRecord, job.EndpointHex);
                }
            }
            catch { }
        }
    }

    /// <summary>
    /// Searches the active GSM tool's installation directory (all subdirectories) as well as %TEMP%
    /// for either an exact filename match or a recent temporary file whose header matches HeaderSignature.
    /// Supports files as small as 1 byte (e.g. 72-byte ASKSW.xml).
    /// </summary>
    private static byte[]? TryRecoverFromHostDisk(string fileName, byte[]? headerSig)
    {
        if (string.IsNullOrWhiteSpace(fileName) || IsIgnoredNoiseFile(fileName)) return null;

        var rootDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            Path.GetTempPath(),
            Environment.CurrentDirectory,
            AppDomain.CurrentDomain.BaseDirectory,
            @"C:\Program Files (x86)\KEY-Tool",
            @"C:\Program Files\KEY-Tool",
            @"C:\UnlockTool"
        };

        try
        {
            foreach (var p in Process.GetProcesses())
            {
                try
                {
                    if (p.Id <= 4 || p.Id == Environment.ProcessId) continue;
                    string pn = p.ProcessName.ToLowerInvariant();
                    if (pn.Contains("key") || pn.Contains("tool") || pn.Contains("adb") ||
                        pn.Contains("samfw") || pn.Contains("chimera") || pn.Contains("unlock") ||
                        pn.Contains("odin") || pn.Contains("gsm"))
                    {
                        string? exe = p.MainModule?.FileName;
                        if (!string.IsNullOrEmpty(exe))
                        {
                            string? d = Path.GetDirectoryName(exe);
                            if (!string.IsNullOrEmpty(d)) rootDirs.Add(d);
                        }
                    }
                }
                catch { }
                finally { p.Dispose(); }
            }
        }
        catch { }

        // Pass 1: Recursive filename search across tool folders (finds retail\ASKSW.xml at any depth!)
        foreach (string dir in rootDirs)
        {
            try
            {
                if (!Directory.Exists(dir)) continue;

                string directCandidate = Path.Combine(dir, fileName);
                byte[]? directBytes = TryReadSharedFile(directCandidate, headerSig);
                if (directBytes != null) return directBytes;

                var enumOpts = new EnumerationOptions
                {
                    IgnoreInaccessible = true,
                    RecurseSubdirectories = true,
                    MaxRecursionDepth = 4,
                    MatchCasing = MatchCasing.CaseInsensitive
                };

                foreach (string matchPath in Directory.EnumerateFiles(dir, fileName, enumOpts))
                {
                    byte[]? subBytes = TryReadSharedFile(matchPath, headerSig);
                    if (subBytes != null) return subBytes;
                }
            }
            catch { }
        }

        // Pass 2: If the tool staged a randomly-named file in %TEMP% within the last 2 minutes, match by header signature (supports >= 4 bytes)
        if (headerSig != null && headerSig.Length >= 4)
        {
            try
            {
                string tempDir = Path.GetTempPath();
                DateTime cutoff = DateTime.UtcNow.AddMinutes(-2);
                int sigCheckLen = Math.Min(headerSig.Length, 32);
                byte[] headBuf = new byte[sigCheckLen];

                foreach (string file in Directory.EnumerateFiles(tempDir))
                {
                    try
                    {
                        if (IsIgnoredNoiseFile(file)) continue;
                        var fi = new FileInfo(file);
                        if (fi.LastWriteTimeUtc < cutoff || fi.Length < sigCheckLen || fi.Length > 128 * 1024 * 1024)
                            continue;

                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                        if (fs.Read(headBuf, 0, sigCheckLen) == sigCheckLen &&
                            headBuf.AsSpan(0, sigCheckLen).SequenceEqual(headerSig.AsSpan(0, sigCheckLen)))
                        {
                            fs.Position = 0;
                            byte[] full = new byte[fi.Length];
                            if (fs.Read(full, 0, full.Length) == full.Length)
                                return full;
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        return null;
    }

    private static byte[]? TryReadSharedFile(string path, byte[]? expectedHeader)
    {
        try
        {
            if (!File.Exists(path)) return null;
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (fs.Length <= 0 || fs.Length > 128 * 1024 * 1024) return null;

            byte[] buf = new byte[fs.Length];
            int total = 0;
            while (total < buf.Length)
            {
                int r = fs.Read(buf, total, buf.Length - total);
                if (r <= 0) break;
                total += r;
            }
            if (total != buf.Length) return null;

            if (expectedHeader != null && expectedHeader.Length >= 4 && buf.Length >= 4)
            {
                int checkLen = Math.Min(8, Math.Min(expectedHeader.Length, buf.Length));
                if (!buf.AsSpan(0, checkLen).SequenceEqual(expectedHeader.AsSpan(0, checkLen)))
                {
                    return null;
                }
            }

            return buf;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Fast, targeted 64-bit & 32-bit RAM carver.
    /// Supports small signatures (>= 4 bytes) and full 64-bit address space.
    /// </summary>
    public byte[]? TryCarveFileFromTargetProcessRam(byte[]? signature, long estimatedSize)
    {
        if (signature == null || signature.Length < 4) return null;

        int sigLen = Math.Min(signature.Length, 64);
        byte[] sigPattern = signature[..sigLen];

        var targetPids = new List<int>();

        try
        {
            foreach (var p in Process.GetProcesses())
            {
                try
                {
                    if (p.Id <= 4 || p.Id == Environment.ProcessId) continue;
                    string pn = p.ProcessName.ToLowerInvariant();
                    if (pn.Contains("key") || pn.Contains("tool") || pn.Contains("samfw") ||
                        pn.Contains("unlock") || pn.Contains("chimera") || pn.Contains("odin") ||
                        pn.Contains("fastboot") || pn.Contains("gsm"))
                    {
                        if (!targetPids.Contains(p.Id)) targetPids.Insert(0, p.Id);
                    }
                    else if (pn.Contains("adb"))
                    {
                        if (!targetPids.Contains(p.Id)) targetPids.Add(p.Id);
                    }
                }
                catch { }
                finally { p.Dispose(); }
            }
        }
        catch { }

        foreach (int pid in _candidatePids.Keys)
        {
            if (!targetPids.Contains(pid)) targetPids.Add(pid);
        }

        byte[]? bestFound = null;

        foreach (int pid in targetPids)
        {
            IntPtr hProc = IntPtr.Zero;
            try
            {
                hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
                if (hProc == IntPtr.Zero)
                {
                    hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, false, pid);
                }
                if (hProc == IntPtr.Zero) continue;

                long currentAddr = 0x10000;
                long maxAddr = Environment.Is64BitOperatingSystem ? 0x00007FFFFFFF0000L : 0x7FFF0000L;
                uint mbiSize = (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();
                byte[] chunkBuf = new byte[256 * 1024];

                while (currentAddr < maxAddr)
                {
                    if (VirtualQueryEx(hProc, (IntPtr)currentAddr, out var mbi, mbiSize) == 0)
                        break;

                    long baseAddr = mbi.BaseAddress.ToInt64();
                    long regionSize = mbi.RegionSize.ToInt64();
                    if (regionSize <= 0) break;

                    bool isReadable = mbi.State == MEM_COMMIT &&
                                      (mbi.Protect & PAGE_NOACCESS) == 0 &&
                                      (mbi.Protect & PAGE_GUARD) == 0 &&
                                      (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY ||
                                       mbi.Protect == PAGE_WRITECOPY || mbi.Protect == PAGE_EXECUTE_READ ||
                                       mbi.Protect == PAGE_EXECUTE_READWRITE);

                    if (isReadable && regionSize >= sigLen && regionSize <= 128 * 1024 * 1024)
                    {
                        long offset = 0;
                        while (offset < regionSize)
                        {
                            int toRead = (int)Math.Min(chunkBuf.Length, regionSize - offset);
                            if (ReadProcessMemory(hProc, (IntPtr)(baseAddr + offset), chunkBuf, toRead, out int bytesRead) && bytesRead >= sigLen)
                            {
                                int searchOffset = 0;
                                while (searchOffset <= bytesRead - sigLen)
                                {
                                    int relIdx = IndexOfSequence(chunkBuf.AsSpan(searchOffset, bytesRead - searchOffset), sigPattern);
                                    if (relIdx < 0) break;

                                    int foundIdx = searchOffset + relIdx;
                                    long fileStartAddr = baseAddr + offset + foundIdx;
                                    long maxAvailableInRegion = regionSize - (offset + foundIdx);

                                    bool isWirePacketCopy = false;
                                    if (foundIdx >= 8 &&
                                        chunkBuf[foundIdx - 8] == (byte)'D' &&
                                        chunkBuf[foundIdx - 7] == (byte)'A' &&
                                        chunkBuf[foundIdx - 6] == (byte)'T' &&
                                        chunkBuf[foundIdx - 5] == (byte)'A')
                                    {
                                        isWirePacketCopy = true;
                                    }

                                    byte[]? carved = ReadExactFileFromProcessMemory(hProc, fileStartAddr, maxAvailableInRegion, estimatedSize, sigPattern);
                                    if (carved != null && carved.Length > (bestFound?.Length ?? 0))
                                    {
                                        bestFound = carved;
                                        if (!isWirePacketCopy && (estimatedSize <= 0 || bestFound.Length >= estimatedSize))
                                        {
                                            return bestFound;
                                        }
                                    }

                                    searchOffset = foundIdx + sigLen;
                                }
                            }
                            if (toRead <= sigLen) break;
                            offset += toRead - sigLen;
                        }
                    }

                    long nextAddr = baseAddr + regionSize;
                    if (nextAddr <= currentAddr) break;
                    currentAddr = nextAddr;
                }
            }
            catch { }
            finally
            {
                if (hProc != IntPtr.Zero) CloseHandle(hProc);
            }
        }

        return bestFound;
    }

    private static byte[]? ReadExactFileFromProcessMemory(
        IntPtr hProc,
        long fileStartAddr,
        long maxAvailableInRegion,
        long estimatedSize,
        byte[] sigPattern)
    {
        int targetSize = 0;

        // 1. ELF Binary (0x7F 'E' 'L' 'F')
        if (sigPattern.Length >= 4 && sigPattern[0] == 0x7F && sigPattern[1] == 0x45 && sigPattern[2] == 0x4C && sigPattern[3] == 0x46)
        {
            byte[] elfHdr = new byte[64];
            if (ReadProcessMemory(hProc, (IntPtr)fileStartAddr, elfHdr, 64, out int hdrRead) && hdrRead >= 52)
            {
                bool is64 = elfHdr[4] == 2;
                long maxEnd = 0;

                if (is64 && hdrRead >= 64)
                {
                    ulong phoff = BitConverter.ToUInt64(elfHdr, 32);
                    ulong shoff = BitConverter.ToUInt64(elfHdr, 40);
                    ushort phentsize = BitConverter.ToUInt16(elfHdr, 54);
                    ushort phnum = BitConverter.ToUInt16(elfHdr, 56);
                    ushort shentsize = BitConverter.ToUInt16(elfHdr, 58);
                    ushort shnum = BitConverter.ToUInt16(elfHdr, 60);

                    if (shoff > 0 && shnum > 0 && shentsize > 0 && shnum <= 4096 && shentsize <= 256)
                    {
                        long shEnd = (long)(shoff + (ulong)(shentsize * shnum));
                        if (shEnd > 0 && shEnd <= 64 * 1024 * 1024) maxEnd = Math.Max(maxEnd, shEnd);
                    }

                    if (phoff > 0 && phnum > 0 && phentsize >= 56 && phnum <= 128)
                    {
                        byte[] phTable = new byte[phentsize * phnum];
                        if (ReadProcessMemory(hProc, (IntPtr)(fileStartAddr + (long)phoff), phTable, phTable.Length, out int phRead) && phRead == phTable.Length)
                        {
                            for (int i = 0; i < phnum; i++)
                            {
                                int pPos = i * phentsize;
                                ulong pOffset = BitConverter.ToUInt64(phTable, pPos + 8);
                                ulong pFilesz = BitConverter.ToUInt64(phTable, pPos + 32);
                                long segEnd = (long)(pOffset + pFilesz);
                                if (segEnd > maxEnd && segEnd <= 64 * 1024 * 1024)
                                    maxEnd = segEnd;
                            }
                        }
                    }
                }
                else
                {
                    uint phoff = BitConverter.ToUInt32(elfHdr, 28);
                    uint shoff = BitConverter.ToUInt32(elfHdr, 32);
                    ushort phentsize = BitConverter.ToUInt16(elfHdr, 42);
                    ushort phnum = BitConverter.ToUInt16(elfHdr, 44);
                    ushort shentsize = BitConverter.ToUInt16(elfHdr, 46);
                    ushort shnum = BitConverter.ToUInt16(elfHdr, 48);

                    if (shoff > 0 && shnum > 0 && shentsize > 0 && shnum <= 4096 && shentsize <= 256)
                    {
                        long shEnd = shoff + (long)(shentsize * shnum);
                        if (shEnd > 0 && shEnd <= 64 * 1024 * 1024) maxEnd = Math.Max(maxEnd, shEnd);
                    }

                    if (phoff > 0 && phnum > 0 && phentsize >= 32 && phnum <= 128)
                    {
                        byte[] phTable = new byte[phentsize * phnum];
                        if (ReadProcessMemory(hProc, (IntPtr)(fileStartAddr + phoff), phTable, phTable.Length, out int phRead) && phRead == phTable.Length)
                        {
                            for (int i = 0; i < phnum; i++)
                            {
                                int pPos = i * phentsize;
                                uint pOffset = BitConverter.ToUInt32(phTable, pPos + 4);
                                uint pFilesz = BitConverter.ToUInt32(phTable, pPos + 16);
                                long segEnd = pOffset + pFilesz;
                                if (segEnd > maxEnd && segEnd <= 64 * 1024 * 1024)
                                    maxEnd = segEnd;
                            }
                        }
                    }
                }

                if (maxEnd > 64 && maxEnd <= 64 * 1024 * 1024)
                {
                    targetSize = (int)maxEnd;
                }
            }
        }
        // 2. DEX Header ("dex\n03")
        else if (sigPattern.Length >= 8 && sigPattern[0] == 0x64 && sigPattern[1] == 0x65 && sigPattern[2] == 0x78 && sigPattern[3] == 0x0A)
        {
            byte[] dexHdr = new byte[36];
            if (ReadProcessMemory(hProc, (IntPtr)fileStartAddr, dexHdr, 36, out int dRead) && dRead == 36)
            {
                uint dSize = BitConverter.ToUInt32(dexHdr, 32);
                if (dSize > 36 && dSize <= 64 * 1024 * 1024)
                {
                    targetSize = (int)dSize;
                }
            }
        }
        // 3. ZIP / APK (0x50 0x4B 0x03 0x04)
        else if (sigPattern.Length >= 4 && sigPattern[0] == 0x50 && sigPattern[1] == 0x4B && sigPattern[2] == 0x03 && sigPattern[3] == 0x04)
        {
            int maxScanBytes = (int)Math.Min(Math.Max(maxAvailableInRegion, 32 * 1024 * 1024L), 64 * 1024 * 1024L);
            byte[] winBuf = new byte[512 * 1024];
            int scanned = 0;

            while (scanned < maxScanBytes)
            {
                int toRead = Math.Min(winBuf.Length, maxScanBytes - scanned);
                if (!ReadProcessMemory(hProc, (IntPtr)(fileStartAddr + scanned), winBuf, toRead, out int r) || r < 22)
                    break;

                for (int i = 0; i <= r - 22; i++)
                {
                    if (winBuf[i] == 0x50 && winBuf[i + 1] == 0x4B && winBuf[i + 2] == 0x05 && winBuf[i + 3] == 0x06)
                    {
                        uint cdSize = BitConverter.ToUInt32(winBuf, i + 12);
                        uint cdOffset = BitConverter.ToUInt32(winBuf, i + 16);
                        ushort commentLen = BitConverter.ToUInt16(winBuf, i + 20);
                        long eocdPosFromStart = scanned + i;

                        if (cdOffset + cdSize == (ulong)eocdPosFromStart)
                        {
                            targetSize = (int)(eocdPosFromStart + 22 + commentLen);
                            break;
                        }
                    }
                }

                if (targetSize > 0) break;
                if (r < 64) break;
                scanned += r - 32;
            }
        }
        // 4. XML / Text / Policy Files (e.g. ADP.xml, ASKSW.xml, trustedTime)
        else if (sigPattern.Length >= 4 && (sigPattern[0] == (byte)'<' || IsMostlyPrintableAscii(sigPattern)))
        {
            int maxTextScan = (int)Math.Min(Math.Max(maxAvailableInRegion, 256 * 1024L), 2 * 1024 * 1024L);
            byte[] textBuf = new byte[Math.Min(maxTextScan, 512 * 1024)];
            if (ReadProcessMemory(hProc, (IntPtr)fileStartAddr, textBuf, textBuf.Length, out int tRead) && tRead > 0)
            {
                int endIdx = 0;
                while (endIdx < tRead)
                {
                    byte b = textBuf[endIdx];
                    if (b == 0) break;
                    if (b < 0x09 || (b > 0x0D && b < 0x20)) break;
                    endIdx++;
                }

                if (endIdx > 0)
                {
                    targetSize = (estimatedSize > 0 && estimatedSize <= endIdx) ? (int)estimatedSize : endIdx;
                }
            }
        }

        if (targetSize <= 0 && estimatedSize > 0 && estimatedSize <= 64 * 1024 * 1024)
        {
            targetSize = (int)estimatedSize;
        }

        if (targetSize > 0 && targetSize <= 64 * 1024 * 1024)
        {
            byte[] fullBytes = new byte[targetSize];
            byte[] tempChunk = new byte[Math.Min(256 * 1024, targetSize)];
            int totalRead = 0;

            while (totalRead < targetSize)
            {
                int chunkLen = Math.Min(tempChunk.Length, targetSize - totalRead);
                if (!ReadProcessMemory(hProc, (IntPtr)(fileStartAddr + totalRead), tempChunk, chunkLen, out int got) || got <= 0)
                {
                    int pageLen = Math.Min(4096, targetSize - totalRead);
                    if (!ReadProcessMemory(hProc, (IntPtr)(fileStartAddr + totalRead), tempChunk, pageLen, out got) || got <= 0)
                        break;
                }

                Buffer.BlockCopy(tempChunk, 0, fullBytes, totalRead, got);
                totalRead += got;
            }

            if (totalRead > 0)
            {
                return totalRead == targetSize ? fullBytes : fullBytes[..totalRead];
            }
        }

        return null;
    }

    private static bool IsMostlyPrintableAscii(byte[] data)
    {
        if (data == null || data.Length == 0) return false;
        int printable = 0;
        foreach (byte b in data)
        {
            if (b == 9 || b == 10 || b == 13 || (b >= 32 && b <= 126)) printable++;
        }
        return printable >= (data.Length * 3) / 4;
    }

    /// <summary>
    /// Strictly saves ONLY ONE file per pushed artifact using its exact original filename.
    /// Supports files of any size >= 1 byte (including 72-byte ASKSW.xml).
    /// </summary>
    public static CapturedPushedFileRecord? SaveSingleCleanFileToDisk(
        byte[] fileBytes,
        string targetPath,
        string mode,
        string captureVector)
    {
        if (fileBytes == null || fileBytes.Length == 0) return null;

        string fname = Path.GetFileName(targetPath);
        if (string.IsNullOrWhiteSpace(fname) || IsIgnoredNoiseFile(fname)) return null;

        string artifactsDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "CapturedArtifacts");
        try
        {
            Directory.CreateDirectory(artifactsDir);
        }
        catch { }

        string originalSavedPath = Path.Combine(artifactsDir, fname);
        try
        {
            if (File.Exists(originalSavedPath))
            {
                long existingLen = new FileInfo(originalSavedPath).Length;
                if (fileBytes.Length < existingLen)
                {
                    fileBytes = File.ReadAllBytes(originalSavedPath);
                }
                else
                {
                    File.WriteAllBytes(originalSavedPath, fileBytes);
                }
            }
            else
            {
                File.WriteAllBytes(originalSavedPath, fileBytes);
            }
        }
        catch { }

        string sha256 = Convert.ToHexString(SHA256.HashData(fileBytes));
        string md5 = Convert.ToHexString(MD5.HashData(fileBytes));
        var classification = SmartContentClassifier.Classify(fileBytes);

        string summary = $"[ADB-PUSH] Saved: {targetPath} -> CapturedArtifacts/{fname} ({fileBytes.Length:N0} bytes | {classification.Description} | {captureVector})";

        return new CapturedPushedFileRecord
        {
            TargetDevicePath = targetPath,
            FileName = fname,
            FilePermissionMode = mode,
            LocalSavedPath = originalSavedPath,
            FileBytes = fileBytes,
            FileSizeBytes = fileBytes.Length,
            DeclaredDataSize = fileBytes.Length,
            Sha256 = sha256,
            Md5 = md5,
            FileClassification = classification.Classification,
            MagicDescription = classification.Description,
            IsExecutableOrExploit = classification.IsExecutableOrExploit,
            CaptureVector = captureVector,
            Timestamp = DateTime.UtcNow,
            Summary = summary,
            AdditionalDetails = $"Target Path: {targetPath}\nMode: {mode}\nTotal Bytes: {fileBytes.Length:N0}\nFormat: {classification.Description}\nSHA-256: {sha256}\nVector: {captureVector}\nSaved File: {originalSavedPath}"
        };
    }

    private static int IndexOfSequence(ReadOnlySpan<byte> buffer, ReadOnlySpan<byte> pattern)
    {
        if (buffer.Length < pattern.Length || pattern.Length == 0) return -1;
        return buffer.IndexOf(pattern);
    }

    private static bool StartsWithAscii(byte[] chunk, string token)
    {
        if (chunk == null || chunk.Length < token.Length) return false;
        for (int i = 0; i < token.Length; i++)
        {
            if (chunk[i] != (byte)token[i]) return false;
        }
        return true;
    }

    private static int FindAsciiTokenOffset(byte[] chunk, string token, int start, int maxEnd)
    {
        if (chunk == null || maxEnd - start < token.Length) return -1;
        int limit = Math.Min(chunk.Length, maxEnd) - token.Length;
        for (int i = start; i <= limit; i++)
        {
            bool match = true;
            for (int j = 0; j < token.Length; j++)
            {
                if (chunk[i + j] != (byte)token[j])
                {
                    match = false;
                    break;
                }
            }
            if (match) return i;
        }
        return -1;
    }

    public static int FindDataHeaderOffset(byte[] chunk, int startOffset = 0)
    {
        if (chunk == null || chunk.Length < startOffset + 8) return -1;
        int maxSearch = chunk.Length - 8;
        for (int i = Math.Max(0, startOffset); i <= maxSearch; i++)
        {
            if (chunk[i] == 'D' && chunk[i + 1] == 'A' && chunk[i + 2] == 'T' && chunk[i + 3] == 'A')
            {
                return i;
            }
        }
        return -1;
    }

    public static int FindDoneTrailerOffset(byte[] chunk, int minOffset = 0)
    {
        if (chunk == null || chunk.Length < minOffset + 8) return -1;

        int exactPos = chunk.Length - 8;
        if (exactPos >= minOffset &&
            chunk[exactPos] == 'D' && chunk[exactPos + 1] == 'O' &&
            chunk[exactPos + 2] == 'N' && chunk[exactPos + 3] == 'E')
        {
            return exactPos;
        }

        for (int i = chunk.Length - 8; i >= minOffset; i--)
        {
            if (chunk[i] == 'D' && chunk[i + 1] == 'O' && chunk[i + 2] == 'N' && chunk[i + 3] == 'E')
            {
                return i;
            }
        }
        return -1;
    }

    private static bool IsAdbWireHeader(byte[] buffer, int offset)
    {
        if (buffer == null || offset + 24 > buffer.Length) return false;
        uint cmd = BitConverter.ToUInt32(buffer, offset);
        uint magic = BitConverter.ToUInt32(buffer, offset + 20);
        return (cmd ^ 0xFFFFFFFF) == magic;
    }

    public static byte[] StripDoneTrailer(byte[] data)
    {
        if (data == null || data.Length < 4) return data ?? [];
        int len = data.Length;
        if (len >= 8 && data[len - 8] == 'D' && data[len - 7] == 'O' && data[len - 6] == 'N' && data[len - 5] == 'E')
        {
            return data[..(len - 8)];
        }
        if (len >= 4 && data[len - 4] == 'D' && data[len - 3] == 'O' && data[len - 2] == 'N' && data[len - 1] == 'E')
        {
            return data[..(len - 4)];
        }
        return data;
    }

    public void Dispose()
    {
        try
        {
            _cts.Cancel();
            _jobChannel.Writer.TryComplete();
        }
        catch { }
    }
}
