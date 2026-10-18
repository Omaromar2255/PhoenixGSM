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
/// Non-blocking background job for parallel full-size file recovery and disk saving.
/// </summary>
internal sealed class PendingFileArchiveJob
{
    public string TargetPath { get; init; } = string.Empty;
    public string Mode { get; init; } = "33188";
    public byte[] WireBytes { get; init; } = [];
    public byte[]? HeaderSignature { get; init; }
    public long TotalDeclaredBytes { get; init; }
    public long TotalActualUrbBytes { get; init; }
    public bool HadTruncatedUrb { get; init; }
    public string EndpointHex { get; init; } = "0x01";
    public string TriggerReason { get; init; } = "DONE";
}

/// <summary>
/// LAYER 12C — High-Speed Parallel Smart File Push Archiver
/// Zero-latency on the USB capture thread: buffers wire chunks in memory (< 5us) and offloads
/// all heavy recovery (adb pull mirror, 64-bit target process RAM carving, disk I/O, hashing)
/// to a dedicated parallel background worker channel.
/// Strictly saves ONLY ONE file per pushed item (no duplicate .elf or .analysis.txt files).
/// </summary>
public sealed class SmartFilePushArchiver : IDisposable
{
    public static readonly Regex PathAndModeRegex = new(
        @"((?:/data/local/tmp/|/data/|/sdcard/|/storage/|/system/|/vendor/|/tmp/)[A-Za-z0-9_\-\./]+)(?:,(\d+))?",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public static readonly Regex Base64EchoRegex = new(
        @"echo\s+['""]?([A-Za-z0-9+/=]{16,})['""]?\s*\|\s*(?:toybox\s+|busybox\s+)?base64\s+(?:-d|--decode)\s*>\s*([^\s;&|]+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private readonly object _transferLock = new();
    private readonly MemoryStream _activeUploadStream = new();
    private string _activeTargetPath = string.Empty;
    private string _pendingStatPath = string.Empty;
    private string _activeMode = "33188";
    private long _declaredDataSize = 0;
    private long _totalActualUrbBytes = 0;
    private byte[]? _firstHeaderSignature = null;
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

        // Start 2 parallel background consumers so large files (e.g. 15MB R2.zip) never block small files
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

    #region P/Invoke Definitions for 64-Bit Process RAM Carving
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

    /// <summary>
    /// Fast, non-blocking packet ingestion on the USB capture thread.
    /// Never performs disk I/O or process memory scans on the calling thread.
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

        string rawAsciiPreview = Encoding.ASCII.GetString(chunk[..Math.Min(chunk.Length, 128)]);
        string cleanLineTrimmed = rawAsciiPreview.Trim('\r', '\n', '\0', ' ');

        if (cleanLineTrimmed.StartsWith("shell:", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        lock (_transferLock)
        {
            string combined = _pendingHeaderBuffer + rawAsciiPreview;

            bool hasSendToken = StartsWithAscii(chunk, "SEND") || FindAsciiTokenOffset(chunk, "SEND", 0, Math.Min(chunk.Length, 64)) >= 0;
            bool hasStatToken = StartsWithAscii(chunk, "STAT") || FindAsciiTokenOffset(chunk, "STAT", 0, Math.Min(chunk.Length, 32)) >= 0;

            // Only run regex on header-sized previews or when SEND/STAT/path prefix is present
            Match m = Match.Empty;
            if (hasSendToken || hasStatToken || !string.IsNullOrEmpty(_pendingHeaderBuffer) ||
                rawAsciiPreview.Contains("/data/") || rawAsciiPreview.Contains("/sdcard/"))
            {
                m = PathAndModeRegex.Match(combined);
                if (!m.Success && chunk.Length <= 256)
                {
                    m = PathAndModeRegex.Match(Encoding.ASCII.GetString(chunk));
                }
            }

            if (hasSendToken || hasStatToken || m.Success)
            {
                if (m.Success)
                {
                    string matchedPath = m.Groups[1].Value.Trim();
                    bool hasExplicitMode = m.Groups[2].Success;
                    string matchedMode = hasExplicitMode ? m.Groups[2].Value.Trim() : "33188";

                    // If this is merely a STAT path check before SEND, record _pendingStatPath without resetting an active stream for the same file
                    if (hasStatToken && !hasSendToken && !hasExplicitMode)
                    {
                        if (_isInsideTransfer && _activeUploadStream.Length > 0 &&
                            !string.IsNullOrEmpty(_activeTargetPath) &&
                            !string.Equals(_activeTargetPath, matchedPath, StringComparison.OrdinalIgnoreCase))
                        {
                            EnqueueCurrentTransferForBackgroundSave(epHex, "NewStatStarted");
                        }
                        _pendingStatPath = matchedPath;
                        _pendingHeaderBuffer = string.Empty;
                        return false;
                    }

                    // If previous transfer for a different file had data, enqueue it for background saving first
                    if (_isInsideTransfer && _activeUploadStream.Length > 0 &&
                        !string.IsNullOrEmpty(_activeTargetPath) &&
                        !string.Equals(_activeTargetPath, matchedPath, StringComparison.OrdinalIgnoreCase))
                    {
                        EnqueueCurrentTransferForBackgroundSave(epHex, "NewSendStarted");
                    }

                    _activeTargetPath = matchedPath;
                    _activeMode = matchedMode;
                    _isInsideTransfer = true;
                    _activeUploadStream.SetLength(0);
                    _declaredDataSize = 0;
                    _totalActualUrbBytes = 0;
                    _firstHeaderSignature = null;
                    _hadTruncatedUrb = actualUrbLength > chunk.Length;
                    _pendingHeaderBuffer = string.Empty;
                    _lastChunkTime = DateTime.UtcNow;

                    int dataIdx = FindDataHeaderOffset(chunk);
                    if (dataIdx >= 0 && dataIdx + 8 <= chunk.Length)
                    {
                        uint dLen = BitConverter.ToUInt32(chunk, dataIdx + 4);
                        if (dLen > 0 && dLen <= 64 * 1024 * 1024)
                        {
                            _declaredDataSize += dLen;
                        }

                        int payloadStart = dataIdx + 8;
                        bool isTruncatedPacket = actualUrbLength > chunk.Length;
                        int doneIdx = !isTruncatedPacket ? FindDoneTrailerOffset(chunk, payloadStart) : -1;
                        int payloadEnd = (doneIdx >= payloadStart) ? doneIdx : chunk.Length;

                        if (payloadEnd > payloadStart)
                        {
                            int count = payloadEnd - payloadStart;
                            _activeUploadStream.Write(chunk, payloadStart, count);

                            if (_firstHeaderSignature == null && count >= 16)
                            {
                                _firstHeaderSignature = chunk[payloadStart..(payloadStart + Math.Min(count, 64))];
                            }
                        }

                        _totalActualUrbBytes += Math.Max(actualUrbLength, (uint)chunk.Length);

                        if (doneIdx >= payloadStart)
                        {
                            EnqueueCurrentTransferForBackgroundSave(epHex, "SinglePacketSendDataDone");
                            return true;
                        }
                    }

                    return false;
                }
                else if (hasSendToken || hasStatToken)
                {
                    _pendingHeaderBuffer = rawAsciiPreview;
                    _lastChunkTime = DateTime.UtcNow;
                    return false;
                }
            }

            // Active transfer continuation chunk
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

                // Check for standalone 8-byte DONE packet ("DONE" + 4-byte mtime)
                if (chunk.Length == 8 && StartsWithAscii(chunk, "DONE"))
                {
                    EnqueueCurrentTransferForBackgroundSave(epHex, "StandaloneDonePacket");
                    return true;
                }

                int payloadStart = 0;
                if (StartsWithAscii(chunk, "DATA") && chunk.Length >= 8)
                {
                    uint dLen = BitConverter.ToUInt32(chunk, 4);
                    if (dLen > 0 && dLen <= 64 * 1024 * 1024)
                    {
                        _declaredDataSize += dLen;
                    }
                    payloadStart = 8;
                }
                else if (chunk.Length >= 24 && IsAdbWireHeader(chunk, 0))
                {
                    payloadStart = 24;
                    if (chunk.Length >= 32 && chunk[24] == 'D' && chunk[25] == 'A' && chunk[26] == 'T' && chunk[27] == 'A')
                    {
                        uint dLen = BitConverter.ToUInt32(chunk, 28);
                        if (dLen > 0 && dLen <= 64 * 1024 * 1024)
                        {
                            _declaredDataSize += dLen;
                        }
                        payloadStart = 32;
                    }
                }

                // Only check for DONE trailer at the end of the chunk if this URB was NOT truncated (actualUrbLength <= chunk.Length)
                bool isTruncatedPacket = actualUrbLength > chunk.Length;
                int doneIdx = !isTruncatedPacket ? FindDoneTrailerOffset(chunk, payloadStart) : -1;
                int payloadEnd = (doneIdx >= payloadStart) ? doneIdx : chunk.Length;

                if (payloadEnd > payloadStart)
                {
                    int count = payloadEnd - payloadStart;
                    _activeUploadStream.Write(chunk, payloadStart, count);

                    if (_firstHeaderSignature == null && count >= 16)
                    {
                        _firstHeaderSignature = chunk[payloadStart..(payloadStart + Math.Min(count, 64))];
                    }
                }

                if (doneIdx >= payloadStart)
                {
                    EnqueueCurrentTransferForBackgroundSave(epHex, "DoneTrailerInChunk");
                    return true;
                }
            }

            return false;
        }
    }

    /// <summary>
    /// Non-blocking check when a shell command arrives.
    /// Enqueues any pending file transfer for parallel saving AND ensures any referenced /data/local/tmp/ file
    /// is mirrored in the background if not yet saved at full size.
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

        // 3. If the shell command references a file in /data/local/tmp/ (e.g. chmod 777 /data/local/tmp/AT or unzip /data/local/tmp/R2.zip),
        // trigger a background check to pull the full original file from the device if our saved copy is missing or smaller!
        if (!trimmed.StartsWith("rm ", StringComparison.OrdinalIgnoreCase) &&
            !trimmed.Contains("rm -r", StringComparison.OrdinalIgnoreCase))
        {
            var matches = PathAndModeRegex.Matches(trimmed);
            foreach (Match pm in matches)
            {
                string refPath = pm.Groups[1].Value.Trim();
                if (string.IsNullOrEmpty(refPath) || refPath.EndsWith("/") || refPath.EndsWith("*")) continue;

                _jobChannel.Writer.TryWrite(new PendingFileArchiveJob
                {
                    TargetPath = refPath,
                    Mode = "0777",
                    WireBytes = [],
                    HeaderSignature = null,
                    TotalDeclaredBytes = 0,
                    TotalActualUrbBytes = 0,
                    HadTruncatedUrb = true,
                    EndpointHex = "0x01",
                    TriggerReason = "ShellReferenceVerify"
                });
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

            // Do NOT prematurely cut off a large multi-megabyte transfer (like 15MB R2.zip or 480KB AT)
            // on a transient CLSE frame from an earlier channel while chunks are actively flowing!
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
        _hadTruncatedUrb = false;
        _pendingHeaderBuffer = string.Empty;

        if (string.IsNullOrWhiteSpace(targetPath)) return;

        _jobChannel.Writer.TryWrite(new PendingFileArchiveJob
        {
            TargetPath = targetPath,
            Mode = mode,
            WireBytes = StripDoneTrailer(wireBytes),
            HeaderSignature = sig,
            TotalDeclaredBytes = declared,
            TotalActualUrbBytes = actualUrb,
            HadTruncatedUrb = truncated,
            EndpointHex = epHex,
            TriggerReason = reason
        });
    }

    /// <summary>
    /// Dedicated background worker loop: recovers the 100% full-size file in parallel
    /// without ever slowing down the USB/ADB command capture loop.
    /// </summary>
    private async Task ProcessArchiveJobsLoopAsync(CancellationToken token)
    {
        await foreach (var job in _jobChannel.Reader.ReadAllAsync(token))
        {
            try
            {
                string fileName = Path.GetFileName(job.TargetPath);
                if (string.IsNullOrWhiteSpace(fileName)) continue;

                // Check if we already have a complete, larger copy saved for this path
                long existingSavedSize = _savedFileSizesByPath.TryGetValue(job.TargetPath, out long s) ? s : 0;
                if (job.TriggerReason == "ShellReferenceVerify" && existingSavedSize > 65536)
                {
                    continue;
                }

                byte[] bestBytes = job.WireBytes ?? [];
                string bestVector = "USB Wire Stream";

                bool needsFullRecovery = job.HadTruncatedUrb ||
                                         bestBytes.Length == 0 ||
                                         (job.TotalDeclaredBytes > bestBytes.Length) ||
                                         (job.TotalActualUrbBytes > bestBytes.Length + 512);

                if (needsFullRecovery)
                {
                    // Run all 3 full-file recovery vectors in parallel and pick the most complete result!
                    var diskTask = Task.Run(() => TryRecoverFromHostDisk(fileName, job.HeaderSignature), token);
                    var pullTask = Task.Run(() => TryPullFullFileFromDevice(job.TargetPath), token);
                    var ramTask = Task.Run(() => TryCarveFileFromTargetProcessRam(job.HeaderSignature, Math.Max(job.TotalDeclaredBytes, job.TotalActualUrbBytes)), token);

                    await Task.WhenAll(diskTask, pullTask, ramTask);

                    byte[]? diskBytes = diskTask.Result;
                    byte[]? pulledBytes = pullTask.Result;
                    byte[]? ramBytes = ramTask.Result;

                    if (diskBytes != null && diskBytes.Length > bestBytes.Length)
                    {
                        bestBytes = diskBytes;
                        bestVector = "Host Disk Snapshot";
                    }
                    if (pulledBytes != null && pulledBytes.Length > bestBytes.Length)
                    {
                        bestBytes = pulledBytes;
                        bestVector = "Device Direct Mirror (adb pull)";
                    }
                    if (ramBytes != null && ramBytes.Length > bestBytes.Length)
                    {
                        bestBytes = ramBytes;
                        bestVector = "Process RAM Carve (64-Bit)";
                    }
                }

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
    /// Pulls the exact full-size file (e.g. 15MB R2.zip or 480KB AT) directly from the connected phone
    /// using the resolved path of the running adb.exe process.
    /// </summary>
    public static byte[]? TryPullFullFileFromDevice(string remoteDevicePath)
    {
        if (string.IsNullOrWhiteSpace(remoteDevicePath) || !remoteDevicePath.StartsWith("/"))
            return null;

        string adbExe = ResolveRunningAdbExecutablePath();
        string fname = Path.GetFileName(remoteDevicePath);
        string shadowRemotePath = $"/data/local/tmp/.phx_keep_{fname}";
        string tempFile = Path.Combine(Path.GetTempPath(), $"phx_pull_{Guid.NewGuid():N}.tmp");

        try
        {
            // Step 1: Create an instant hard-link (ln -f) on /data/local/tmp/ (< 2ms for 15MB!)
            // so even if the GSM tool runs "rm -r /data/local/tmp/R2.zip" 100ms later, the 15MB inode remains intact!
            var lnPsi = new ProcessStartInfo
            {
                FileName = adbExe,
                Arguments = $"shell \"ln -f '{remoteDevicePath}' '{shadowRemotePath}' 2>/dev/null || cp -f '{remoteDevicePath}' '{shadowRemotePath}' 2>/dev/null\"",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using (var lnProc = Process.Start(lnPsi))
            {
                lnProc?.WaitForExit(800);
            }

            // Step 2: Pull from the protected shadow link first, or fallback to original remoteDevicePath
            foreach (string pullSource in new[] { shadowRemotePath, remoteDevicePath })
            {
                var psi = new ProcessStartInfo
                {
                    FileName = adbExe,
                    Arguments = $"pull \"{pullSource}\" \"{tempFile}\"",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                using var proc = Process.Start(psi);
                if (proc != null)
                {
                    if (!proc.WaitForExit(8000))
                    {
                        try { proc.Kill(); } catch { }
                    }
                }

                if (File.Exists(tempFile))
                {
                    byte[] data = File.ReadAllBytes(tempFile);
                    try { File.Delete(tempFile); } catch { }
                    if (data.Length > 0)
                    {
                        // Clean up shadow link on device asynchronously
                        _ = Task.Run(() =>
                        {
                            try
                            {
                                using var rmProc = Process.Start(new ProcessStartInfo
                                {
                                    FileName = adbExe,
                                    Arguments = $"shell \"rm -f '{shadowRemotePath}' 2>/dev/null\"",
                                    UseShellExecute = false,
                                    CreateNoWindow = true
                                });
                                rmProc?.WaitForExit(1000);
                            }
                            catch { }
                        });
                        return data;
                    }
                }
            }
        }
        catch
        {
            try { if (File.Exists(tempFile)) File.Delete(tempFile); } catch { }
        }

        return null;
    }

    private static string ResolveRunningAdbExecutablePath()
    {
        try
        {
            foreach (var p in Process.GetProcessesByName("adb"))
            {
                try
                {
                    string? path = p.MainModule?.FileName;
                    if (!string.IsNullOrEmpty(path) && File.Exists(path))
                        return path;
                }
                catch { }
                finally { p.Dispose(); }
            }
        }
        catch { }

        return "adb";
    }

    private static byte[]? TryRecoverFromHostDisk(string fileName, byte[]? headerSig)
    {
        if (string.IsNullOrWhiteSpace(fileName)) return null;

        var dirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            Path.GetTempPath(),
            Environment.CurrentDirectory,
            AppDomain.CurrentDomain.BaseDirectory
        };

        try
        {
            foreach (var p in Process.GetProcesses())
            {
                try
                {
                    if (p.Id <= 4 || p.Id == Environment.ProcessId) continue;
                    string pn = p.ProcessName.ToLowerInvariant();
                    if (pn.Contains("adb") || pn.Contains("key") || pn.Contains("tool") || pn.Contains("samfw") || pn.Contains("chimera") || pn.Contains("unlock"))
                    {
                        string? exe = p.MainModule?.FileName;
                        if (!string.IsNullOrEmpty(exe))
                        {
                            string? d = Path.GetDirectoryName(exe);
                            if (!string.IsNullOrEmpty(d)) dirs.Add(d);
                        }
                    }
                }
                catch { }
                finally { p.Dispose(); }
            }
        }
        catch { }

        foreach (string dir in dirs)
        {
            try
            {
                if (!Directory.Exists(dir)) continue;
                string candidate = Path.Combine(dir, fileName);
                if (File.Exists(candidate))
                {
                    using var fs = new FileStream(candidate, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                    if (fs.Length > 0 && fs.Length <= 128 * 1024 * 1024)
                    {
                        byte[] buf = new byte[fs.Length];
                        int read = fs.Read(buf, 0, buf.Length);
                        if (read == buf.Length) return buf;
                    }
                }
            }
            catch { }
        }

        return null;
    }

    /// <summary>
    /// Fast, targeted 64-bit & 32-bit RAM carver.
    /// ONLY scans the target GSM tool processes and adb.exe (never scans all 150 system processes!).
    /// Supports 64-bit user address space up to 0x7FFFFFFF0000 and parses true ELF/ZIP/DEX sizes.
    /// </summary>
    public byte[]? TryCarveFileFromTargetProcessRam(byte[]? signature, long estimatedSize)
    {
        if (signature == null || signature.Length < 16) return null;

        int sigLen = Math.Min(signature.Length, 32);
        byte[] sig32 = signature[..sigLen];

        var targetPids = new HashSet<int>(_candidatePids.Keys);

        try
        {
            foreach (var p in Process.GetProcesses())
            {
                try
                {
                    if (p.Id <= 4 || p.Id == Environment.ProcessId) continue;
                    string pn = p.ProcessName.ToLowerInvariant();
                    if (pn.Contains("key") || pn.Contains("tool") || pn.Contains("adb") ||
                        pn.Contains("samfw") || pn.Contains("unlock") || pn.Contains("chimera") ||
                        pn.Contains("odin") || pn.Contains("fastboot"))
                    {
                        targetPids.Add(p.Id);
                    }
                }
                catch { }
                finally { p.Dispose(); }
            }
        }
        catch { }

        foreach (int pid in targetPids)
        {
            IntPtr hProc = IntPtr.Zero;
            try
            {
                hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
                if (hProc == IntPtr.Zero) continue;

                long currentAddr = 0x10000;
                long maxAddr = Environment.Is64BitOperatingSystem ? 0x00007FFFFFFF0000L : 0x7FFF0000L;
                uint mbiSize = (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();
                byte[] chunkBuf = new byte[256 * 1024]; // 256KB scan window for fast sequential reads

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

                    if (isReadable && regionSize >= sigLen && regionSize <= 64 * 1024 * 1024)
                    {
                        long offset = 0;
                        while (offset < regionSize)
                        {
                            int toRead = (int)Math.Min(chunkBuf.Length, regionSize - offset);
                            if (ReadProcessMemory(hProc, (IntPtr)(baseAddr + offset), chunkBuf, toRead, out int bytesRead) && bytesRead >= sigLen)
                            {
                                int foundIdx = IndexOfSequence(chunkBuf.AsSpan(0, bytesRead), sig32);
                                if (foundIdx >= 0)
                                {
                                    long fileStartAddr = baseAddr + offset + foundIdx;
                                    long maxAvailableInRegion = regionSize - (offset + foundIdx);
                                    byte[]? fullFile = ReadExactFileFromProcessMemory(hProc, fileStartAddr, maxAvailableInRegion, estimatedSize, sig32);
                                    if (fullFile != null && fullFile.Length > signature.Length)
                                    {
                                        return fullFile;
                                    }
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

        return null;
    }

    /// <summary>
    /// Determines the true file size in RAM by prioritizing format headers (ELF Program+Section headers,
    /// ZIP End-of-Central-Directory up to 32MB, DEX file_size header) over the 64KB ADB DATA block size.
    /// </summary>
    private static byte[]? ReadExactFileFromProcessMemory(
        IntPtr hProc,
        long fileStartAddr,
        long maxAvailableInRegion,
        long estimatedSize,
        byte[] sig32)
    {
        int targetSize = 0;

        // 1. ELF Binary (0x7F 'E' 'L' 'F', e.g. AT = ~480 KB): compute max end across BOTH Program Headers and Section Headers!
        if (sig32.Length >= 4 && sig32[0] == 0x7F && sig32[1] == 0x45 && sig32[2] == 0x4C && sig32[3] == 0x46)
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

                    if (shoff > 0 && shnum > 0 && shentsize > 0)
                    {
                        maxEnd = Math.Max(maxEnd, (long)(shoff + (ulong)(shentsize * shnum)));
                    }

                    if (phoff > 0 && phnum > 0 && phentsize >= 56 && phnum <= 64)
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

                    if (shoff > 0 && shnum > 0 && shentsize > 0)
                    {
                        maxEnd = Math.Max(maxEnd, shoff + (long)(shentsize * shnum));
                    }

                    if (phoff > 0 && phnum > 0 && phentsize >= 32 && phnum <= 64)
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
        // 2. DEX Header ("dex\n03"): exact uint32 file_size at offset 32
        else if (sig32.Length >= 8 && sig32[0] == 0x64 && sig32[1] == 0x65 && sig32[2] == 0x78 && sig32[3] == 0x0A)
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
        // 3. ZIP / APK (0x50 0x4B 0x03 0x04, e.g. R2.zip = 15 MB): scan up to 32 MB for verified EOCD (0x50 0x4B 0x05 0x06)
        else if (sig32.Length >= 4 && sig32[0] == 0x50 && sig32[1] == 0x4B && sig32[2] == 0x03 && sig32[3] == 0x04)
        {
            int maxScanBytes = (int)Math.Min(Math.Max(maxAvailableInRegion, 32 * 1024 * 1024L), 32 * 1024 * 1024L);
            byte[] winBuf = new byte[1024 * 1024]; // 1MB sliding window up to 32MB
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

        if (targetSize <= 0 && estimatedSize > 0 && estimatedSize <= 64 * 1024 * 1024)
        {
            targetSize = (int)estimatedSize;
        }

        if (targetSize > 0 && targetSize <= 64 * 1024 * 1024)
        {
            byte[] fullBytes = new byte[targetSize];
            int totalRead = 0;
            while (totalRead < targetSize)
            {
                int chunkLen = Math.Min(1024 * 1024, targetSize - totalRead);
                if (!ReadProcessMemory(hProc, (IntPtr)(fileStartAddr + totalRead), fullBytes, chunkLen, out int got) || got <= 0)
                    break;
                if (totalRead > 0)
                {
                    // Read directly into offset via temp buffer when multi-MB
                    byte[] tmp = new byte[chunkLen];
                    if (!ReadProcessMemory(hProc, (IntPtr)(fileStartAddr + totalRead), tmp, chunkLen, out got) || got <= 0)
                        break;
                    Buffer.BlockCopy(tmp, 0, fullBytes, totalRead, got);
                }
                totalRead += got;
            }

            if (totalRead > 0)
            {
                return totalRead == targetSize ? fullBytes : fullBytes[..totalRead];
            }
        }

        return null;
    }

    /// <summary>
    /// Strictly saves ONLY ONE file per pushed artifact using its exact original filename
    /// (NO duplicate .elf, NO .analysis.txt, NO Extracted_ folders).
    /// </summary>
    public static CapturedPushedFileRecord? SaveSingleCleanFileToDisk(
        byte[] fileBytes,
        string targetPath,
        string mode,
        string captureVector)
    {
        if (fileBytes == null || fileBytes.Length == 0) return null;

        string fname = Path.GetFileName(targetPath);
        if (string.IsNullOrWhiteSpace(fname)) fname = "pushed_file.bin";

        string artifactsDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "CapturedArtifacts");
        try
        {
            Directory.CreateDirectory(artifactsDir);
        }
        catch { }

        string originalSavedPath = Path.Combine(artifactsDir, fname);
        try
        {
            // If an older/smaller version exists, only overwrite if the new capture is >= existing size
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

    public static int FindDataHeaderOffset(byte[] chunk)
    {
        if (chunk == null || chunk.Length < 8) return -1;
        int maxSearch = Math.Min(chunk.Length - 8, 256);
        for (int i = 0; i <= maxSearch; i++)
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

        // Exact 8-byte DONE trailer at the end of the packet ("DONE" + 4-byte mtime)
        int exactPos = chunk.Length - 8;
        if (exactPos >= minOffset &&
            chunk[exactPos] == 'D' && chunk[exactPos + 1] == 'O' &&
            chunk[exactPos + 2] == 'N' && chunk[exactPos + 3] == 'E')
        {
            return exactPos;
        }

        int searchStart = Math.Max(minOffset, chunk.Length - 16);
        for (int i = chunk.Length - 8; i >= searchStart; i--)
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
