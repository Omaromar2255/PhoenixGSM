using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace PhoenixGSM.OmniTrace.Sensors;

/// <summary>
/// LAYER 12C &amp; LAYER 24 SHARED ARCHIVER — High-Integrity Passive Parallel Smart File Push &amp; Extracted File Archiver.
/// - Works across ADB (USB Filter ON or OFF) AND Layer 24 (Modem, MTK DA/Preloader, Odin/Tar, QCN, Firmware/Loader extraction).
/// - Shares a single unified per-session folder under CapturedArtifacts/Session_yyyy-MM-dd_HH-mm-ss across ADB and L24.
/// - Automatically numbers repeated/modified files (e.g., preloader.bin, preloader_2.bin) while deduplicating identical RAM hits.
/// </summary>
public sealed partial class SmartFilePushArchiver : IDisposable
{
    private readonly object _transferLock = new();
    private static readonly object _diskWriteLock = new();
    private static readonly object _sharedSessionLock = new();

    private static string _sharedActiveSessionDirectory = string.Empty;
    private static string _sharedActiveSessionFolderName = string.Empty;
    private static readonly ConcurrentDictionary<string, string> _l24SavedHashByFileKey = new(StringComparer.OrdinalIgnoreCase);
    private static readonly ConcurrentDictionary<string, int> _l24UploadCountByFileName = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Shared active session directory (`CapturedArtifacts\Session_yyyy-MM-dd_HH-mm-ss`) used by both ADB and Layer 24.
    /// </summary>
    public static string ActiveSessionDirectory
    {
        get
        {
            lock (_sharedSessionLock)
            {
                if (string.IsNullOrWhiteSpace(_sharedActiveSessionDirectory) || !Directory.Exists(_sharedActiveSessionDirectory))
                {
                    EnsureSharedSessionFolderInitializedLocked();
                }
                return _sharedActiveSessionDirectory;
            }
        }
    }

    /// <summary>
    /// Shared active session folder name (`Session_yyyy-MM-dd_HH-mm-ss`).
    /// </summary>
    public static string ActiveSessionFolderName
    {
        get
        {
            lock (_sharedSessionLock)
            {
                if (string.IsNullOrWhiteSpace(_sharedActiveSessionFolderName))
                {
                    EnsureSharedSessionFolderInitializedLocked();
                }
                return _sharedActiveSessionFolderName;
            }
        }
    }

    private static void EnsureSharedSessionFolderInitializedLocked()
    {
        string baseRoot = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "CapturedArtifacts");
        string timestampName = $"Session_{DateTime.Now:yyyy-MM-dd_HH-mm-ss}";
        string candidateDir = Path.Combine(baseRoot, timestampName);

        int suffix = 2;
        while (Directory.Exists(candidateDir) && Directory.GetFileSystemEntries(candidateDir).Length > 0)
        {
            timestampName = $"Session_{DateTime.Now:yyyy-MM-dd_HH-mm-ss}_{suffix}";
            candidateDir = Path.Combine(baseRoot, timestampName);
            suffix++;
        }

        try
        {
            Directory.CreateDirectory(candidateDir);
        }
        catch { }

        _sharedActiveSessionFolderName = timestampName;
        _sharedActiveSessionDirectory = candidateDir;
    }

    /// <summary>
    /// Archives any extracted, prepared, or used firmware/loader/DA/QCN/PIT/NV file discovered by Layer 24
    /// directly into the shared ADB session folder (`CapturedArtifacts\Session_...`).
    /// </summary>
    public static bool ArchiveL24ExtractedOrUsedFile(
        string? filePathOrName,
        byte[]? fallbackBytes,
        int processId,
        string callerOrigin,
        out CapturedPushedFileRecord? archivedRecord)
    {
        archivedRecord = null;
        if (string.IsNullOrWhiteSpace(filePathOrName)) return false;

        string cleaned = filePathOrName.Trim().Trim('"', '\'', ' ');
        // Ignore remote cloud URLs that haven't been downloaded to a local file yet
        if (cleaned.StartsWith("//", StringComparison.OrdinalIgnoreCase) ||
            cleaned.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
            cleaned.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        string normalized = cleaned.Replace('/', '\\');
        string fileName = Path.GetFileName(normalized);
        if (string.IsNullOrWhiteSpace(fileName) || fileName.Length < 3 || !fileName.Contains('.'))
            return false;

        if (IsIgnoredNoiseFile(fileName) ||
            fileName.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".psm1", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".sys", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        string? resolvedLocalPath = ResolveL24LocalFilePath(normalized, fileName, processId);
        byte[]? fileBytes = null;

        if (!string.IsNullOrWhiteSpace(resolvedLocalPath) && File.Exists(resolvedLocalPath))
        {
            for (int attempt = 0; attempt < 3; attempt++)
            {
                fileBytes = TryReadL24FileShared(resolvedLocalPath);
                if (fileBytes != null && fileBytes.Length > 0) break;
                Thread.Sleep(60);
            }
        }

        if ((fileBytes == null || fileBytes.Length == 0) && fallbackBytes != null && fallbackBytes.Length > 0)
        {
            fileBytes = fallbackBytes;
        }

        if (fileBytes == null || fileBytes.Length == 0)
            return false;

        string sha256 = Convert.ToHexString(SHA256.HashData(fileBytes));
        string dedupeKey = $"{fileName.ToLowerInvariant()}:{sha256}";

        // Prevent duplicate saving when LiveHeapCommandHunter re-scans the same unchanged file in RAM
        if (!_l24SavedHashByFileKey.TryAdd(dedupeKey, resolvedLocalPath ?? normalized))
        {
            return false;
        }

        int seqNum = _l24UploadCountByFileName.AddOrUpdate(fileName, 1, (_, prev) => prev + 1);
        string sessionDir = ActiveSessionDirectory;
        string sessionFolder = ActiveSessionFolderName;

        archivedRecord = SaveSingleCleanFileToDisk(
            fileBytes,
            resolvedLocalPath ?? filePathOrName,
            "L24-AUTO",
            $"L24 Auto-Saved ({callerOrigin})",
            sessionDir,
            sessionFolder,
            seqNum,
            transferSequenceId: 0,
            isCompleteCapture: true,
            declaredSize: fileBytes.Length,
            kernelDroppedDelta: 0);

        return archivedRecord != null;
    }

    private static string? ResolveL24LocalFilePath(string normalizedPath, string fileName, int processId)
    {
        try
        {
            if (Path.IsPathRooted(normalizedPath) && !normalizedPath.StartsWith("\\") && File.Exists(normalizedPath))
            {
                return normalizedPath;
            }

            // Handle root-relative paths like `\UnlockTool\Temp\pgpt.bin` or `\Users\trihc\Desktop\...`
            string trimmedRelative = normalizedPath.TrimStart('\\');
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (!drive.IsReady) continue;
                string driveCandidate = Path.Combine(drive.RootDirectory.FullName, trimmedRelative);
                if (File.Exists(driveCandidate)) return driveCandidate;
            }

            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string? procCwd = processId > 4 ? TryGetProcessCurrentDirectory(processId) : null;
            string? procExeDir = processId > 4 ? Path.GetDirectoryName(TryGetProcessExecutablePath(processId)) : null;

            string?[] searchRoots =
            [
                procCwd,
                procExeDir,
                @"C:\UnlockTool\Temp",
                @"C:\UnlockTool",
                @"C:\UnlockTool\Binaries",
                Path.GetTempPath(),
                Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                Path.Combine(userProfile, "Downloads"),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Environment.CurrentDirectory,
                AppDomain.CurrentDomain.BaseDirectory
            ];

            foreach (string? root in searchRoots)
            {
                if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root)) continue;
                if (root.Contains("CapturedArtifacts", StringComparison.OrdinalIgnoreCase)) continue;

                string direct1 = Path.Combine(root, trimmedRelative);
                if (File.Exists(direct1)) return direct1;

                string direct2 = Path.Combine(root, fileName);
                if (File.Exists(direct2)) return direct2;

                try
                {
                    var opts = new EnumerationOptions
                    {
                        IgnoreInaccessible = true,
                        RecurseSubdirectories = true,
                        MaxRecursionDepth = 3,
                        MatchCasing = MatchCasing.CaseInsensitive
                    };
                    foreach (string match in Directory.EnumerateFiles(root, fileName, opts))
                    {
                        if (!match.Contains("CapturedArtifacts", StringComparison.OrdinalIgnoreCase))
                            return match;
                    }
                }
                catch { }
            }
        }
        catch { }

        return null;
    }

    private static byte[]? TryReadL24FileShared(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (fs.Length <= 0 || fs.Length > 256L * 1024 * 1024) return null;

            byte[] buf = new byte[fs.Length];
            int readTotal = 0;
            while (readTotal < buf.Length)
            {
                int r = fs.Read(buf, readTotal, buf.Length - readTotal);
                if (r <= 0) break;
                readTotal += r;
            }
            return readTotal == buf.Length ? buf : null;
        }
        catch
        {
            return null;
        }
    }

    private readonly MemoryStream _activeUploadStream = new();
    private string _activeTargetPath = string.Empty;
    private string _pendingStatPath = string.Empty;
    private string _activeMode = "33188";
    private long _declaredDataSize = 0;
    private long _totalActualUrbBytes = 0;
    private int _activeDataBlockCount = 0;
    private int _remainingInCurrentDataBlock = 0;
    private byte[]? _firstHeaderSignature = null;
    private Task<byte[]?>? _eagerSnapshotTask = null;
    private bool _hadTruncatedUrb = false;
    private bool _sawExplicitDone = false;
    private bool _doneAlreadyStripped = false;
    private bool _isInsideTransfer = false;
    private string _pendingHeaderBuffer = string.Empty;
    private DateTime _lastChunkTime = DateTime.MinValue;

    private long _latestKnownKernelDroppedPackets = 0;
    private long _kernelDroppedAtTransferStart = 0;

    private long _transferSequenceCounter = 0;
    private long _activeTransferSequenceId = 0;
    private int _activeUploadSequenceNumber = 1;

    private string _currentSessionDirectory = string.Empty;
    private string _currentSessionFolderName = string.Empty;

    private readonly ConcurrentDictionary<int, string> _candidatePids = new();
    private readonly ConcurrentDictionary<string, int> _uploadCountByTargetPath = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, int> _uploadCountByFileName = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<long, (string LocalSavedPath, string SavedFileName, long SavedSize, int UploadNumber, bool IsComplete)> _savedTransfersById = new();
    private readonly ConcurrentDictionary<string, (string SavedFileName, int UploadNumber, long FileSize, string LocalSavedPath)> _latestInstanceByPath = new(StringComparer.OrdinalIgnoreCase);

    private readonly ConcurrentDictionary<string, (string LocalPath, byte[] FileBytes, DateTime CapturedAtUtc)> _recentCliPushByTarget = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DateTime> _recentCliPushDedupe = new(StringComparer.OrdinalIgnoreCase);

    private readonly Channel<PendingFileArchiveJob> _jobChannel;
    private readonly CancellationTokenSource _cts = new();

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

    public string CurrentSessionDirectory
    {
        get
        {
            lock (_transferLock)
            {
                if (string.IsNullOrWhiteSpace(_currentSessionDirectory))
                {
                    InitializeNewSessionFolderLocked();
                }
                return _currentSessionDirectory;
            }
        }
    }

    public string CurrentSessionFolderName
    {
        get
        {
            lock (_transferLock)
            {
                if (string.IsNullOrWhiteSpace(_currentSessionFolderName))
                {
                    InitializeNewSessionFolderLocked();
                }
                return _currentSessionFolderName;
            }
        }
    }

    public SmartFilePushArchiver()
    {
        lock (_transferLock)
        {
            InitializeNewSessionFolderLocked();
        }

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

    public void UpdateKernelDroppedPacketsCount(ulong totalDropped)
    {
        Interlocked.Exchange(ref _latestKnownKernelDroppedPackets, (long)totalDropped);
    }

    public string StartNewSession()
    {
        lock (_transferLock)
        {
            if (_isInsideTransfer && _activeUploadStream.Length > 0 && !string.IsNullOrWhiteSpace(_activeTargetPath))
            {
                EnqueueCurrentTransferForBackgroundSave("0x01", "SessionRestartFlush");
            }

            _uploadCountByTargetPath.Clear();
            _uploadCountByFileName.Clear();
            _savedTransfersById.Clear();
            _latestInstanceByPath.Clear();
            _recentCliPushByTarget.Clear();
            _recentCliPushDedupe.Clear();
            _l24SavedHashByFileKey.Clear();
            _l24UploadCountByFileName.Clear();
            _activeUploadStream.SetLength(0);
            _isInsideTransfer = false;
            _activeTargetPath = string.Empty;
            _pendingStatPath = string.Empty;
            _declaredDataSize = 0;
            _activeDataBlockCount = 0;
            _remainingInCurrentDataBlock = 0;

            InitializeNewSessionFolderLocked();
            return _currentSessionDirectory;
        }
    }

    private void InitializeNewSessionFolderLocked()
    {
        lock (_sharedSessionLock)
        {
            EnsureSharedSessionFolderInitializedLocked();
            _currentSessionFolderName = _sharedActiveSessionFolderName;
            _currentSessionDirectory = _sharedActiveSessionDirectory;
        }
    }

    public string GetActiveArtifactInstanceLabel(string targetDevicePath)
    {
        if (string.IsNullOrWhiteSpace(targetDevicePath)) return string.Empty;

        if (_latestInstanceByPath.TryGetValue(targetDevicePath.Trim(), out var info))
        {
            return info.UploadNumber > 1
                ? $"{targetDevicePath} [Saved: {info.SavedFileName} | Upload #{info.UploadNumber}]"
                : $"{targetDevicePath} [Saved: {info.SavedFileName}]";
        }

        string fileName = Path.GetFileName(targetDevicePath.Trim());
        if (!string.IsNullOrWhiteSpace(fileName))
        {
            foreach (var kvp in _latestInstanceByPath)
            {
                if (string.Equals(Path.GetFileName(kvp.Key), fileName, StringComparison.OrdinalIgnoreCase))
                {
                    return kvp.Value.UploadNumber > 1
                        ? $"{targetDevicePath} [Saved: {kvp.Value.SavedFileName} | Upload #{kvp.Value.UploadNumber}]"
                        : $"{targetDevicePath} [Saved: {kvp.Value.SavedFileName}]";
                }
            }
        }

        return targetDevicePath;
    }

    public void RegisterCandidateProcess(int pid, string name)
    {
        if (pid > 4 && pid != Environment.ProcessId)
        {
            _candidatePids[pid] = name ?? string.Empty;
        }
    }

    public void Dispose()
    {
        try
        {
            lock (_transferLock)
            {
                if (_isInsideTransfer && _activeUploadStream.Length > 0 && !string.IsNullOrWhiteSpace(_activeTargetPath))
                {
                    EnqueueCurrentTransferForBackgroundSave("0x01", "DisposeFlush");
                }
            }
            _cts.Cancel();
            _jobChannel.Writer.TryComplete();
        }
        catch { }
    }
}
