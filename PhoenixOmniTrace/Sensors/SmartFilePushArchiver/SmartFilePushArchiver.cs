using System;
using System.Collections.Concurrent;
using System.IO;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace PhoenixGSM.OmniTrace.Sensors;

/// <summary>
/// LAYER 12C — High-Integrity Passive Parallel Smart File Push Archiver.
/// - Works both WITH the USB Kernel Filter enabled AND WITHOUT the USB Filter (via ETW/WMI/CLI process interception + PEB CWD resolution).
/// - Resolves exact local source files from CMD / PowerShell / ADB working directories (via Win32 PEB CurrentDirectory).
/// - Creates a dedicated per-session folder under CapturedArtifacts/ every time the monitor starts.
/// - Automatically numbers repeated uploads of the same target path (AT, AT_2, AT_3 or ADP.xml, ADP_2.xml).
/// </summary>
public sealed partial class SmartFilePushArchiver : IDisposable
{
    private readonly object _transferLock = new();
    private static readonly object _diskWriteLock = new();

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

    // Maps remote TargetDevicePath (or FileName) -> recently resolved local file bytes from CLI `adb push <local> <remote>`
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

        _currentSessionFolderName = timestampName;
        _currentSessionDirectory = candidateDir;
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
