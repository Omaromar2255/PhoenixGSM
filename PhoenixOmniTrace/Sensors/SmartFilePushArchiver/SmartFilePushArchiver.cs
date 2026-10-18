using System;
using System.Collections.Concurrent;
using System.IO;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace PhoenixGSM.OmniTrace.Sensors;

/// <summary>
/// LAYER 12C — 100% Passive High-Speed Parallel Smart File Push Archiver.
/// - ZERO USB interruption: Never spawns adb.exe, never runs "adb pull" or "adb shell ln -f",
///   and never competes with direct WinUSB tools (such as KEY-Tool.exe) for the USB handle.
/// - Captures files of ALL sizes from 1 byte (e.g. 72-byte ASKSW.xml, trustedTime) up to 64 MB (15MB R2.zip, 480KB AT).
/// - Handles multi-file coalesced USB buffers where a small file (like ASKSW.xml) starts at offset > 160
///   immediately after the previous file's DONE token in the same USB Bulk transfer.
/// - Strictly saves ONLY ONE file per pushed item with its exact original name and full size.
/// </summary>
public sealed partial class SmartFilePushArchiver : IDisposable
{
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
