using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using PhoenixGSM.OmniTrace.Bus;

namespace PhoenixGSM.OmniTrace.Sensors;

/// <summary>
/// LAYER 3E — Temporary File & AT Script Interceptor Sensor
/// Intercepts and detects AT commands and modem payload files created in temporary directories
/// (e.g. %TEMP%\AT*, C:\...\Temp\AT\*, *.tmp, *.at, *.bat, *.seq) by GSM servicing tools (Tool.exe)
/// before or during execution against the USB Modem Interface.
/// Operates in fail-open mode with non-blocking queueing, micro-retry file reading (FileShare.ReadWrite | FileShare.Delete),
/// and automatic process attribution via Windows Restart Manager API and active tool observation.
/// </summary>
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public sealed partial class TempFileAtSensor : IDisposable
{
    public const long MaxFileSizeBytes = 10 * 1024 * 1024; // 10 MB limit for AT scripts and staging files

    private readonly OmniTraceEventBus _bus;
    private readonly List<FileSystemWatcher> _watchers = [];
    private readonly HashSet<string> _watchedDirectories = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, (DateTime Expiration, string Hash)> _dedupCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly Channel<string> _fileQueue;
    private readonly CancellationTokenSource _cts = new();

    private Task? _consumerTask;
    private bool _isRunning;
    private ulong _sequence;

    // Observability metrics
    private long _filesMonitored;
    private long _atFilesCaptured;
    private long _atCommandsExtracted;
    private long _bytesCaptured;
    private long _errorsCount;
    private string? _lastError;

    public bool IsRunning => _isRunning;
    public long FilesMonitored => Interlocked.Read(ref _filesMonitored);
    public long AtFilesCaptured => Interlocked.Read(ref _atFilesCaptured);
    public long AtCommandsExtracted => Interlocked.Read(ref _atCommandsExtracted);
    public long BytesCaptured => Interlocked.Read(ref _bytesCaptured);
    public long ErrorsCount => Interlocked.Read(ref _errorsCount);
    public string? LastError => _lastError;
    public IReadOnlyCollection<string> WatchedDirectories
    {
        get
        {
            lock (_watchedDirectories) return _watchedDirectories.ToArray();
        }
    }

    public event Action<TempFileAtEvent>? OnTempFileAtCaptured;

    public TempFileAtSensor(OmniTraceEventBus bus, int queueCapacity = 4096)
    {
        _bus = bus ?? throw new ArgumentNullException(nameof(bus));

        var options = new BoundedChannelOptions(queueCapacity)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleWriter = false,
            SingleReader = true
        };
        _fileQueue = Channel.CreateBounded<string>(options);
    }

    public void Start()
    {
        if (_isRunning) return;

        // 1. Register default temp paths
        RegisterDefaultWatchDirectories();

        // 2. Start background consumer worker
        _consumerTask = Task.Run(ProcessFileQueueAsync);

        _isRunning = true;
    }

    public void Stop()
    {
        if (!_isRunning) return;
        _isRunning = false;

        _cts.Cancel();

        lock (_watchers)
        {
            foreach (var w in _watchers)
            {
                try
                {
                    w.EnableRaisingEvents = false;
                    w.Dispose();
                }
                catch { }
            }
            _watchers.Clear();
        }

        try
        {
            _consumerTask?.Wait(1000);
        }
        catch { }
    }

    public void AddWatchDirectory(string directoryPath, bool includeSubdirectories = true)
    {
        if (string.IsNullOrWhiteSpace(directoryPath)) return;
        try
        {
            string fullPath = Path.GetFullPath(directoryPath).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            if (!Directory.Exists(fullPath)) return;

            lock (_watchedDirectories)
            {
                if (_watchedDirectories.Contains(fullPath)) return;

                _watchedDirectories.Add(fullPath);
                AttachWatcher(fullPath, includeSubdirectories);
            }
        }
        catch { }
    }

    private void RegisterDefaultWatchDirectories()
    {
        // 1. %TEMP%
        try
        {
            string temp = Path.GetTempPath();
            if (Directory.Exists(temp))
            {
                AddWatchDirectory(temp);

                string atDir = Path.Combine(temp, "AT");
                if (!Directory.Exists(atDir))
                {
                    try { Directory.CreateDirectory(atDir); } catch { }
                }
            }
        }
        catch { }

        // 2. C:\Temp or %SystemDrive%\Temp (frequently used by GSM tools e.g. C:\Temp\AT)
        try
        {
            string sysRoot = Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\";
            string rootTemp = Path.Combine(sysRoot, "Temp");
            try
            {
                if (!Directory.Exists(rootTemp))
                {
                    Directory.CreateDirectory(rootTemp);
                }
            }
            catch { }

            if (Directory.Exists(rootTemp))
            {
                AddWatchDirectory(rootTemp);

                string rootAt = Path.Combine(rootTemp, "AT");
                if (!Directory.Exists(rootAt))
                {
                    try { Directory.CreateDirectory(rootAt); } catch { }
                }
            }
        }
        catch { }

        // 3. %LOCALAPPDATA%\Temp (if distinct)
        try
        {
            string localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (!string.IsNullOrEmpty(localApp))
            {
                string localTemp = Path.Combine(localApp, "Temp");
                if (Directory.Exists(localTemp))
                {
                    AddWatchDirectory(localTemp);
                }
            }
        }
        catch { }

        // 4. %WINDIR%\Temp (System-wide temporary folder used by services and drivers)
        try
        {
            string winTemp = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp");
            if (Directory.Exists(winTemp))
            {
                AddWatchDirectory(winTemp);
            }
        }
        catch { }

        // 5. %ProgramData%\Temp
        try
        {
            string progData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            if (!string.IsNullOrEmpty(progData))
            {
                string pdTemp = Path.Combine(progData, "Temp");
                if (Directory.Exists(pdTemp))
                {
                    AddWatchDirectory(pdTemp);
                }
            }
        }
        catch { }

        // 6. User Desktop staging directories (mac\tmp, mac\5, mac, tools) frequently used by GSM exploitation tools
        try
        {
            string desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            if (!string.IsNullOrEmpty(desktop))
            {
                string macTmp = Path.Combine(desktop, "mac", "tmp");
                if (Directory.Exists(macTmp)) AddWatchDirectory(macTmp, includeSubdirectories: true);

                string mac5 = Path.Combine(desktop, "mac", "5");
                if (Directory.Exists(mac5)) AddWatchDirectory(mac5, includeSubdirectories: true);

                string macDir = Path.Combine(desktop, "mac");
                if (Directory.Exists(macDir)) AddWatchDirectory(macDir, includeSubdirectories: false);

                string toolsDir = Path.Combine(desktop, "tools");
                if (Directory.Exists(toolsDir)) AddWatchDirectory(toolsDir, includeSubdirectories: true);
            }

            if (Directory.Exists(@"C:\Users\pc5\Desktop\mac\tmp")) AddWatchDirectory(@"C:\Users\pc5\Desktop\mac\tmp", includeSubdirectories: true);
            if (Directory.Exists(@"C:\Users\pc5\Desktop\mac\5")) AddWatchDirectory(@"C:\Users\pc5\Desktop\mac\5", includeSubdirectories: true);
            if (Directory.Exists(@"C:\Users\pc5\Desktop\mac")) AddWatchDirectory(@"C:\Users\pc5\Desktop\mac", includeSubdirectories: false);
            if (Directory.Exists(@"C:\Users\pc5\Desktop\tools")) AddWatchDirectory(@"C:\Users\pc5\Desktop\tools", includeSubdirectories: true);
        }
        catch { }
    }

    private void ScanExistingStagedFiles()
    {
        Task.Run(() =>
        {
            string[] dirs;
            lock (_watchedDirectories) dirs = _watchedDirectories.ToArray();
            foreach (var dir in dirs)
            {
                try
                {
                    if (!Directory.Exists(dir)) continue;

                    bool isMacRoot = dir.EndsWith(@"\mac", StringComparison.OrdinalIgnoreCase) || dir.EndsWith("/mac", StringComparison.OrdinalIgnoreCase);

                    IEnumerable<string> files;
                    try
                    {
                        files = Directory.EnumerateFiles(dir, "*", new EnumerationOptions
                        {
                            RecurseSubdirectories = !isMacRoot,
                            IgnoreInaccessible = true,
                            ReturnSpecialDirectories = false
                        });
                    }
                    catch
                    {
                        files = Directory.GetFiles(dir, "*", isMacRoot ? SearchOption.TopDirectoryOnly : SearchOption.AllDirectories);
                    }

                    foreach (var file in files)
                    {
                        try
                        {
                            // Skip huge VMware / Big Sur virtual machine directories
                            if (file.Contains(@"\mac\3\") || file.Contains("/mac/3/") || file.EndsWith(".vmdk", StringComparison.OrdinalIgnoreCase) || file.EndsWith(".iso", StringComparison.OrdinalIgnoreCase))
                                continue;

                            if (IsCandidatePath(file))
                            {
                                _fileQueue.Writer.TryWrite(file);
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }
        });
    }

    private void AttachWatcher(string directoryPath, bool includeSubdirectories = true)
    {
        try
        {
            if (!Directory.Exists(directoryPath)) return;

            var watcher = new FileSystemWatcher(directoryPath)
            {
                IncludeSubdirectories = includeSubdirectories,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName | NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime,
                InternalBufferSize = 65536
            };

            watcher.Created += OnFileSystemEvent;
            watcher.Changed += OnFileSystemEvent;
            watcher.Renamed += OnFileSystemRenamed;
            watcher.Error += (s, e) =>
            {
                Interlocked.Increment(ref _errorsCount);
                _lastError = e.GetException().Message;
            };

            watcher.EnableRaisingEvents = true;

            lock (_watchers)
            {
                _watchers.Add(watcher);
            }
        }
        catch (Exception ex)
        {
            Interlocked.Increment(ref _errorsCount);
            _lastError = ex.Message;
            // Fail-open: proceed even if a restricted path cannot be watched
        }
    }

    private void OnFileSystemEvent(object sender, FileSystemEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(e.FullPath)) return;

        // Skip directories themselves from queue
        try
        {
            if (Directory.Exists(e.FullPath)) return;
        }
        catch { }

        _fileQueue.Writer.TryWrite(e.FullPath);
    }

    private void OnFileSystemRenamed(object sender, RenamedEventArgs e)
    {
        if (!string.IsNullOrWhiteSpace(e.FullPath))
        {
            _fileQueue.Writer.TryWrite(e.FullPath);
        }
    }

    private async Task ProcessFileQueueAsync()
    {
        var reader = _fileQueue.Reader;
        var token = _cts.Token;

        try
        {
            while (await reader.WaitToReadAsync(token).ConfigureAwait(false))
            {
                while (reader.TryRead(out var filePath))
                {
                    try
                    {
                        ProcessFileCandidate(filePath);
                    }
                    catch (Exception ex)
                    {
                        Interlocked.Increment(ref _errorsCount);
                        _lastError = ex.Message;
                    }
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            Interlocked.Increment(ref _errorsCount);
            _lastError = ex.Message;
        }
    }

    private void ProcessFileCandidate(string filePath)
    {
        Interlocked.Increment(ref _filesMonitored);

        // 1. Initial quick path/name filter check
        if (!IsCandidatePath(filePath)) return;

        // 2. Read file bytes with micro-retry loop (handles tool locking and fast deletion)
        byte[]? fileBytes = ReadFileWithRetry(filePath, maxRetries: 8, delayMs: 15);
        if (fileBytes == null || fileBytes.Length == 0) return;

        ProcessFileBytesDirect(filePath, fileBytes);
    }

    public void Dispose()
    {
        Stop();
        _cts.Dispose();
    }
}
