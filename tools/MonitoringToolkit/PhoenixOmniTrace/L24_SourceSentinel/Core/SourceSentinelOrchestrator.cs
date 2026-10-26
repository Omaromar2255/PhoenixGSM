using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using PhoenixGSM.OmniTrace.Bus;
using PhoenixGSM.OmniTrace.Commands;
using PhoenixGSM.OmniTrace.Sensors;
using PhoenixGSM.OmniTrace.ToolSourceInterception;
using PhoenixOmniTrace.L24_SourceSentinel.Models;

namespace PhoenixOmniTrace.L24_SourceSentinel.Core;

public sealed class SourceSentinelOrchestrator : IDisposable
{
    private static readonly string[] KnownGsmToolNames =
    [
        "unlocktool", "chimera", "miracle", "dftpro", "pandora", "z3x", "octoplus",
        "samfw", "odin", "3utools", "miflash", "qfil", "spflash", "flashtool", "umt",
        "hydra", "easyjtag", "cheetah", "tft", "sigmakey", "dc-unlocker", "cm2",
        "medusa", "ufi", "mrt", "trtools", "qcfire", "globalunlocker", "nck",
        "key-tool", "keytool", "qunlock", "q-unlock", "cdma"
    ];

    private readonly SourceIpcServer _ipcServer = new();
    private readonly RamAndModuleWatcher _ramWatcher = new();
    private readonly PortAndFileRadar _radar = new();
    private readonly OriginAttributionEngine _attributionEngine = new();
    private readonly LiveHeapCommandHunter _heapHunter = new();
    private readonly DllFunctionTableAuditor _dllAuditor = new();
    private readonly ActiveComAndUsbPortPoller _portPoller = new();
    private readonly KernelAndUsbEtwInterceptor _kernelInterceptor = new();
    private readonly ToolExecutionMultiInterceptor _multiExecInterceptor = new();
    private readonly WinUsbFilterAdbBridge _adbBridge;

    // الحساسات المدمجة لضمان التقاط الروابط وأوامر MTK المنفذة والعمليات حتى عند فتح L24 بشكل مستقل!
    private readonly OmniTraceEventBus _internalBus = new();
    private readonly NetworkUrlSensor _networkUrlSensor;
    private readonly ClipboardUrlSensor _clipboardUrlSensor;
    private readonly TempFileAtSensor _tempFileSensor;
    private readonly GsmToolUiActionSensor _uiActionSensor;
    private readonly GsmToolSessionStreamSensor _sessionStreamSensor;
    private readonly FilterDriverCommandCorrelatorSensor _filterCorrelatorSensor;
    private readonly DevicePnpArrivalCommandSensor _pnpArrivalSensor;
    private readonly UniversalToolCommandInterceptor _universalInterceptor;
    private readonly ToolSourceInterceptionOrchestrator _toolSourceOrchestrator;

    // 1. القوائم المنظمة (بعد الفلترة ومنع التكرار)
    private readonly ConcurrentQueue<SourceTelemetryEvent> _sessionEvents = new();
    private readonly BlockingCollection<SourceTelemetryEvent> _diskLogQueue = new(new ConcurrentQueue<SourceTelemetryEvent>());

    // 2. السجل الشامل الخام بدون فلترة (Unfiltered Raw Everything Stream — يسجل كل شيء في تبويب وملف منفصلين!)
    private readonly ConcurrentQueue<SourceTelemetryEvent> _unfilteredRawEvents = new();
    private readonly BlockingCollection<SourceTelemetryEvent> _unfilteredRawDiskQueue = new(new ConcurrentQueue<SourceTelemetryEvent>());
    private readonly ConcurrentDictionary<string, DateTime> _rawStreamMicroDebounce = new(StringComparer.OrdinalIgnoreCase);
    private volatile bool _isUnfilteredRawLoggingEnabled = true;

    public bool IsUnfilteredRawLoggingEnabled
    {
        get => _isUnfilteredRawLoggingEnabled;
        set
        {
            if (_isUnfilteredRawLoggingEnabled != value)
            {
                _isUnfilteredRawLoggingEnabled = value;
                OnLogMessage?.Invoke(value
                    ? "[L24 SourceSentinel] تم تفعيل وتسجيل السجل الخام الشامل آنياً (Raw Stream: ON)"
                    : "[L24 SourceSentinel] تم إيقاف تسجيل السجل الخام الشامل آنياً (Raw Stream: PAUSED)");
            }
        }
    }

    public bool IsRamHunterEnabled
    {
        get => _heapHunter.IsRamHunterEnabled;
        set
        {
            if (_heapHunter.IsRamHunterEnabled != value)
            {
                _heapHunter.IsRamHunterEnabled = value;
                OnLogMessage?.Invoke(value
                    ? "[L24 SourceSentinel] تم تشغيل فاحص الذاكرة اللحظي (RAM Hunter: ON)"
                    : "[L24 SourceSentinel] تم إيقاف فاحص الذاكرة مؤقتاً لتوفير الأداء والتركيز على الأوامر المنفذة 100% (RAM Hunter: PAUSED)");
            }
        }
    }

    public bool SuppressIdleStaticBaseline
    {
        get => _heapHunter.SuppressIdleStaticBaseline;
        set
        {
            if (_heapHunter.SuppressIdleStaticBaseline != value)
            {
                _heapHunter.SuppressIdleStaticBaseline = value;
                OnLogMessage?.Invoke(value
                    ? "[L24 SourceSentinel] تم تفعيل عزل أوامر وضع الخمول (Idle Baseline Filter: ON — يعرض فقط الأوامر الجديدة والنشطة)"
                    : "[L24 SourceSentinel] تم إيقاف عزل الخمول (Idle Baseline Filter: OFF — يعرض كافة نصوص الرام شاملة الثابتة)");
            }
        }
    }

    public bool ScanDynamicHeapOnly
    {
        get => _heapHunter.ScanDynamicHeapOnly;
        set
        {
            if (_heapHunter.ScanDynamicHeapOnly != value)
            {
                _heapHunter.ScanDynamicHeapOnly = value;
                OnLogMessage?.Invoke(value
                    ? "[L24 SourceSentinel] تم تفعيل وضع فحص الـ Heap الديناميكي السريع فقط (Dynamic RW Heap Only)"
                    : "[L24 SourceSentinel] تم تفعيل وضع فحص صفحات الذاكرة الشامل (Full Memory Regions)");
            }
        }
    }

    public void CaptureIdleBaselineSnapshot()
    {
        _heapHunter.CaptureCurrentRamAsIdleBaseline();
        OnLogMessage?.Invoke("[L24 SourceSentinel] تم التقاط بصمة وضع الخمول (Idle Snapshot) بنجاح — سيتم إخفاء النصوص الساكنة الحالية وإظهار الأوامر الجديدة فوراً.");
    }

    public void ResetIdleBaselineSnapshot()
    {
        _heapHunter.ClearIdleBaseline();
        OnLogMessage?.Invoke("[L24 SourceSentinel] تم تصفير بصمة الخمول وإعادة فحص كامل الذاكرة.");
    }

    private readonly ConcurrentDictionary<int, string> _autoAttachedPids = new();
    private CancellationTokenSource? _activeCts;
    private Task? _diskLoggerTask;
    private Task? _unfilteredDiskLoggerTask;
    private Task? _autoDiscoveryTask;
    private volatile bool _isActive;
    private bool _isDisposed;

    private readonly string _logDirectory;
    private readonly string _sessionLogPath;
    private readonly string _sessionJsonlPath;
    private readonly string _unfilteredRawTxtPath;
    private readonly string _unfilteredRawJsonlPath;

    public event Action<SourceTelemetryEvent>? OnTelemetryEventCaptured;
    public event Action<SourceTelemetryEvent>? OnUnfilteredRawEventCaptured;
    public event Action<string>? OnLogMessage;

    public bool IsActive => _isActive;
    public string LogDirectory => _logDirectory;
    public string SessionLogPath => _sessionLogPath;
    public string UnfilteredRawTxtPath => _unfilteredRawTxtPath;
    public string UnfilteredRawJsonlPath => _unfilteredRawJsonlPath;
    public string CapturedFilesDirectory => L24FileArchiver.CurrentCapturedFilesDirectory;

    public OriginAttributionEngine Attribution => _attributionEngine;
    public KernelAndUsbEtwInterceptor KernelInterceptor => _kernelInterceptor;
    public ToolExecutionMultiInterceptor MultiExecInterceptor => _multiExecInterceptor;
    public WinUsbFilterAdbBridge AdbBridge => _adbBridge;
    public LiveHeapCommandHunter HeapHunter => _heapHunter;

    public L24DiscoveryMode DiscoveryMode
    {
        get => _heapHunter.DiscoveryMode;
        set
        {
            _heapHunter.DiscoveryMode = value;
            OnLogMessage?.Invoke($"[L24 SourceSentinel] تم تغيير وضع اكتشاف أوامر الذاكرة إلى: {value}");
        }
    }

    public bool ShowPhoneResponses
    {
        get => ForensicNoiseGate.ShowPhoneResponses;
        set
        {
            ForensicNoiseGate.ShowPhoneResponses = value;
            OnLogMessage?.Invoke(value
                ? "[L24 SourceSentinel] تم تفعيل إظهار ردود الهاتف."
                : "[L24 SourceSentinel] تم إيقاف إظهار ردود الهاتف.");
        }
    }

    private readonly ConcurrentDictionary<L24CommandGroup, bool> _enabledCategories = new();
    private volatile bool _excludeUrlsFromDiscovered = false;
    private volatile bool _excludeUrlsFromRawLog = true;

    public bool ExcludeUrlsFromRawLog
    {
        get => _excludeUrlsFromRawLog;
        set
        {
            if (_excludeUrlsFromRawLog != value)
            {
                _excludeUrlsFromRawLog = value;
                OnLogMessage?.Invoke(value
                    ? "[L24 SourceSentinel] تم تفعيل استثناء الروابط من السجل الخام."
                    : "[L24 SourceSentinel] تم إيقاف استثناء الروابط من السجل الخام (تسجيل كافة الروابط).");
            }
        }
    }

    public bool ExcludeUrlsFromDiscovered
    {
        get => _excludeUrlsFromDiscovered;
        set
        {
            if (_excludeUrlsFromDiscovered != value)
            {
                _excludeUrlsFromDiscovered = value;
                _heapHunter.ExcludeUrls = value;
                OnLogMessage?.Invoke(value
                    ? "[L24 SourceSentinel] تم تفعيل استثناء الروابط من الأوامر المكتشفة بالذاكرة."
                    : "[L24 SourceSentinel] تم إيقاف استثناء الروابط من الأوامر المكتشفة.");
            }
        }
    }

    public bool IsCategoryDetectionEnabled(L24CommandGroup group)
    {
        return _enabledCategories.TryGetValue(group, out bool enabled) ? enabled : true;
    }

    public void SetCategoryDetectionEnabled(L24CommandGroup group, bool enabled)
    {
        _enabledCategories[group] = enabled;
        OnLogMessage?.Invoke($"[L24 SourceSentinel] فئة [{L24CommandClassifier.GetGroupArabicTitle(group)}]: {(enabled ? "مفعلة ▶️" : "معطلة ⏸️ (تم إيقاف رصدها)")}");
    }

    public SourceSentinelOrchestrator(string? customLogDir = null)
    {
        _adbBridge = new WinUsbFilterAdbBridge(HandleIncomingEvent);
        string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");

        _logDirectory = !string.IsNullOrWhiteSpace(customLogDir)
            ? customLogDir
            : ResolveDefaultLogDirectory();

        Directory.CreateDirectory(_logDirectory);
        L24FileArchiver.InitializeSessionDirectory(_logDirectory);

        _sessionLogPath = Path.Combine(_logDirectory, $"session_{timestamp}.json");
        _sessionJsonlPath = Path.Combine(_logDirectory, $"session_{timestamp}.jsonl");
        _unfilteredRawTxtPath = Path.Combine(_logDirectory, $"unfiltered_raw_session_{timestamp}.txt");
        _unfilteredRawJsonlPath = Path.Combine(_logDirectory, $"unfiltered_raw_session_{timestamp}.jsonl");

        // تهيئة الحساسات الداخلية للطبقة L24 (الروابط + أوامر MTK + واجهة الأدوات + الجلسات الحية + العمليات)
        _networkUrlSensor = new NetworkUrlSensor(_internalBus, $"PhoenixL24_Net_{Process.GetCurrentProcess().Id}");
        _clipboardUrlSensor = new ClipboardUrlSensor(_internalBus);
        _tempFileSensor = new TempFileAtSensor(_internalBus);
        _uiActionSensor = new GsmToolUiActionSensor(_internalBus);
        _sessionStreamSensor = new GsmToolSessionStreamSensor(_internalBus);
        _filterCorrelatorSensor = new FilterDriverCommandCorrelatorSensor(_internalBus, _uiActionSensor);
        _pnpArrivalSensor = new DevicePnpArrivalCommandSensor(_internalBus, _uiActionSensor);
        _universalInterceptor = new UniversalToolCommandInterceptor(_internalBus);
        _toolSourceOrchestrator = new ToolSourceInterceptionOrchestrator(_internalBus);

        _adbBridge.Attach(_internalBus);

        // ربط أحداث المكونات المختلفة
        _ipcServer.OnEventCaptured += HandleIncomingEvent;
        _ramWatcher.OnModuleOrRamActivity += HandleIncomingEvent;
        _radar.OnRadarActivity += HandleIncomingEvent;
        _heapHunter.OnCommandCaptured += HandleIncomingEvent;
        _dllAuditor.OnDllCapabilitiesExtracted += HandleIncomingEvent;
        _portPoller.OnPortActivityDetected += HandleIncomingEvent;
        _kernelInterceptor.OnKernelActivityDetected += HandleIncomingEvent;
        _multiExecInterceptor.OnToolCommandIntercepted += HandleIncomingEvent;

        _multiExecInterceptor.OnChildProcessRegistered += (childPid, procName) =>
        {
            _heapHunter.RegisterChildAdbProcess(childPid, procName);
        };

        _kernelInterceptor.OnChildAdbOrWinUsbDetected += (childPid, procName) =>
        {
            _heapHunter.IsWinUsbOrChildAdbActive = true;
            if (string.Equals(procName, "adb.exe", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(procName, "fastboot.exe", StringComparison.OrdinalIgnoreCase))
            {
                _heapHunter.RegisterChildAdbProcess(childPid, procName);
            }
            OnLogMessage?.Invoke($"[L24 SourceSentinel] تفعيل المسح المزدوج المتوافق مع WinUSB/ADB/MTK (الهدف: {procName}, PID: {childPid})");
        };

        _ramWatcher.OnExternalModuleDiscovered += (pid, procName, dllPath) =>
        {
            string fileName = Path.GetFileName(dllPath);
            if (fileName.Contains("winusb", StringComparison.OrdinalIgnoreCase) ||
                fileName.Contains("adbwinusb", StringComparison.OrdinalIgnoreCase) ||
                fileName.Contains("libusb", StringComparison.OrdinalIgnoreCase))
            {
                _heapHunter.IsWinUsbOrChildAdbActive = true;
            }

            _dllAuditor.AuditLoadedModule(pid, procName, dllPath);
        };

        _heapHunter.IsCategoryEnabled = IsCategoryDetectionEnabled;
        _heapHunter.ExcludeUrls = _excludeUrlsFromDiscovered;
    }

    private static string ResolveDefaultLogDirectory()
    {
        string localProjLogs = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Logs", "L24_SourceSentinel");
        if (Directory.Exists(Path.GetDirectoryName(localProjLogs)))
            return localProjLogs;

        return Path.Combine(Directory.GetCurrentDirectory(), "Logs", "L24_SourceSentinel");
    }

    public void Start()
    {
        if (_isActive || _isDisposed) return;
        _isActive = true;

        try { _activeCts?.Cancel(); _activeCts?.Dispose(); } catch { }
        _activeCts = new CancellationTokenSource();
        var token = _activeCts.Token;

        ForensicNoiseGate.ResetSessionDeduplication();
        _ipcServer.Start();
        _radar.StartMonitoring();
        _portPoller.StartPolling(0, "SystemWidePortMonitor");
        _multiExecInterceptor.Start();

        // تشغيل حساسات الروابط وأوامر MTK والعمليات الحية تلقائياً
        try { _networkUrlSensor.Start(); } catch { }
        try { _clipboardUrlSensor.Start(); } catch { }
        try { _tempFileSensor.Start(); } catch { }
        try { _uiActionSensor.Start(); } catch { }
        try { _sessionStreamSensor.Start(); } catch { }
        try { _filterCorrelatorSensor.Start(); } catch { }
        try { _pnpArrivalSensor.Start(); } catch { }
        try { _universalInterceptor.Start(); } catch { }
        try { _toolSourceOrchestrator.Start(); } catch { }

        _diskLoggerTask = Task.Run(() => DiskLoggerLoop(token), token);
        _unfilteredDiskLoggerTask = Task.Run(() => UnfilteredRawDiskLoggerLoop(token), token);
        _autoDiscoveryTask = Task.Run(() => AutoDiscoverGsmToolsLoop(token), token);

        OnLogMessage?.Invoke("[L24 SourceSentinel] تم تفعيل وتشغيل الطبقة 24 بنجاح (الاعتراض المتعدد للأوامر + فحص الرام الذكي + صائد ملفات البوت نشطة الآن)");
    }

    public void Stop()
    {
        if (!_isActive || _isDisposed) return;
        _isActive = false;

        try
        {
            _activeCts?.Cancel();
            _activeCts?.Dispose();
        }
        catch { }
        _activeCts = null;

        try { _networkUrlSensor.Stop(); } catch { }
        try { _clipboardUrlSensor.Stop(); } catch { }
        try { _tempFileSensor.Stop(); } catch { }
        try { _uiActionSensor.Stop(); } catch { }
        try { _sessionStreamSensor.Stop(); } catch { }
        try { _filterCorrelatorSensor.Stop(); } catch { }
        try { _pnpArrivalSensor.Stop(); } catch { }
        try { _universalInterceptor.Stop(); } catch { }
        try { _toolSourceOrchestrator.Stop(); } catch { }

        try { _multiExecInterceptor.Stop(); } catch { }
        try { _ipcServer.Stop(); } catch { }
        try { _radar.StopMonitoring(); } catch { }
        try { _portPoller.Stop(); } catch { }
        try { _heapHunter.StopHunting(); } catch { }
        try { _kernelInterceptor.StopMonitoring(); } catch { }
        try { _ramWatcher.Reset(); } catch { }

        _autoAttachedPids.Clear();

        OnLogMessage?.Invoke("[L24 SourceSentinel] تم إيقاف وتعطيل الطبقة 24 بالكامل (توقف استهلاك موارد المعالج والذاكرة بالخلفية 100%)");
    }

    private async Task AutoDiscoverGsmToolsLoop(CancellationToken token)
    {
        while (!token.IsCancellationRequested && !_isDisposed && _isActive)
        {
            try
            {
                var procs = Process.GetProcesses();
                foreach (var p in procs)
                {
                    if (token.IsCancellationRequested || !_isActive) break;
                    try
                    {
                        string nameLower = p.ProcessName.ToLowerInvariant();
                        if (KnownGsmToolNames.Any(k => nameLower.Contains(k)) && !_autoAttachedPids.ContainsKey(p.Id))
                        {
                            _autoAttachedPids[p.Id] = p.ProcessName;
                            AttachToRunningProcess(p.Id);
                        }
                    }
                    catch { }
                    finally
                    {
                        p.Dispose();
                    }
                }
            }
            catch { }

            try
            {
                await Task.Delay(1500, token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { break; }
        }
    }

    private void HandleIncomingEvent(SourceTelemetryEvent evt)
    {
        if (!_isActive || _isDisposed || evt == null) return;

        // ══════════════════════════════════════════════════════════════════════
        // المسار الأول: السجل الشامل الخام بدون فلترة (Unfiltered Raw Stream)
        // ══════════════════════════════════════════════════════════════════════
        RecordUnfilteredRawEvent(evt);

        // إيقاف الفئات غير المفعلة من الرصد بالذاكرة أو استثناء الروابط
        if (evt.Scope == L24CommandScope.DiscoveredInRam)
        {
            if (!IsCategoryDetectionEnabled(evt.CommandGroup))
                return;

            if (_excludeUrlsFromDiscovered && (evt.CommandGroup == L24CommandGroup.ServerCloudLogin || L24CommandClassifier.IsUrlOrNetworkOrAuth(evt)))
                return;
        }

        // ══════════════════════════════════════════════════════════════════════
        // المسار الثاني: بوابة التصفية والتنظيم للتبويبات الـ 4 المعزولة
        // ══════════════════════════════════════════════════════════════════════
        if (!ForensicNoiseGate.TryFilterAndNormalizeEvent(evt)) return;

        _attributionEngine.TrackEvent(evt);
        _sessionEvents.Enqueue(evt);
        _diskLogQueue.TryAdd(evt);
        OnTelemetryEventCaptured?.Invoke(evt);
    }

    private void RecordUnfilteredRawEvent(SourceTelemetryEvent evt)
    {
        if (!_isActive || !_isUnfilteredRawLoggingEnabled || _isDisposed || evt == null) return;
        try
        {
            if (_excludeUrlsFromRawLog && (evt.CommandGroup == L24CommandGroup.ServerCloudLogin || L24CommandClassifier.IsUrlOrNetworkOrAuth(evt)))
                return;
            string rawKey = $"{evt.HookedApiName}|{evt.CommandCategory}|{evt.TargetResource}|{evt.DecodedCommandText}";
            DateTime now = DateTime.UtcNow;

            if (_rawStreamMicroDebounce.TryGetValue(rawKey, out var lastSeen) && (now - lastSeen).TotalSeconds < 1.5)
                return;
            _rawStreamMicroDebounce[rawKey] = now;

            var rawCopy = new SourceTelemetryEvent
            {
                EventId = Guid.NewGuid(),
                Timestamp = evt.Timestamp,
                ProcessId = evt.ProcessId,
                ThreadId = evt.ThreadId,
                Stage = evt.Stage,
                MemoryAddress = evt.MemoryAddress,
                HookedApiName = evt.HookedApiName,
                CallerModuleOrigin = evt.CallerModuleOrigin,
                TargetResource = evt.TargetResource,
                CommandCategory = evt.CommandCategory,
                DecodedCommandText = evt.DecodedCommandText,
                PureCommandText = evt.PureCommandText,
                SavedFilePath = evt.SavedFilePath,
                RawPayloadHex = evt.RawPayloadHex,
                PayloadSize = evt.PayloadSize
            };

            _unfilteredRawEvents.Enqueue(rawCopy);
            _unfilteredRawDiskQueue.TryAdd(rawCopy);
            OnUnfilteredRawEventCaptured?.Invoke(rawCopy);
        }
        catch { }
    }

    public bool LaunchAndInterceptTool(string executablePath, string arguments = "", string? workingDir = null)
    {
        if (!File.Exists(executablePath))
        {
            OnLogMessage?.Invoke($"[خطأ] مسار الأداة غير موجود: {executablePath}");
            return false;
        }

        try
        {
            if (!_isActive) Start();

            string toolDir = !string.IsNullOrWhiteSpace(workingDir) ? workingDir : Path.GetDirectoryName(executablePath) ?? "";
            if (!string.IsNullOrWhiteSpace(toolDir))
            {
                L24FileArchiver.RegisterToolDirectory(toolDir);
                _radar.AddDirectoryWatcher(toolDir);
                _multiExecInterceptor.AddToolStagingWatcher(toolDir);
            }

            var startInfo = new ProcessStartInfo
            {
                FileName = executablePath,
                Arguments = arguments,
                WorkingDirectory = toolDir,
                UseShellExecute = true
            };

            ToolExecutionMultiInterceptor.PrepareToolLaunchEnvironment(startInfo, toolDir, _logDirectory);

            var proc = Process.Start(startInfo);
            if (proc != null)
            {
                _autoAttachedPids[proc.Id] = proc.ProcessName;
                _universalInterceptor.RegisterToolPid(proc.Id);
                _multiExecInterceptor.RegisterToolProcess(proc.Id, proc.ProcessName);
                OnLogMessage?.Invoke($"[L24 SourceSentinel] تم تشغيل الأداة بنجاح (PID: {proc.Id}) - جاري تفعيل المراقبة الشاملة من المصدر");

                _radar.CurrentMonitoredPid = proc.Id;
                _radar.CurrentMonitoredProcessName = proc.ProcessName;

                _heapHunter.StartHunting(proc.Id, proc.ProcessName);
                _portPoller.StartPolling(proc.Id, proc.ProcessName);
                _kernelInterceptor.StartMonitoring(proc.Id, proc.ProcessName);
                _ramWatcher.ScanProcessModulesAndMemory(proc.Id, _logDirectory);

                var token = _activeCts?.Token ?? CancellationToken.None;
                Task.Run(async () =>
                {
                    while (!proc.HasExited && !token.IsCancellationRequested && !_isDisposed && _isActive)
                    {
                        await Task.Delay(1500, token).ConfigureAwait(false);
                        _ramWatcher.ScanProcessModulesAndMemory(proc.Id, _logDirectory);
                    }
                }, token);

                return true;
            }
        }
        catch (Exception ex)
        {
            OnLogMessage?.Invoke($"[استثناء أثناء تشغيل الأداة]: {ex.Message}");
        }

        return false;
    }

    public bool AttachToRunningProcess(int processId)
    {
        try
        {
            using var proc = Process.GetProcessById(processId);
            if (!_isActive) Start();

            _autoAttachedPids[processId] = proc.ProcessName;
            _universalInterceptor.RegisterToolPid(processId);
            _multiExecInterceptor.RegisterToolProcess(processId, proc.ProcessName);

            try
            {
                string? exePath = proc.MainModule?.FileName;
                string? toolDir = !string.IsNullOrWhiteSpace(exePath) ? Path.GetDirectoryName(exePath) : null;
                if (!string.IsNullOrWhiteSpace(toolDir))
                {
                    L24FileArchiver.RegisterToolDirectory(toolDir);
                    _radar.AddDirectoryWatcher(toolDir);
                    _multiExecInterceptor.AddToolStagingWatcher(toolDir);
                }
            }
            catch { }

            OnLogMessage?.Invoke($"[L24 SourceSentinel] تم الارتباط بالعملية {proc.ProcessName} (PID: {processId}) بنجاح");

            _radar.CurrentMonitoredPid = proc.Id;
            _radar.CurrentMonitoredProcessName = proc.ProcessName;

            _heapHunter.StartHunting(proc.Id, proc.ProcessName);
            _portPoller.StartPolling(proc.Id, proc.ProcessName);
            _kernelInterceptor.StartMonitoring(proc.Id, proc.ProcessName);
            _ramWatcher.ScanProcessModulesAndMemory(processId, _logDirectory);

            var token = _activeCts?.Token ?? CancellationToken.None;
            Task.Run(async () =>
            {
                while (!proc.HasExited && !token.IsCancellationRequested && !_isDisposed && _isActive)
                {
                    await Task.Delay(1500, token).ConfigureAwait(false);
                    _ramWatcher.ScanProcessModulesAndMemory(processId, _logDirectory);
                }
            }, token);

            return true;
        }
        catch (Exception ex)
        {
            OnLogMessage?.Invoke($"[خطأ الارتباط بالعملية {processId}]: {ex.Message}");
            return false;
        }
    }

    private void DiskLoggerLoop(CancellationToken token)
    {
        var options = new JsonSerializerOptions
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            WriteIndented = false
        };

        try
        {
            using var jsonlStream = new FileStream(_sessionJsonlPath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
            using var writer = new StreamWriter(jsonlStream, Encoding.UTF8) { AutoFlush = true };

            while (!token.IsCancellationRequested && !_isDisposed && _isActive)
            {
                try
                {
                    if (_diskLogQueue.TryTake(out var evt, 500, token))
                    {
                        writer.WriteLine(JsonSerializer.Serialize(evt, options));
                    }
                }
                catch (OperationCanceledException) { break; }
                catch { }
            }
        }
        catch { }
    }

    private void UnfilteredRawDiskLoggerLoop(CancellationToken token)
    {
        var options = new JsonSerializerOptions
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            WriteIndented = false
        };

        try
        {
            using var txtStream = new FileStream(_unfilteredRawTxtPath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
            using var txtWriter = new StreamWriter(txtStream, Encoding.UTF8) { AutoFlush = true };

            using var jsonlStream = new FileStream(_unfilteredRawJsonlPath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
            using var jsonlWriter = new StreamWriter(jsonlStream, Encoding.UTF8) { AutoFlush = true };

            txtWriter.WriteLine($"=== السجل الشامل الخام بدون فلترة (L24 Unfiltered Raw Stream) — بدأ في {DateTime.Now:yyyy-MM-dd HH:mm:ss} ===");
            txtWriter.WriteLine(new string('=', 95));

            while (!token.IsCancellationRequested && !_isDisposed && _isActive)
            {
                try
                {
                    if (_unfilteredRawDiskQueue.TryTake(out var evt, 500, token))
                    {
                        jsonlWriter.WriteLine(JsonSerializer.Serialize(evt, options));

                        string savedInfo = !string.IsNullOrWhiteSpace(evt.SavedFilePath) ? $" | SavedFile: {evt.SavedFilePath}" : "";
                        txtWriter.WriteLine($"[{evt.FormattedTimestamp}] [PID:{evt.ProcessId}] [{evt.StageBadge}] [{evt.CommandCategory}] Origin: {evt.CallerModuleOrigin} | Target: {evt.TargetResource}{savedInfo}");
                        txtWriter.WriteLine($"  -> الأمر الصافي : {evt.PureCommandText}");
                        txtWriter.WriteLine($"  -> التفاصيل    : {evt.DecodedCommandText}");
                        txtWriter.WriteLine(new string('-', 80));
                    }
                }
                catch (OperationCanceledException) { break; }
                catch { }
            }
        }
        catch { }
    }

    public IReadOnlyList<SourceTelemetryEvent> GetSessionEvents() => _sessionEvents.ToArray();
    public IReadOnlyList<SourceTelemetryEvent> GetUnfilteredRawEvents() => _unfilteredRawEvents.ToArray();

    public void ClearUnfilteredRawEvents()
    {
        while (_unfilteredRawEvents.TryDequeue(out _)) { }
        while (_unfilteredRawDiskQueue.TryTake(out _)) { }
        _rawStreamMicroDebounce.Clear();
    }

    public void FlushAndExportSessionSnapshot()
    {
        try
        {
            var options = new JsonSerializerOptions
            {
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                WriteIndented = true
            };

            var snapshot = _sessionEvents.ToArray();
            string json = JsonSerializer.Serialize(snapshot, options);
            File.WriteAllText(_sessionLogPath, json, Encoding.UTF8);
            OnLogMessage?.Invoke($"[L24 SourceSentinel] تم حفظ الجلسة المنظمة ({snapshot.Length} حدث) والسجل الخام في: {_logDirectory}");
        }
        catch (Exception ex)
        {
            OnLogMessage?.Invoke($"[خطأ تصدير الجلسة]: {ex.Message}");
        }
    }

    public void AttachToOmniTraceEventBus(OmniTraceEventBus bus)
    {
        _adbBridge.Attach(bus);
        OnLogMessage?.Invoke("[L24 SourceSentinel] تم ربط ناقل OmniTraceEventBus الرئيسي بنجاح لاستقبال كافة أوامر الهاتف المنفذة والملفات والـ USB والـ ADB");
    }

    public void PublishExternalTelemetryEvent(SourceTelemetryEvent evt)
    {
        if (!_isActive || _isDisposed || evt == null) return;
        HandleIncomingEvent(evt);
    }

    public void Dispose()
    {
        if (_isDisposed) return;
        _isDisposed = true;
        Stop();

        try { _networkUrlSensor.Dispose(); } catch { }
        try { _clipboardUrlSensor.Dispose(); } catch { }
        try { _tempFileSensor.Dispose(); } catch { }
        try { _uiActionSensor.Dispose(); } catch { }
        try { _sessionStreamSensor.Dispose(); } catch { }
        try { _filterCorrelatorSensor.Dispose(); } catch { }
        try { _pnpArrivalSensor.Dispose(); } catch { }
        try { _universalInterceptor.Dispose(); } catch { }
        try { _toolSourceOrchestrator.Dispose(); } catch { }

        _multiExecInterceptor.Dispose();
        _adbBridge.Dispose();
        _ipcServer.Dispose();
        _ramWatcher.Dispose();
        _radar.Dispose();
        _heapHunter.Dispose();
        _portPoller.Dispose();
        _kernelInterceptor.Dispose();

        FlushAndExportSessionSnapshot();
    }
}


// ══════════════════════════════════════════════════════════════════════════════
// محرك الاعتراض المتعدد والمستقل لأوامر الأدوات قبل وأثناء التنفيذ (Multi-Vector Tool Command & Session Interceptor)
// مدمج مباشرة داخل SourceSentinelOrchestrator.cs لضمان التوافق الفوري للبناء دون الحاجة لإضافة ملفات خارجية جديدة
// ══════════════════════════════════════════════════════════════════════════════
public sealed class ToolExecutionMultiInterceptor : IDisposable
{
    private readonly ConcurrentDictionary<int, string> _trackedToolPids = new();
    private readonly ConcurrentDictionary<int, string> _seenChildProcessCmds = new();
    private readonly ConcurrentDictionary<string, DateTime> _dedupMap = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<FileSystemWatcher> _stagingWatchers = new();

    private CancellationTokenSource? _cts;
    private Task? _pebTreeTask;
    private Task? _consolePtyTask;
    private Task? _loopbackSocketTask;
    private Task? _namedPipeTask;
    private volatile bool _isRunning;
    private bool _isDisposed;

    public event Action<SourceTelemetryEvent>? OnToolCommandIntercepted;
    public event Action<int, string>? OnChildProcessRegistered;

    public bool IsEnabled { get; set; } = true;

    private static readonly string[] TargetCliBinaries =
    [
        "cmd", "powershell", "pwsh", "conhost", "openconsole",
        "adb", "fastboot", "fh_loader", "qsahara_server", "edl", "spd_dump",
        "irecovery", "ideviceinfo", "ideviceactivation", "idevice_id", "idevicepair",
        "idevicerestore", "idevicebackup2", "ideviceinstaller", "iproxy", "gaster",
        "python", "python3", "7z", "7za", "tar", "unzip", "lz4", "simg2img", "lpunpack",
        "openssl", "curl", "wget", "devcon", "pnputil", "filter-x64", "filter-x86"
    ];

    private static readonly System.Text.RegularExpressions.Regex AdbSocketCommandRegex = new(
        @"^[0-9A-Fa-f]{4}(?:host|shell|exec|abb|abb_exec|sync|usb|reboot|remount|root|unroot|tcpip|forward|reverse|localabstract|localfilesystem|dev|jdwp|track-devices|version|kill)[^\x00]{0,400}",
        System.Text.RegularExpressions.RegexOptions.Compiled | System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    public void RegisterToolProcess(int pid, string processName)
    {
        if (pid <= 0) return;
        _trackedToolPids[pid] = processName;
    }

    public static void PrepareToolLaunchEnvironment(ProcessStartInfo startInfo, string toolDirectory, string captureDirectory)
    {
        if (startInfo == null) return;
        try
        {
            if (!startInfo.UseShellExecute)
            {
                string traceLogDir = Path.Combine(captureDirectory, "ToolEnvLogs");
                Directory.CreateDirectory(traceLogDir);
                startInfo.EnvironmentVariables["ADB_TRACE"] = "all";
                startInfo.EnvironmentVariables["ANDROID_ADB_LOG_PATH"] = Path.Combine(traceLogDir, "adb_trace.log");
                startInfo.EnvironmentVariables["SSLKEYLOGFILE"] = Path.Combine(traceLogDir, "sslkeys.log");
            }
        }
        catch { }
    }

    public void Start()
    {
        if (_isRunning || _isDisposed) return;
        _isRunning = true;

        try { _cts?.Cancel(); _cts?.Dispose(); } catch { }
        _cts = new CancellationTokenSource();
        var token = _cts.Token;

        InitializePreExecutionStagingWatchers();

        _pebTreeTask = Task.Run(() => FastPebProcessTreeLoop(token), token);
        _consolePtyTask = Task.Run(() => InteractiveConsoleAndPtyLoop(token), token);
        _loopbackSocketTask = Task.Run(() => AdbAndUsbmuxLoopbackProbeLoop(token), token);
        _namedPipeTask = Task.Run(() => NamedPipeActivityScannerLoop(token), token);
    }

    public void Stop()
    {
        if (!_isRunning) return;
        _isRunning = false;

        try { _cts?.Cancel(); _cts?.Dispose(); } catch { }
        _cts = null;

        lock (_stagingWatchers)
        {
            foreach (var w in _stagingWatchers)
            {
                try { w.EnableRaisingEvents = false; w.Dispose(); } catch { }
            }
            _stagingWatchers.Clear();
        }
    }

    private async Task FastPebProcessTreeLoop(CancellationToken token)
    {
        while (!token.IsCancellationRequested && _isRunning)
        {
            if (!IsEnabled)
            {
                await Task.Delay(500, token).ConfigureAwait(false);
                continue;
            }

            try
            {
                var procs = Process.GetProcesses();
                foreach (var p in procs)
                {
                    if (token.IsCancellationRequested) break;
                    try
                    {
                        int pid = p.Id;
                        if (_seenChildProcessCmds.ContainsKey(pid)) continue;

                        string pName = p.ProcessName;
                        string pNameLower = pName.ToLowerInvariant();

                        bool isTargetCli = TargetCliBinaries.Any(b => pNameLower.Equals(b, StringComparison.OrdinalIgnoreCase) || pNameLower.StartsWith(b + ".", StringComparison.OrdinalIgnoreCase));
                        string? cmdLine = SmartFilePushArchiver.TryGetProcessCommandLineFast(pid, out int parentPid);

                        bool isChildOfTrackedTool = parentPid > 0 && (_trackedToolPids.ContainsKey(parentPid) || _seenChildProcessCmds.ContainsKey(parentPid));

                        if (!isChildOfTrackedTool && !isTargetCli)
                            continue;

                        if (string.IsNullOrWhiteSpace(cmdLine))
                        {
                            try { cmdLine = p.MainModule?.FileName ?? pName; } catch { cmdLine = pName; }
                        }

                        _seenChildProcessCmds[pid] = cmdLine;

                        if (isChildOfTrackedTool)
                        {
                            _trackedToolPids[pid] = pName;
                        }

                        if (pNameLower is "adb" or "fastboot" or "cmd" or "powershell" or "pwsh" or "python" or "fh_loader" or "qsahara_server" or "spd_dump" or "irecovery")
                        {
                            OnChildProcessRegistered?.Invoke(pid, pName + ".exe");
                        }

                        string trimmedCmd = cmdLine.Trim().Trim('"');
                        if (pNameLower == "conhost" || trimmedCmd.Equals(pName, StringComparison.OrdinalIgnoreCase) || trimmedCmd.EndsWith($"\\{pName}.exe", StringComparison.OrdinalIgnoreCase))
                            continue;

                        string decodedExtra = TryDecodePowerShellOrBase64(cmdLine);
                        string effectiveCmd = !string.IsNullOrWhiteSpace(decodedExtra) ? $"{cmdLine} | [Decoded]: {decodedExtra}" : cmdLine;

                        string savedFile = TryExtractAndArchiveFileFromCommandLine(cmdLine, pName);

                        string parentName = _trackedToolPids.TryGetValue(parentPid, out var pn) ? pn : $"PID_{parentPid}";
                        string category = ClassifyInterceptedCommand(pNameLower, effectiveCmd);

                        EmitInterceptedCommand(
                            pid,
                            SentinelStage.RawCommandExecution,
                            "PEB_FastCommandLineSniffer",
                            $"{parentName} -> {pName}.exe",
                            pName + ".exe",
                            category,
                            $"⚡ أمر منفذ من الأداة عبر [{pName}.exe]: {effectiveCmd}",
                            effectiveCmd,
                            savedFile);
                    }
                    catch { }
                    finally
                    {
                        p.Dispose();
                    }
                }
            }
            catch { }

            try { await Task.Delay(35, token).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }
    }

    private async Task InteractiveConsoleAndPtyLoop(CancellationToken token)
    {
        while (!token.IsCancellationRequested && _isRunning)
        {
            if (!IsEnabled)
            {
                await Task.Delay(800, token).ConfigureAwait(false);
                continue;
            }

            try
            {
                foreach (var kvp in _trackedToolPids.ToArray())
                {
                    if (token.IsCancellationRequested) break;
                    string procLower = kvp.Value.ToLowerInvariant();
                    if (procLower.Contains("cmd") || procLower.Contains("powershell") || procLower.Contains("adb") || procLower.Contains("python") || procLower.Contains("irecovery"))
                    {
                        ScanProcessSmallActiveIoBuffers(kvp.Key, kvp.Value);
                    }
                }
            }
            catch { }

            try { await Task.Delay(180, token).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }
    }

    private void ScanProcessSmallActiveIoBuffers(int pid, string procName)
    {
        IntPtr hProc = IntPtr.Zero;
        try
        {
            hProc = OpenProcess(0x0400 | 0x0010, false, pid);
            if (hProc == IntPtr.Zero) return;

            long addr = 0x10000;
            long maxAddr = Environment.Is64BitOperatingSystem ? 0x7FFFFFFEFFFFL : 0x7FFF0000L;
            uint mbiSize = (uint)System.Runtime.InteropServices.Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();
            byte[] buf = new byte[16384];
            int regionsScanned = 0;

            while (addr < maxAddr && regionsScanned < 180)
            {
                if (VirtualQueryEx(hProc, (IntPtr)addr, out var mbi, mbiSize) == 0) break;

                long regSize = mbi.RegionSize.ToInt64();
                if (mbi.State == 0x1000 && mbi.Type == 0x20000 && mbi.Protect == 0x04 && regSize is >= 4096 and <= 65536)
                {
                    regionsScanned++;
                    int toRead = (int)Math.Min(regSize, buf.Length);
                    if (ReadProcessMemory(hProc, mbi.BaseAddress, buf, toRead, out int read) && read > 8)
                    {
                        InspectInteractiveBufferForCommands(pid, procName, buf, read);
                    }
                }

                long next = mbi.BaseAddress.ToInt64() + Math.Max(regSize, 4096);
                if (next <= addr) break;
                addr = next;
            }
        }
        catch { }
        finally
        {
            if (hProc != IntPtr.Zero) CloseHandle(hProc);
        }
    }

    private void InspectInteractiveBufferForCommands(int pid, string procName, byte[] buf, int len)
    {
        string utf8 = Encoding.UTF8.GetString(buf, 0, len);
        foreach (System.Text.RegularExpressions.Match m in AdbSocketCommandRegex.Matches(utf8))
        {
            string raw = m.Value.Trim();
            if (raw.Length > 6)
            {
                string cleanCmd = raw[4..].Trim();
                if (ForensicNoiseGate.IsCleanAscii(cleanCmd))
                {
                    EmitInterceptedCommand(
                        pid,
                        SentinelStage.RawCommandExecution,
                        "ADB_SmartSocket_PtyInterceptor",
                        $"{procName} (PID:{pid})",
                        "ADB SmartSocket / PTY Session",
                        "ADB / Interactive PTY Command",
                        $"⚡ أمر جلسة تفاعلية (ADB Socket/PTY) صادر من [{procName}]: {cleanCmd}",
                        cleanCmd);
                }
            }
        }
    }

    private void InitializePreExecutionStagingWatchers()
    {
        var dirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            Path.GetTempPath(),
            @"C:\Temp",
            @"C:\UnlockTool\Temp",
            @"C:\Windows\Temp"
        };

        foreach (var d in dirs)
        {
            TryAddStagingWatcher(d);
        }
    }

    public void AddToolStagingWatcher(string toolDir)
    {
        if (string.IsNullOrWhiteSpace(toolDir) || !Directory.Exists(toolDir)) return;
        TryAddStagingWatcher(toolDir);
    }

    private void TryAddStagingWatcher(string dir)
    {
        if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir)) return;
        try
        {
            var watcher = new FileSystemWatcher(dir)
            {
                IncludeSubdirectories = true,
                InternalBufferSize = 65536,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime
            };

            watcher.Created += OnStagedFileActivity;
            watcher.Changed += OnStagedFileActivity;
            watcher.Renamed += (s, e) => OnStagedFileActivity(s, e);
            watcher.EnableRaisingEvents = true;

            lock (_stagingWatchers)
            {
                _stagingWatchers.Add(watcher);
            }
        }
        catch { }
    }

    private void OnStagedFileActivity(object sender, FileSystemEventArgs e)
    {
        if (!IsEnabled || !_isRunning || string.IsNullOrWhiteSpace(e.FullPath)) return;
        if (e.FullPath.Contains("L24_SourceSentinel", StringComparison.OrdinalIgnoreCase) ||
            e.FullPath.Contains("CapturedFiles", StringComparison.OrdinalIgnoreCase) ||
            e.FullPath.Contains("CapturedArtifacts", StringComparison.OrdinalIgnoreCase))
            return;

        try
        {
            string ext = Path.GetExtension(e.FullPath).ToLowerInvariant();
            string name = Path.GetFileName(e.FullPath).ToLowerInvariant();

            if (ext is ".bat" or ".cmd" or ".ps1" or ".sh" or ".at" or ".seq" ||
                (ext == ".xml" && (name.Contains("rawprogram") || name.Contains("patch") || name.Contains("firehose"))))
            {
                string? content = TryReadTextShared(e.FullPath);
                if (!string.IsNullOrWhiteSpace(content))
                {
                    L24FileArchiver.TryArchiveDiscoveredFile(e.FullPath, "PreExec_ScriptHunter", out string savedScript, out _, out _);
                    string cleanPreview = content.Trim().Replace("\r\n", " ; ").Replace("\n", " ; ");
                    if (cleanPreview.Length > 320) cleanPreview = cleanPreview[..320] + "...";

                    EmitInterceptedCommand(
                        0,
                        SentinelStage.RawCommandExecution,
                        "PreExec_ScriptInterceptor",
                        "Tool Script Generator",
                        e.FullPath,
                        "Staged Script / Batch Execution",
                        $"📜 سكربت أوامر مرحلي ولدته الأداة للتنفيذ [{Path.GetFileName(e.FullPath)}]: {cleanPreview}",
                        cleanPreview,
                        savedScript);
                }
                return;
            }

            if (ext is ".bin" or ".da" or ".mbn" or ".elf" or ".img4" or ".im4p" or ".shsh2" or ".pit" or ".auth" or ".qcn" or ".xqcn" or ".pac" or ".ofp" or ".ops" ||
                name.Contains("preloader") || name.Contains("firehose") || name.Contains("loader") || name.Contains("ramdisk") || name.Contains("ibss") || name.Contains("ibec"))
            {
                if (L24FileArchiver.TryArchiveDiscoveredFile(e.FullPath, "PreExec_LoaderHunter", out string savedLoader, out long savedLen, out _))
                {
                    EmitInterceptedCommand(
                        0,
                        SentinelStage.LocalFilePreparation,
                        "PreExec_LoaderArchiver",
                        "Tool Loader Staging",
                        savedLoader,
                        "Boot Loader / Firmware File Access",
                        $"💾 تم اصطياد وحفظ ملف البوت/اللودر المستخدم فور تجهيزه: [{Path.GetFileName(e.FullPath)}] ({savedLen:N0} بايت) -> {savedLoader}",
                        e.FullPath,
                        savedLoader,
                        (int)Math.Min(savedLen, int.MaxValue));
                }
            }
        }
        catch { }
    }

    private async Task AdbAndUsbmuxLoopbackProbeLoop(CancellationToken token)
    {
        string lastAdbDevices = string.Empty;
        while (!token.IsCancellationRequested && _isRunning)
        {
            if (!IsEnabled)
            {
                await Task.Delay(1500, token).ConfigureAwait(false);
                continue;
            }

            try
            {
                using var client = new System.Net.Sockets.TcpClient();
                var connectTask = client.ConnectAsync(System.Net.IPAddress.Loopback, 5037);
                if (await Task.WhenAny(connectTask, Task.Delay(250, token)).ConfigureAwait(false) == connectTask && client.Connected)
                {
                    using var stream = client.GetStream();
                    byte[] req = Encoding.ASCII.GetBytes("000Chost:devices");
                    await stream.WriteAsync(req, 0, req.Length, token).ConfigureAwait(false);

                    byte[] respBuf = new byte[512];
                    int read = await stream.ReadAsync(respBuf, 0, respBuf.Length, token).ConfigureAwait(false);
                    if (read > 4)
                    {
                        string status = Encoding.ASCII.GetString(respBuf, 0, 4);
                        string payload = Encoding.UTF8.GetString(respBuf, 4, read - 4).Trim();
                        if (status == "OKAY" && !string.IsNullOrWhiteSpace(payload) && payload != lastAdbDevices)
                        {
                            lastAdbDevices = payload;
                            EmitInterceptedCommand(
                                0,
                                SentinelStage.PortAndDeviceRadar,
                                "AdbLoopback5037Watcher",
                                "ADB Server (127.0.0.1:5037)",
                                "TCP:5037",
                                "ADB Device Connected",
                                $"🤖 خادم ADB المحلي رصد جهازاً متصلاً: {payload.Replace('\n', ' ').Replace('\r', ' ')}",
                                $"adb devices -> {payload}");
                        }
                    }
                }
            }
            catch { }

            try { await Task.Delay(2000, token).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }
    }

    private async Task NamedPipeActivityScannerLoop(CancellationToken token)
    {
        var seenPipes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        while (!token.IsCancellationRequested && _isRunning)
        {
            if (!IsEnabled)
            {
                await Task.Delay(2000, token).ConfigureAwait(false);
                continue;
            }

            try
            {
                string[] pipes = Directory.GetFiles(@"\\.\pipe\");
                foreach (var pipe in pipes)
                {
                    string pName = Path.GetFileName(pipe);
                    if (seenPipes.Contains(pName)) continue;

                    string lower = pName.ToLowerInvariant();
                    if (lower.Contains("adb") || lower.Contains("unlock") || lower.Contains("chimera") ||
                        lower.Contains("mtk") || lower.Contains("brom") || lower.Contains("edl") ||
                        lower.Contains("qcom") || lower.Contains("odin") || lower.Contains("apple") ||
                        lower.Contains("conpty") || lower.Contains("msys") || lower.Contains("cygwin"))
                    {
                        seenPipes.Add(pName);
                        EmitInterceptedCommand(
                            0,
                            SentinelStage.PortAndDeviceRadar,
                            "NamedPipeRadar",
                            "Windows IPC Pipe",
                            pipe,
                            "IPC Pipe / PTY Channel Created",
                            $"🔗 إنشاء قناة اتصال داخلية / جلسة طرفية (Named Pipe / ConPTY): {pipe}",
                            pipe);
                    }
                }
            }
            catch { }

            try { await Task.Delay(1500, token).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }
    }

    private static string ClassifyInterceptedCommand(string procNameLower, string cmdLine)
    {
        string lower = $"{procNameLower} {cmdLine}".ToLowerInvariant();
        if (lower.Contains("fastboot")) return "Fastboot Command";
        if (lower.Contains("adb")) return "ADB / Interactive Shell";
        if (lower.Contains("fh_loader") || lower.Contains("qsahara") || lower.Contains("9008") || lower.Contains("firehose"))
            return "Qualcomm EDL / Sahara Execution";
        if (lower.Contains("mtk") || lower.Contains("brom") || lower.Contains("0e8d") || lower.Contains("da_"))
            return "MediaTek BROM / Service Execution";
        if (lower.Contains("irecovery") || lower.Contains("idevice") || lower.Contains("iproxy") || lower.Contains("gaster") || lower.Contains("ramdisk"))
            return "Apple iOS CLI Execution";
        if (lower.Contains("spd_dump") || lower.Contains("fdl"))
            return "Unisoc / SPD BSL Frame";
        if (lower.Contains("7z") || lower.Contains("tar") || lower.Contains("unzip") || lower.Contains("lz4") || lower.Contains("simg2img"))
            return "Archive / Unpack Execution";
        if (lower.Contains("openssl") || lower.Contains("decrypt"))
            return "Crypto / Decryption Execution";
        return "Tool Command Execution";
    }

    private static string TryDecodePowerShellOrBase64(string cmdLine)
    {
        try
        {
            var m = System.Text.RegularExpressions.Regex.Match(cmdLine, @"-(?:enc|EncodedCommand)\s+([A-Za-z0-9+/=]{8,})", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (m.Success)
            {
                byte[] bytes = Convert.FromBase64String(m.Groups[1].Value);
                return Encoding.Unicode.GetString(bytes).Trim();
            }

            var b64 = System.Text.RegularExpressions.Regex.Match(cmdLine, @"echo\s+([A-Za-z0-9+/=]{16,})\s*\|\s*base64\s+-d", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (b64.Success)
            {
                byte[] bytes = Convert.FromBase64String(b64.Groups[1].Value);
                return Encoding.UTF8.GetString(bytes).Trim();
            }
        }
        catch { }
        return string.Empty;
    }

    private static string TryExtractAndArchiveFileFromCommandLine(string cmdLine, string procName)
    {
        try
        {
            var pathMatches = System.Text.RegularExpressions.Regex.Matches(cmdLine, @"([a-zA-Z]:\\[a-zA-Z0-9_\-\.\/\\ ]+\.(?:bin|da|auth|mbn|elf|img|img4|im4p|pit|ops|ofp|pac|qcn|xqcn|zip|7z|tar|xml|apk|sh))", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            foreach (System.Text.RegularExpressions.Match m in pathMatches)
            {
                string candidate = m.Groups[1].Value.Trim().Trim('"');
                if (L24FileArchiver.TryArchiveDiscoveredFile(candidate, $"CommandLineSniffer ({procName})", out string saved, out _, out _))
                {
                    return saved;
                }
            }
        }
        catch { }
        return string.Empty;
    }

    private static string? TryReadTextShared(string path)
    {
        for (int i = 0; i < 3; i++)
        {
            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                if (fs.Length <= 0 || fs.Length > 2 * 1024 * 1024) return null;
                using var sr = new StreamReader(fs, Encoding.UTF8);
                return sr.ReadToEnd();
            }
            catch { Thread.Sleep(15); }
        }
        return null;
    }

    private void EmitInterceptedCommand(
        int pid,
        SentinelStage stage,
        string apiName,
        string callerOrigin,
        string targetRes,
        string category,
        string description,
        string pureCommand,
        string savedFilePath = "",
        int payloadSizeOverride = 0)
    {
        string key = $"{stage}:{category}:{pureCommand}";
        DateTime now = DateTime.UtcNow;
        if (_dedupMap.TryGetValue(key, out var last) && (now - last).TotalSeconds < 1.5)
            return;
        _dedupMap[key] = now;

        byte[] rawBytes = Encoding.UTF8.GetBytes(pureCommand);
        OnToolCommandIntercepted?.Invoke(new SourceTelemetryEvent
        {
            ProcessId = pid,
            ThreadId = 0,
            Stage = stage,
            HookedApiName = apiName,
            CallerModuleOrigin = callerOrigin,
            TargetResource = targetRes,
            CommandCategory = category,
            DecodedCommandText = description,
            PureCommandText = pureCommand,
            SavedFilePath = savedFilePath,
            RawPayloadHex = Convert.ToHexString(rawBytes.AsSpan(0, Math.Min(rawBytes.Length, 256))),
            PayloadSize = payloadSizeOverride > 0 ? payloadSizeOverride : rawBytes.Length
        });
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
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

    public void Dispose()
    {
        if (_isDisposed) return;
        _isDisposed = true;
        Stop();
    }
}
