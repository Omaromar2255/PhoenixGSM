using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using PhoenixGSM.OmniTrace.Bus;
using PhoenixGSM.OmniTrace.Sensors;
using PhoenixGSM.OmniTrace.ToolSourceInterception;
using PhoenixOmniTrace.L24_SourceSentinel.Models;

namespace PhoenixOmniTrace.L24_SourceSentinel.Core;

public sealed partial class SourceSentinelOrchestrator : IDisposable
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

    // الحساسات المدمجة لضمان التقاط الروابط وأوامر MTK المنفذة والعمليات
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

    // 2. السجل الشامل الخام بدون فلترة
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

        // تهيئة الحساسات الداخلية للطبقة L24
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

    private void HandleIncomingEvent(SourceTelemetryEvent evt)
    {
        if (!_isActive || _isDisposed || evt == null) return;

        RecordUnfilteredRawEvent(evt);

        if (evt.Scope == L24CommandScope.DiscoveredInRam)
        {
            if (!IsCategoryDetectionEnabled(evt.CommandGroup))
                return;

            if (_excludeUrlsFromDiscovered && (evt.CommandGroup == L24CommandGroup.ServerCloudLogin || L24CommandClassifier.IsUrlOrNetworkOrAuth(evt)))
                return;
        }

        if (!ForensicNoiseGate.TryFilterAndNormalizeEvent(evt)) return;

        _attributionEngine.TrackEvent(evt);
        _sessionEvents.Enqueue(evt);
        _diskLogQueue.TryAdd(evt);
        OnTelemetryEventCaptured?.Invoke(evt);
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
