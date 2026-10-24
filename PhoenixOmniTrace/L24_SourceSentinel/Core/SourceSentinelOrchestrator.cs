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

    /// <summary>
    /// التحكم الآني في تشغيل أو إيقاف السجل الشامل الخام بدون فلترة
    /// </summary>
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
    public WinUsbFilterAdbBridge AdbBridge => _adbBridge;

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
    private volatile bool _excludeUrlsFromRawLog = true; // default true: "او اجعل افتراضي مفعل"

    /// <summary>
    /// خيار استثناء الروابط من السجل الخام الشامل (مفعل افتراضياً حسب طلب المستخدم)
    /// </summary>
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

    /// <summary>
    /// خيار استثناء الروابط واستدعاءات الخوادم من الأوامر المكتشفة في الذاكرة
    /// </summary>
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

        OnLogMessage?.Invoke("[L24 SourceSentinel] تم تفعيل وتشغيل الطبقة 24 بنجاح (المراقبة الشاملة وفحص الذاكرة والرادار نشطة الآن)");
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
                await Task.Delay(2000, token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { break; }
        }
    }

    private void HandleIncomingEvent(SourceTelemetryEvent evt)
    {
        if (!_isActive || _isDisposed || evt == null) return;

        // ══════════════════════════════════════════════════════════════════════
        // المسار الأول (الجديد): السجل الشامل الخام بدون فلترة (Unfiltered Raw Stream)
        // يسجل كل شيء فوراً في تبويب السجل الشامل الخام وفي ملف منفصل خاص به قبل أي فلترة!
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
            // استثناء الروابط واستدعاءات الخوادم من السجل الخام عند تفعيل الخيار (مفعل افتراضياً)
            if (_excludeUrlsFromRawLog && (evt.CommandGroup == L24CommandGroup.ServerCloudLogin || L24CommandClassifier.IsUrlOrNetworkOrAuth(evt)))
                return;
            string rawKey = $"{evt.HookedApiName}|{evt.CommandCategory}|{evt.TargetResource}|{evt.DecodedCommandText}";
            DateTime now = DateTime.UtcNow;

            // منع تكرار نفس النبضة الساكنة حرفياً خلال 1.5 ثانية فقط للحفاظ على سرعة الواجهة دون حذف أي حدث فعلي
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
            }

            var startInfo = new ProcessStartInfo
            {
                FileName = executablePath,
                Arguments = arguments,
                WorkingDirectory = toolDir,
                UseShellExecute = true
            };

            var proc = Process.Start(startInfo);
            if (proc != null)
            {
                _autoAttachedPids[proc.Id] = proc.ProcessName;
                _universalInterceptor.RegisterToolPid(proc.Id);
                OnLogMessage?.Invoke($"[L24 SourceSentinel] تم تشغيل الأداة بنجاح (PID: {proc.Id}) - جاري تفعيل المراقبة الشاملة");

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

            try
            {
                string? exePath = proc.MainModule?.FileName;
                string? toolDir = !string.IsNullOrWhiteSpace(exePath) ? Path.GetDirectoryName(exePath) : null;
                if (!string.IsNullOrWhiteSpace(toolDir))
                {
                    L24FileArchiver.RegisterToolDirectory(toolDir);
                    _radar.AddDirectoryWatcher(toolDir);
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
        OnLogMessage?.Invoke("[L24 SourceSentinel] تم ربط ناقل OmniTraceEventBus بنجاح لاستقبال كافة أوامر MTK والروابط والمودم و ADB");
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
