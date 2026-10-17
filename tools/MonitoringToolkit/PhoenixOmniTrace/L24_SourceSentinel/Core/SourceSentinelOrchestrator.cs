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

    private readonly ConcurrentQueue<SourceTelemetryEvent> _sessionEvents = new();
    private readonly BlockingCollection<SourceTelemetryEvent> _diskLogQueue = new(new ConcurrentQueue<SourceTelemetryEvent>());
    private readonly ConcurrentDictionary<int, string> _autoAttachedPids = new();
    private readonly CancellationTokenSource _cts = new();
    private Task? _diskLoggerTask;
    private Task? _autoDiscoveryTask;
    private bool _isDisposed;

    private readonly string _logDirectory;
    private readonly string _sessionLogPath;
    private readonly string _sessionJsonlPath;

    public event Action<SourceTelemetryEvent>? OnTelemetryEventCaptured;
    public event Action<string>? OnLogMessage;

    public bool IsActive { get; private set; }
    public string LogDirectory => _logDirectory;
    public string SessionLogPath => _sessionLogPath;
    public OriginAttributionEngine Attribution => _attributionEngine;
    public KernelAndUsbEtwInterceptor KernelInterceptor => _kernelInterceptor;
    public WinUsbFilterAdbBridge AdbBridge => _adbBridge;

    public SourceSentinelOrchestrator(string? customLogDir = null)
    {
        _adbBridge = new WinUsbFilterAdbBridge(HandleIncomingEvent);
        string timestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
        
        // مسار السجلات المستقل تماماً
        _logDirectory = !string.IsNullOrWhiteSpace(customLogDir)
            ? customLogDir
            : ResolveDefaultLogDirectory();

        Directory.CreateDirectory(_logDirectory);
        _sessionLogPath = Path.Combine(_logDirectory, $"session_{timestamp}.json");
        _sessionJsonlPath = Path.Combine(_logDirectory, $"session_{timestamp}.jsonl");

        // ربط أحداث المكونات المختلفة
        _ipcServer.OnEventCaptured += HandleIncomingEvent;
        _ramWatcher.OnModuleOrRamActivity += HandleIncomingEvent;
        _radar.OnRadarActivity += HandleIncomingEvent;
        _heapHunter.OnCommandCaptured += HandleIncomingEvent;
        _dllAuditor.OnDllCapabilitiesExtracted += HandleIncomingEvent;
        _portPoller.OnPortActivityDetected += HandleIncomingEvent;
        _kernelInterceptor.OnKernelActivityDetected += HandleIncomingEvent;

        // ربط رصد WinUSB / adb.exe بوضع LiveHeapCommandHunter المتوازن
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
                OnLogMessage?.Invoke($"[L24 SourceSentinel] رصد مكتبة {fileName} - تفعيل المسح المزدوج المتوافق مع WinUSB/libusb");
            }

            _dllAuditor.AuditLoadedModule(pid, procName, dllPath);
        };
    }

    private static string ResolveDefaultLogDirectory()
    {
        string localProjLogs = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Logs", "L24_SourceSentinel");
        if (Directory.Exists(Path.GetDirectoryName(localProjLogs)))
            return localProjLogs;

        string cwdLogs = Path.Combine(Directory.GetCurrentDirectory(), "Logs", "L24_SourceSentinel");
        return cwdLogs;
    }

    public void Start()
    {
        if (IsActive || _isDisposed) return;
        IsActive = true;

        ForensicNoiseGate.ResetSessionDeduplication();
        _ipcServer.Start();
        _radar.StartMonitoring();
        // بدء مراقبة المنافذ التسلسلية والبورتات فوراً حتى قبل ربط أداة محددة
        _portPoller.StartPolling(0, "SystemWidePortMonitor");
        _diskLoggerTask = Task.Run(DiskLoggerLoop);
        _autoDiscoveryTask = Task.Run(() => AutoDiscoverGsmToolsLoop(_cts.Token));

        OnLogMessage?.Invoke($"[L24 SourceSentinel] تم تشغيل خادم الاعتراض الشامل (MTK / Modem / ADB / Ports) عبر الأنبوب: {SourceIpcServer.PipeName}");
    }

    private async Task AutoDiscoverGsmToolsLoop(CancellationToken token)
    {
        while (!token.IsCancellationRequested && !_isDisposed)
        {
            try
            {
                var procs = Process.GetProcesses();
                foreach (var p in procs)
                {
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
        if (_isDisposed) return;

        // بوابة التصفية الجنائية الموحدة وتطهير الضوضاء ومنع التكرار
        if (!ForensicNoiseGate.TryFilterAndNormalizeEvent(evt)) return;

        // تسجيل الأصل وتحديث إحصائيات المحرك
        _attributionEngine.TrackEvent(evt);

        // إضافة للذاكرة
        _sessionEvents.Enqueue(evt);

        // إرسال لصف الحفظ على القرص
        _diskLogQueue.TryAdd(evt);

        // إشعار المشتركين والواجهة
        OnTelemetryEventCaptured?.Invoke(evt);
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
            Start();

            var startInfo = new ProcessStartInfo
            {
                FileName = executablePath,
                Arguments = arguments,
                WorkingDirectory = !string.IsNullOrWhiteSpace(workingDir) ? workingDir : Path.GetDirectoryName(executablePath) ?? "",
                UseShellExecute = true
            };

            var proc = Process.Start(startInfo);
            if (proc != null)
            {
                _autoAttachedPids[proc.Id] = proc.ProcessName;
                OnLogMessage?.Invoke($"[L24 SourceSentinel] تم تشغيل الأداة بنجاح (PID: {proc.Id}) - جاري تفعيل المراقبة من المصدر");
                
                _radar.CurrentMonitoredPid = proc.Id;
                _radar.CurrentMonitoredProcessName = proc.ProcessName;

                _heapHunter.StartHunting(proc.Id, proc.ProcessName);
                _portPoller.StartPolling(proc.Id, proc.ProcessName);
                _kernelInterceptor.StartMonitoring(proc.Id, proc.ProcessName);

                _ramWatcher.ScanProcessModulesAndMemory(proc.Id, _logDirectory);

                Task.Run(async () =>
                {
                    while (!proc.HasExited && !_cts.IsCancellationRequested && !_isDisposed)
                    {
                        await Task.Delay(1500, _cts.Token).ConfigureAwait(false);
                        _ramWatcher.ScanProcessModulesAndMemory(proc.Id, _logDirectory);
                    }
                }, _cts.Token);

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
            Start();

            _autoAttachedPids[processId] = proc.ProcessName;
            OnLogMessage?.Invoke($"[L24 SourceSentinel] تم الارتباط بالعملية {proc.ProcessName} (PID: {processId}) بنجاح");
            
            _radar.CurrentMonitoredPid = proc.Id;
            _radar.CurrentMonitoredProcessName = proc.ProcessName;

            _heapHunter.StartHunting(proc.Id, proc.ProcessName);
            _portPoller.StartPolling(proc.Id, proc.ProcessName);
            _kernelInterceptor.StartMonitoring(proc.Id, proc.ProcessName);

            _ramWatcher.ScanProcessModulesAndMemory(processId, _logDirectory);

            Task.Run(async () =>
            {
                while (!proc.HasExited && !_cts.IsCancellationRequested && !_isDisposed)
                {
                    await Task.Delay(1500, _cts.Token).ConfigureAwait(false);
                    _ramWatcher.ScanProcessModulesAndMemory(processId, _logDirectory);
                }
            }, _cts.Token);

            return true;
        }
        catch (Exception ex)
        {
            OnLogMessage?.Invoke($"[خطأ الارتباط بالعملية {processId}]: {ex.Message}");
            return false;
        }
    }

    private void DiskLoggerLoop()
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

            while (!_cts.IsCancellationRequested && !_isDisposed)
            {
                try
                {
                    if (_diskLogQueue.TryTake(out var evt, 500, _cts.Token))
                    {
                        string jsonLine = JsonSerializer.Serialize(evt, options);
                        writer.WriteLine(jsonLine);
                    }
                }
                catch (OperationCanceledException) { break; }
                catch { }
            }
        }
        catch { }
    }

    public IReadOnlyList<SourceTelemetryEvent> GetSessionEvents() => _sessionEvents.ToArray();

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
            OnLogMessage?.Invoke($"[L24 SourceSentinel] تم حفظ وتصدير جلسة المراقبة كاملة إلى: {_sessionLogPath}");
        }
        catch (Exception ex)
        {
            OnLogMessage?.Invoke($"[خطأ تصدير الجلسة]: {ex.Message}");
        }
    }

    public void AttachToOmniTraceEventBus(PhoenixGSM.OmniTrace.Bus.OmniTraceEventBus bus)
    {
        _adbBridge.Attach(bus);
        OnLogMessage?.Invoke("[L24 SourceSentinel] تم ربط ناقل OmniTraceEventBus بنجاح لاستقبال كافة أوامر MTK والمودم والبورتات و ADB التفاعلية");
    }

    public void Dispose()
    {
        if (_isDisposed) return;
        _isDisposed = true;
        IsActive = false;

        _cts.Cancel();
        _cts.Dispose();

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
