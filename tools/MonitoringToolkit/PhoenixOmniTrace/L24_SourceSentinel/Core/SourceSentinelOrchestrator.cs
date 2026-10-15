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
    private readonly SourceIpcServer _ipcServer = new();
    private readonly RamAndModuleWatcher _ramWatcher = new();
    private readonly PortAndFileRadar _radar = new();
    private readonly OriginAttributionEngine _attributionEngine = new();
    private readonly LiveHeapCommandHunter _heapHunter = new();
    private readonly DllFunctionTableAuditor _dllAuditor = new();
    private readonly ActiveComAndUsbPortPoller _portPoller = new();
    private readonly KernelAndUsbEtwInterceptor _kernelInterceptor = new();

    private readonly ConcurrentQueue<SourceTelemetryEvent> _sessionEvents = new();
    private readonly BlockingCollection<SourceTelemetryEvent> _diskLogQueue = new(new ConcurrentQueue<SourceTelemetryEvent>());
    private readonly CancellationTokenSource _cts = new();
    private Task? _diskLoggerTask;
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

    public SourceSentinelOrchestrator(string? customLogDir = null)
    {
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

        // ربط رصد WinUSB / adb.exe بوضع LiveHeapCommandHunter الهادئ
        _kernelInterceptor.OnChildAdbOrWinUsbDetected += (childPid, procName) =>
        {
            _heapHunter.IsWinUsbOrChildAdbActive = true;
            if (string.Equals(procName, "adb.exe", StringComparison.OrdinalIgnoreCase))
            {
                _heapHunter.RegisterChildAdbProcess(childPid, procName);
            }
            OnLogMessage?.Invoke($"[L24 SourceSentinel] تفعيل الوضع الهادئ المتوافق مع WinUSB/ADB (الهدف: {procName}, PID: {childPid})");
        };

        _ramWatcher.OnExternalModuleDiscovered += (pid, procName, dllPath) =>
        {
            // رصد مكتبات WinUSB / AdbWinUsbApi المحملة في ذاكرة الأداة
            string fileName = Path.GetFileName(dllPath);
            if (fileName.Contains("winusb", StringComparison.OrdinalIgnoreCase) ||
                fileName.Contains("adbwinusb", StringComparison.OrdinalIgnoreCase))
            {
                _heapHunter.IsWinUsbOrChildAdbActive = true;
                OnLogMessage?.Invoke($"[L24 SourceSentinel] رصد مكتبة {fileName} - تم تحويل Hunter إلى الوضع الهادئ المتوافق مع WinUSB");
            }

            _dllAuditor.AuditLoadedModule(pid, procName, dllPath);
        };
    }

    private static string ResolveDefaultLogDirectory()
    {
        // 1. مجلد المشروع المحلي إن وجد
        string localProjLogs = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Logs", "L24_SourceSentinel");
        if (Directory.Exists(Path.GetDirectoryName(localProjLogs)))
            return localProjLogs;

        // 2. مجلد العمل الحالي
        string cwdLogs = Path.Combine(Directory.GetCurrentDirectory(), "Logs", "L24_SourceSentinel");
        return cwdLogs;
    }

    public void Start()
    {
        if (IsActive || _isDisposed) return;
        IsActive = true;

        _ipcServer.Start();
        _radar.StartMonitoring();
        _diskLoggerTask = Task.Run(DiskLoggerLoop);

        OnLogMessage?.Invoke($"[L24 SourceSentinel] تم تشغيل خادم الاعتراض فائق السرعة عبر الأنبوب: {SourceIpcServer.PipeName}");
    }

    private void HandleIncomingEvent(SourceTelemetryEvent evt)
    {
        if (_isDisposed) return;

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
                OnLogMessage?.Invoke($"[L24 SourceSentinel] تم تشغيل الأداة بنجاح (PID: {proc.Id}) - جاري تفعيل المراقبة من المصدر");
                
                // ربط رادار الملفات بالعملية الحالية
                _radar.CurrentMonitoredPid = proc.Id;
                _radar.CurrentMonitoredProcessName = proc.ProcessName;

                // تشغيل صياد الذاكرة الحية ورادار منافذ السيريال والـ USB واعتراض الكيرنل
                _heapHunter.StartHunting(proc.Id, proc.ProcessName);
                _portPoller.StartPolling(proc.Id, proc.ProcessName);
                _kernelInterceptor.StartMonitoring(proc.Id, proc.ProcessName);

                // مسح أولي للمكتبات المحملة بالرام
                _ramWatcher.ScanProcessModulesAndMemory(proc.Id, _logDirectory);

                // بدء فحص دوري للمكتبات الجديدة المفكوكة
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

            OnLogMessage?.Invoke($"[L24 SourceSentinel] تم الارتباط بالعملية {proc.ProcessName} (PID: {processId}) بنجاح");
            
            // ربط رادار الملفات بالعملية الحالية
            _radar.CurrentMonitoredPid = proc.Id;
            _radar.CurrentMonitoredProcessName = proc.ProcessName;

            // تشغيل صياد الذاكرة الحية ورادار منافذ السيريال والـ USB واعتراض الكيرنل
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

    public void Dispose()
    {
        if (_isDisposed) return;
        _isDisposed = true;
        IsActive = false;

        _cts.Cancel();
        _cts.Dispose();

        _ipcServer.Dispose();
        _ramWatcher.Dispose();
        _radar.Dispose();
        _heapHunter.Dispose();
        _portPoller.Dispose();
        _kernelInterceptor.Dispose();

        FlushAndExportSessionSnapshot();
    }
}
