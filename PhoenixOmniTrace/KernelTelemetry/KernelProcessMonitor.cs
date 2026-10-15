using System;
using System.Collections.Generic;
using System.Runtime.Versioning;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace PhoenixGSM.OmniTrace.KernelTelemetry;

/// <summary>
/// مراقب عمليات النواة - يتتبع العمليات، مسارات التشغيل وتحميل الصور
/// Kernel process monitor - tracks processes, threads, and image loads
/// </summary>
[SupportedOSPlatform("windows")]
public class KernelProcessMonitor : IDisposable
{
    private TraceEventSession? _session;
    
    // استبعاد العمليات النظامية لتقليل الضوضاء
    // Exclude system processes to reduce noise
    private readonly HashSet<string> _excludedProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "csrss.exe", "lsass.exe", "smss.exe", "services.exe", "svchost.exe", "System"
    };

    public event Action<SecurityEvent>? OnSecurityEvent;

    public void Start()
    {
        try
        {
            // بدء جلسة ETW للعمليات
            // Start ETW session for processes
            _session = new TraceEventSession("PhoenixOmniTrace_Process_Monitor");
            _session.EnableKernelProvider(
                KernelTraceEventParser.Keywords.Process |
                KernelTraceEventParser.Keywords.Thread |
                KernelTraceEventParser.Keywords.ImageLoad);

            _session.Source.Kernel.ProcessStart += traceData =>
            {
                if (_excludedProcesses.Contains(traceData.ProcessName)) return;
                
                var details = new Dictionary<string, string>
                {
                    { "CommandLine", traceData.CommandLine },
                    { "ImageFileName", traceData.ImageFileName }
                };
                
                var evt = new SecurityEvent(
                    SecurityEventType.ProcessCreated,
                    SecurityEventSeverity.Info,
                    traceData.TimeStamp,
                    traceData.ProcessID,
                    traceData.ProcessName,
                    traceData.ParentID,
                    $"Process started: {traceData.ProcessName}",
                    details,
                    Array.Empty<byte>()
                );
                OnSecurityEvent?.Invoke(evt);
            };

            _session.Source.Kernel.ProcessStop += traceData =>
            {
                if (_excludedProcesses.Contains(traceData.ProcessName)) return;

                var evt = new SecurityEvent(
                    SecurityEventType.ProcessTerminated,
                    SecurityEventSeverity.Info,
                    traceData.TimeStamp,
                    traceData.ProcessID,
                    traceData.ProcessName,
                    traceData.ParentID,
                    $"Process stopped: {traceData.ProcessName}",
                    new Dictionary<string, string>(),
                    Array.Empty<byte>()
                );
                OnSecurityEvent?.Invoke(evt);
            };

            _session.Source.Kernel.ThreadStart += traceData =>
            {
                if (_excludedProcesses.Contains(traceData.ProcessName)) return;
                
                var evt = new SecurityEvent(
                    SecurityEventType.ThreadCreated,
                    SecurityEventSeverity.Info,
                    traceData.TimeStamp,
                    traceData.ProcessID,
                    traceData.ProcessName,
                    0,
                    $"Thread started in process: {traceData.ProcessName}",
                    new Dictionary<string, string> { { "ThreadID", traceData.ThreadID.ToString() } },
                    Array.Empty<byte>()
                );
                OnSecurityEvent?.Invoke(evt);
            };

            _session.Source.Kernel.ImageLoad += traceData =>
            {
                if (_excludedProcesses.Contains(traceData.ProcessName)) return;
                
                var evt = new SecurityEvent(
                    SecurityEventType.ImageLoaded,
                    SecurityEventSeverity.Info,
                    traceData.TimeStamp,
                    traceData.ProcessID,
                    traceData.ProcessName,
                    0,
                    $"Image loaded: {traceData.FileName}",
                    new Dictionary<string, string> { { "FileName", traceData.FileName } },
                    Array.Empty<byte>()
                );
                OnSecurityEvent?.Invoke(evt);
            };

            // تشغيل الاستماع في خلفية منفصلة
            Task.Run(() => _session.Source.Process());
        }
        catch (Exception ex)
        {
            // تجنب توقف النظام في حالة حدوث خطأ
            // Fail-open: prevent crash
            Console.WriteLine($"[KernelProcessMonitor] Error starting: {ex.Message}");
        }
    }

    public void Stop()
    {
        try
        {
            if (_session != null)
            {
                _session.Stop();
                _session.Dispose();
                _session = null;
            }
        }
        catch { }
    }

    public void Dispose()
    {
        Stop();
    }
}
