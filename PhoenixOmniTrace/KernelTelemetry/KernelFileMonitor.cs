using System;
using System.Collections.Generic;
using System.Runtime.Versioning;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace PhoenixGSM.OmniTrace.KernelTelemetry;

/// <summary>
/// مراقب ملفات النواة - يتتبع إنشاء الملفات، الكتابة، الحذف وإعادة التسمية
/// Kernel file monitor - tracks file creates, writes, deletes, renames
/// </summary>
[SupportedOSPlatform("windows")]
public class KernelFileMonitor : IDisposable
{
    private TraceEventSession? _session;
    public event Action<SecurityEvent>? OnSecurityEvent;

    public void Start()
    {
        try
        {
            // بدء جلسة ETW للملفات
            _session = new TraceEventSession("PhoenixOmniTrace_File_Monitor");
            _session.EnableKernelProvider(
                KernelTraceEventParser.Keywords.FileIOInit |
                KernelTraceEventParser.Keywords.FileIO);

            _session.Source.Kernel.FileIOCreate += traceData =>
            {
                if (!IsRelevantPath(traceData.FileName)) return;

                var evt = new SecurityEvent(
                    SecurityEventType.FileModified,
                    SecurityEventSeverity.Info,
                    traceData.TimeStamp,
                    traceData.ProcessID,
                    traceData.ProcessName,
                    -1,
                    $"File Create: {traceData.FileName}",
                    new Dictionary<string, string> { { "FileName", traceData.FileName }, { "Operation", "Create" } },
                    Array.Empty<byte>()
                );
                OnSecurityEvent?.Invoke(evt);
            };

            _session.Source.Kernel.FileIOWrite += traceData =>
            {
                if (!IsRelevantPath(traceData.FileName)) return;

                var evt = new SecurityEvent(
                    SecurityEventType.FileModified,
                    SecurityEventSeverity.Info,
                    traceData.TimeStamp,
                    traceData.ProcessID,
                    traceData.ProcessName,
                    -1,
                    $"File Write: {traceData.FileName}",
                    new Dictionary<string, string> { { "FileName", traceData.FileName }, { "Operation", "Write" } },
                    Array.Empty<byte>()
                );
                OnSecurityEvent?.Invoke(evt);
            };

            _session.Source.Kernel.FileIODelete += traceData =>
            {
                if (!IsRelevantPath(traceData.FileName)) return;
                
                var evt = new SecurityEvent(
                    SecurityEventType.FileModified,
                    SecurityEventSeverity.Medium,
                    traceData.TimeStamp,
                    traceData.ProcessID,
                    traceData.ProcessName,
                    -1,
                    $"File Delete: {traceData.FileName}",
                    new Dictionary<string, string> { { "FileName", traceData.FileName }, { "Operation", "Delete" } },
                    Array.Empty<byte>()
                );
                OnSecurityEvent?.Invoke(evt);
            };

            _session.Source.Kernel.FileIORename += traceData =>
            {
                var evt = new SecurityEvent(
                    SecurityEventType.FileModified,
                    SecurityEventSeverity.Low,
                    traceData.TimeStamp,
                    traceData.ProcessID,
                    traceData.ProcessName,
                    -1,
                    "File Rename",
                    new Dictionary<string, string> { { "Operation", "Rename" } },
                    Array.Empty<byte>()
                );
                OnSecurityEvent?.Invoke(evt);
            };

            Task.Run(() => _session.Source.Process());
        }
        catch (Exception ex)
        {
            // Fail-open: prevent crash
            Console.WriteLine($"[KernelFileMonitor] Error starting: {ex.Message}");
        }
    }

    private bool IsRelevantPath(string path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        var p = path.ToLowerInvariant();
        return p.Contains("\\temp\\") || 
               p.Contains("\\appdata\\") || 
               p.Contains("\\system32\\") || 
               p.Contains("\\drivers\\");
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

    public void Dispose() => Stop();
}
