using System;
using System.Collections.Generic;
using System.Runtime.Versioning;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace PhoenixGSM.OmniTrace.KernelTelemetry;

/// <summary>
/// مراقب السجل من خلال النواة - يتتبع تعديلات السجل الهامة
/// Kernel registry monitor - tracks critical registry modifications
/// </summary>
[SupportedOSPlatform("windows")]
public class KernelRegistryMonitor : IDisposable
{
    private TraceEventSession? _session;
    public event Action<SecurityEvent>? OnSecurityEvent;

    public void Start()
    {
        try
        {
            // بدء جلسة ETW للسجلات
            _session = new TraceEventSession("PhoenixOmniTrace_Registry_Monitor");
            _session.EnableKernelProvider(KernelTraceEventParser.Keywords.Registry);

            _session.Source.Kernel.RegistryCreate += traceData =>
            {
                if (!IsRelevantKey(traceData.KeyName)) return;

                var evt = new SecurityEvent(
                    SecurityEventType.RegistryModified,
                    SecurityEventSeverity.Low,
                    traceData.TimeStamp,
                    traceData.ProcessID,
                    traceData.ProcessName,
                    -1,
                    $"Registry Key Created: {traceData.KeyName}",
                    new Dictionary<string, string> { { "KeyName", traceData.KeyName }, { "Operation", "Create" } },
                    Array.Empty<byte>()
                );
                OnSecurityEvent?.Invoke(evt);
            };

            _session.Source.Kernel.RegistrySetValue += traceData =>
            {
                if (!IsRelevantKey(traceData.KeyName)) return;

                var evt = new SecurityEvent(
                    SecurityEventType.RegistryModified,
                    SecurityEventSeverity.Medium,
                    traceData.TimeStamp,
                    traceData.ProcessID,
                    traceData.ProcessName,
                    -1,
                    $"Registry Value Set: {traceData.KeyName}",
                    new Dictionary<string, string> { { "KeyName", traceData.KeyName }, { "ValueName", traceData.ValueName }, { "Operation", "SetValue" } },
                    Array.Empty<byte>()
                );
                OnSecurityEvent?.Invoke(evt);
            };

            _session.Source.Kernel.RegistryDelete += traceData =>
            {
                if (!IsRelevantKey(traceData.KeyName)) return;

                var evt = new SecurityEvent(
                    SecurityEventType.RegistryModified,
                    SecurityEventSeverity.Low,
                    traceData.TimeStamp,
                    traceData.ProcessID,
                    traceData.ProcessName,
                    -1,
                    $"Registry Key Deleted: {traceData.KeyName}",
                    new Dictionary<string, string> { { "KeyName", traceData.KeyName }, { "Operation", "Delete" } },
                    Array.Empty<byte>()
                );
                OnSecurityEvent?.Invoke(evt);
            };

            Task.Run(() => _session.Source.Process());
        }
        catch (Exception ex)
        {
            // Fail-open
            Console.WriteLine($"[KernelRegistryMonitor] Error starting: {ex.Message}");
        }
    }

    private bool IsRelevantKey(string keyName)
    {
        if (string.IsNullOrEmpty(keyName)) return false;
        var k = keyName.ToLowerInvariant();
        return k.Contains("run") || 
               k.Contains("services") || 
               k.Contains("image file execution options") || 
               k.Contains("usb");
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
