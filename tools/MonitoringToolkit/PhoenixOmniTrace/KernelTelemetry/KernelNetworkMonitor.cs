using System;
using System.Collections.Generic;
using System.Runtime.Versioning;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace PhoenixGSM.OmniTrace.KernelTelemetry;

/// <summary>
/// مراقب شبكة النواة - يتتبع اتصالات الشبكة
/// Kernel network monitor - tracks network connections
/// </summary>
[SupportedOSPlatform("windows")]
public class KernelNetworkMonitor : IDisposable
{
    private TraceEventSession? _session;
    public event Action<SecurityEvent>? OnSecurityEvent;

    public void Start()
    {
        try
        {
            // بدء جلسة ETW للشبكات
            _session = new TraceEventSession("PhoenixOmniTrace_Network_Monitor");
            _session.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP);

            _session.Source.Kernel.TcpIpConnect += traceData =>
            {
                var evt = new SecurityEvent(
                    SecurityEventType.NetworkConnection,
                    SecurityEventSeverity.Info,
                    traceData.TimeStamp,
                    traceData.ProcessID,
                    traceData.ProcessName,
                    -1,
                    $"TCP Connect: {traceData.saddr}:{traceData.sport} -> {traceData.daddr}:{traceData.dport}",
                    new Dictionary<string, string>
                    {
                        { "SourceIP", traceData.saddr.ToString() },
                        { "SourcePort", traceData.sport.ToString() },
                        { "DestinationIP", traceData.daddr.ToString() },
                        { "DestinationPort", traceData.dport.ToString() }
                    },
                    Array.Empty<byte>()
                );
                OnSecurityEvent?.Invoke(evt);
            };

            Task.Run(() => _session.Source.Process());
        }
        catch (Exception ex)
        {
            // Fail-open: prevent crash
            Console.WriteLine($"[KernelNetworkMonitor] Error starting: {ex.Message}");
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

    public void Dispose() => Stop();
}
