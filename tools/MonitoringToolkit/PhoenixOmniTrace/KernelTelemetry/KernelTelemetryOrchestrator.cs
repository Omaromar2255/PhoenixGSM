using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Runtime.Versioning;
using System.Text.Json;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.KernelTelemetry;

/// <summary>
/// منسق بيانات النواة - يدير كافة المراقبين ويجمع الأحداث
/// Kernel telemetry orchestrator - manages all monitors and aggregates events
/// </summary>
[SupportedOSPlatform("windows")]
public class KernelTelemetryOrchestrator : IDisposable
{
    private readonly KernelProcessMonitor _processMonitor;
    private readonly KernelFileMonitor _fileMonitor;
    private readonly KernelNetworkMonitor _networkMonitor;
    private readonly KernelRegistryMonitor _registryMonitor;
    private readonly dynamic _bus; // استخدام الناقل (Event Bus) الموجود مسبقا
    
    private readonly ConcurrentDictionary<SecurityEventType, long> _metrics = new();

    public event Action<SecurityEvent>? OnSecurityEvent;

    public KernelTelemetryOrchestrator(dynamic bus)
    {
        _bus = bus;
        _processMonitor = new KernelProcessMonitor();
        _fileMonitor = new KernelFileMonitor();
        _networkMonitor = new KernelNetworkMonitor();
        _registryMonitor = new KernelRegistryMonitor();

        // اشتراك في أحداث المراقبين
        // Subscribe to monitors' events
        _processMonitor.OnSecurityEvent += HandleSecurityEvent;
        _fileMonitor.OnSecurityEvent += HandleSecurityEvent;
        _networkMonitor.OnSecurityEvent += HandleSecurityEvent;
        _registryMonitor.OnSecurityEvent += HandleSecurityEvent;
    }

    private void HandleSecurityEvent(SecurityEvent evt)
    {
        try
        {
            _metrics.AddOrUpdate(evt.Type, 1, (_, count) => count + 1);
            OnSecurityEvent?.Invoke(evt);

            var payloadStr = JsonSerializer.Serialize(evt);
            var payloadBytes = System.Text.Encoding.UTF8.GetBytes(payloadStr);

            var metadata = new Dictionary<string, string>
            {
                { "ProcessId", evt.ProcessId.ToString() },
                { "ProcessName", evt.ProcessName ?? "" },
                { "Severity", evt.Severity.ToString() }
            };

            // استخدام RawCaptureEvent لإرسال البيانات عبر الناقل
            // Use RawCaptureEvent to send data via the bus
            var rawEvent = RawCaptureEvent.Create(
                sequence: 0,
                sensor: SensorType.ETW,
                transport: TransportType.ETW,
                direction: PacketDirection.INTERNAL,
                device: "LocalMachine",
                session: "KernelTelemetry",
                iface: 0,
                endpoint: evt.Type.ToString(),
                payload: payloadBytes,
                timestampSource: "ETW",
                metadata: metadata
            );

            _bus.Publish(rawEvent);
        }
        catch (Exception ex)
        {
            // Fail-open
            Console.WriteLine($"[KernelTelemetryOrchestrator] Handle error: {ex.Message}");
        }
    }

    public void Start()
    {
        try
        {
            _processMonitor.Start();
            _fileMonitor.Start();
            _networkMonitor.Start();
            _registryMonitor.Start();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[KernelTelemetryOrchestrator] Error starting: {ex.Message}");
        }
    }

    public void Stop()
    {
        try
        {
            _processMonitor.Stop();
            _fileMonitor.Stop();
            _networkMonitor.Stop();
            _registryMonitor.Stop();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[KernelTelemetryOrchestrator] Error stopping: {ex.Message}");
        }
    }

    public IReadOnlyDictionary<SecurityEventType, long> GetMetrics()
    {
        return new Dictionary<SecurityEventType, long>(_metrics);
    }

    public void Dispose()
    {
        Stop();
        _processMonitor.Dispose();
        _fileMonitor.Dispose();
        _networkMonitor.Dispose();
        _registryMonitor.Dispose();
    }
}
