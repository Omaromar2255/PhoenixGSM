using System;
using System.Threading;
using PhoenixGSM.OmniTrace.Bus;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.Sensors;

/// <summary>
/// LAYER 3 — USB Capture Sensor Adapter
/// Transforms physical USB packet acquisitions into unified RawCaptureEvents.
/// </summary>
public sealed class UsbDeviceSensor
{
    private readonly OmniTraceEventBus _bus;
    private ulong _sequence;

    public UsbDeviceSensor(OmniTraceEventBus bus)
    {
        _bus = bus;
    }

    public RawCaptureEvent IngestUsbPacket(
        string deviceId,
        int interfaceIndex,
        string endpointAddress,
        PacketDirection direction,
        byte[] payload,
        string transportSession = "USB_SESSION_01",
        Dictionary<string, string>? metadata = null,
        SensorType sensor = SensorType.USB,
        TransportType transport = TransportType.BULK)
    {
        ulong seq = Interlocked.Increment(ref _sequence);
        var rawEvt = RawCaptureEvent.Create(
            sequence: seq,
            sensor: sensor,
            transport: transport,
            direction: direction,
            device: deviceId,
            session: transportSession,
            iface: interfaceIndex,
            endpoint: endpointAddress,
            payload: payload,
            timestampSource: sensor == SensorType.ETW ? "ETW" : "KernelUSB",
            metadata: metadata
        );

        _bus.Publish(rawEvt);
        return rawEvt;
    }
}
