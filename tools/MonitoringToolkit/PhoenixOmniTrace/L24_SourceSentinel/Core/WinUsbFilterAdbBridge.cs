using System;
using System.Text;
using PhoenixGSM.OmniTrace.Bus;
using PhoenixGSM.OmniTrace.Models;
using PhoenixOmniTrace.L24_SourceSentinel.Models;

namespace PhoenixOmniTrace.L24_SourceSentinel.Core;

/// <summary>
/// LAYER 24 BRIDGE — WinUsbFilterAdbBridge
/// Bridges KernelDriver / WinUSB Filter ADB stream events, ADB-RIL-IPC, and ADB-INTERACTIVE-CMD
/// directly into the L24 Source Sentinel forensic ledger with zero packet drop.
/// </summary>
public sealed class WinUsbFilterAdbBridge : IDisposable
{
    private readonly Action<SourceTelemetryEvent> _eventSink;
    private OmniTraceEventBus? _attachedBus;
    private bool _isDisposed;

    public WinUsbFilterAdbBridge(Action<SourceTelemetryEvent> eventSink)
    {
        _eventSink = eventSink ?? throw new ArgumentNullException(nameof(eventSink));
    }

    public void Attach(OmniTraceEventBus bus)
    {
        if (_attachedBus != null || bus == null) return;
        _attachedBus = bus;

        _attachedBus.OnLogicalCommand += HandleLogicalCommand;
        _attachedBus.OnRawCaptured += HandleRawCaptured;
    }

    public void Detach()
    {
        if (_attachedBus == null) return;
        _attachedBus.OnLogicalCommand -= HandleLogicalCommand;
        _attachedBus.OnRawCaptured -= HandleRawCaptured;
        _attachedBus = null;
    }

    private void HandleLogicalCommand(LogicalCommandEvent cmd)
    {
        if (_isDisposed || cmd == null) return;

        string proto = cmd.Details.TryGetValue("ProtocolName", out var pVal) ? pVal : (cmd.Protocol.ToString() ?? "");
        if (proto.Contains("ADB-RIL-IPC", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("ADB-INTERACTIVE", StringComparison.OrdinalIgnoreCase) ||
            (proto.Contains("ADB-STREAM", StringComparison.OrdinalIgnoreCase) && cmd.Direction == PacketDirection.HOST_TO_DEVICE))
        {
            string commandText = cmd.Command ?? "";
            byte[] rawBytes = Encoding.UTF8.GetBytes(commandText);

            var telemetryEvt = new SourceTelemetryEvent
            {
                ProcessId = 0,
                ThreadId = 0,
                Stage = SentinelStage.RawCommandExecution,
                HookedApiName = "WinUsbFilterAdbBridge",
                CallerModuleOrigin = "WinUSB Kernel Filter -> /data/local/tmp/AT",
                TargetResource = "/data/local/tmp/AT",
                CommandCategory = "ADB / Interactive Shell",
                DecodedCommandText = $"أمر تفاعلي مرسل للأداة (/data/local/tmp/AT): {commandText}",
                PayloadSize = rawBytes.Length,
                RawPayloadHex = Convert.ToHexString(rawBytes)
            };

            _eventSink(telemetryEvt);
        }
    }

    private void HandleRawCaptured(RawCaptureEvent raw)
    {
        if (_isDisposed || raw == null || raw.RawPayload == null || raw.RawPayload.Length == 0) return;

        // Inspect metadata
        string proto = raw.Metadata.TryGetValue("Protocol", out var pVal) ? pVal : "";
        string dir = raw.Direction == PacketDirection.HOST_TO_DEVICE ? "OUT" : "IN";

        bool isRelevant = proto.Equals("ADB-RIL-IPC", StringComparison.OrdinalIgnoreCase) ||
                          proto.Equals("ADB-INTERACTIVE-CMD", StringComparison.OrdinalIgnoreCase) ||
                          (proto.Equals("ADB-STREAM", StringComparison.OrdinalIgnoreCase) && dir == "OUT");

        if (isRelevant)
        {
            string ascii = Encoding.ASCII.GetString(raw.RawPayload).Trim('\0', '\r', '\n');
            string cmdText = raw.Metadata.TryGetValue("Command", out var cVal) && !string.IsNullOrWhiteSpace(cVal)
                ? cVal
                : (ascii.Length > 0 ? ascii : Convert.ToHexString(raw.RawPayload));

            var telemetryEvt = new SourceTelemetryEvent
            {
                ProcessId = 0,
                ThreadId = 0,
                Stage = SentinelStage.RawCommandExecution,
                HookedApiName = "WinUsbFilterAdbBridge",
                CallerModuleOrigin = "WinUSB Kernel Filter -> /data/local/tmp/AT",
                TargetResource = "/data/local/tmp/AT",
                CommandCategory = "ADB / Interactive Shell",
                DecodedCommandText = $"أمر تفاعلي على السلك (USB OUT): {cmdText}",
                PayloadSize = raw.RawPayload.Length,
                RawPayloadHex = Convert.ToHexString(raw.RawPayload)
            };

            _eventSink(telemetryEvt);
        }
    }

    public void ReportInteractiveCommand(string commandText, string targetTool = "/data/local/tmp/AT", int pid = 0)
    {
        if (_isDisposed || string.IsNullOrWhiteSpace(commandText)) return;

        byte[] rawBytes = Encoding.UTF8.GetBytes(commandText);
        var telemetryEvt = new SourceTelemetryEvent
        {
            ProcessId = pid,
            ThreadId = 0,
            Stage = SentinelStage.RawCommandExecution,
            HookedApiName = "WinUsbFilterAdbBridge",
            CallerModuleOrigin = $"WinUSB Kernel Filter -> {targetTool}",
            TargetResource = targetTool,
            CommandCategory = "ADB / Interactive Shell",
            DecodedCommandText = $"أمر تفاعلي مرسل للأداة ({targetTool}): {commandText}",
            PayloadSize = rawBytes.Length,
            RawPayloadHex = Convert.ToHexString(rawBytes)
        };

        _eventSink(telemetryEvt);
    }

    public void Dispose()
    {
        if (_isDisposed) return;
        _isDisposed = true;
        Detach();
    }
}
