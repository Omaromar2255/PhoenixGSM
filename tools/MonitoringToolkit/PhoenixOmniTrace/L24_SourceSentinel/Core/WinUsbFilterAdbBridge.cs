using System;
using System.Linq;
using System.Text;
using PhoenixGSM.OmniTrace.Bus;
using PhoenixGSM.OmniTrace.Models;
using PhoenixOmniTrace.L24_SourceSentinel.Models;

namespace PhoenixOmniTrace.L24_SourceSentinel.Core;

/// <summary>
/// LAYER 24 UNIVERSAL BRIDGE — WinUsbFilterAdbBridge
/// Bridges KernelDriver / WinUSB Filter / ETW / Serial / ToolSource events across:
/// 1. MediaTek (MTK-BROM, MTK-DA, MTK-FILTER, Preloader, SLA/DAA, XFlash)
/// 2. Serial & Modem Ports (AT commands, Qualcomm DIAG, Samsung Modem, Staged AT files)
/// 3. Android ADB & Interactive Sessions (ADB-SHELL, ADB-RIL-IPC, /data/local/tmp/AT, Fastboot, EDL)
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
        string commandText = (cmd.Command ?? "").Trim();
        if (string.IsNullOrWhiteSpace(commandText)) return;

        // Ignore empty host subprocess notifications
        if (commandText.Equals("SUBPROCESS_EXECUTION", StringComparison.OrdinalIgnoreCase))
            return;

        string callerTool = cmd.Attribution?.ImageName;
        if (string.IsNullOrWhiteSpace(callerTool))
        {
            callerTool = cmd.Details.TryGetValue("Caller", out var clr) && !string.IsNullOrWhiteSpace(clr)
                ? clr
                : (!string.IsNullOrWhiteSpace(cmd.Service) ? cmd.Service : "OmniTraceBus");
        }

        int pid = cmd.Attribution?.ProcessId ?? 0;
        string targetRes = !string.IsNullOrWhiteSpace(cmd.DeviceIdentity) ? cmd.DeviceIdentity : cmd.Service;
        byte[] rawBytes = Encoding.UTF8.GetBytes(commandText);
        string dirStr = cmd.Direction == PacketDirection.HOST_TO_DEVICE ? "OUT" : "IN";

        // 1. MediaTek BROM / Preloader / DA / Filter Commands
        if (cmd.Protocol is KnownProtocol.MtkBrom or KnownProtocol.MtkDa ||
            proto.Contains("MTK", StringComparison.OrdinalIgnoreCase) ||
            (cmd.Details.TryGetValue("Category", out var catVal) && catVal.Equals("MediaTek", StringComparison.OrdinalIgnoreCase)))
        {
            string mtkCategory = cmd.Protocol == KnownProtocol.MtkDa || proto.Contains("DA", StringComparison.OrdinalIgnoreCase)
                ? "MediaTek DA Command"
                : "MediaTek BROM / Preloader Command";

            string details = cmd.Details.TryGetValue("Summary", out var sum) && !string.IsNullOrWhiteSpace(sum)
                ? sum
                : commandText;

            _eventSink(new SourceTelemetryEvent
            {
                ProcessId = pid,
                ThreadId = 0,
                Stage = SentinelStage.RawCommandExecution,
                HookedApiName = "L24_MtkProtocolBridge",
                CallerModuleOrigin = $"{callerTool} -> MTK ({dirStr})",
                TargetResource = string.IsNullOrWhiteSpace(targetRes) ? "MTK USB/VCOM Port" : targetRes,
                CommandCategory = mtkCategory,
                DecodedCommandText = $"[{mtkCategory}] ({dirStr}) على [{targetRes}]: {details}",
                PayloadSize = rawBytes.Length,
                RawPayloadHex = Convert.ToHexString(rawBytes)
            });
            return;
        }

        // 2. Modem AT / Serial COM Port / Qualcomm DIAG / Staged AT Commands
        if (cmd.Protocol == KnownProtocol.SerialAt ||
            proto.Contains("SERIAL", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("AT", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("DIAG", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("MODEM", StringComparison.OrdinalIgnoreCase))
        {
            bool isReply = cmd.Direction == PacketDirection.DEVICE_TO_HOST || commandText.StartsWith("<<");
            string cleanAt = commandText.TrimStart('<', '>', ' ');
            string modemCat = isReply ? "Modem Phone Response" : "Modem AT Command";

            _eventSink(new SourceTelemetryEvent
            {
                ProcessId = pid,
                ThreadId = 0,
                Stage = SentinelStage.RawCommandExecution,
                HookedApiName = "L24_ModemSerialBridge",
                CallerModuleOrigin = $"{callerTool} -> {targetRes}",
                TargetResource = string.IsNullOrWhiteSpace(targetRes) ? "COM / Modem Port" : targetRes,
                CommandCategory = modemCat,
                DecodedCommandText = isReply
                    ? $"رد المودم/الهاتف على [{targetRes}]: {cleanAt}"
                    : $"أمر مودم/بورت صادر إلى [{targetRes}]: {cleanAt}",
                PayloadSize = rawBytes.Length,
                RawPayloadHex = Convert.ToHexString(rawBytes)
            });
            return;
        }

        // 3. Qualcomm EDL (Sahara / Firehose) & Unisoc SPD & Fastboot & Odin
        if (cmd.Protocol is KnownProtocol.QualcommSahara or KnownProtocol.QualcommFirehose or KnownProtocol.SpreadtrumFdl or KnownProtocol.Fastboot or KnownProtocol.SamsungOdin)
        {
            string protoCategory = cmd.Protocol switch
            {
                KnownProtocol.QualcommFirehose => "Qualcomm Firehose XML",
                KnownProtocol.QualcommSahara => "Qualcomm Sahara",
                KnownProtocol.SpreadtrumFdl => "Unisoc / SPD BSL Frame",
                KnownProtocol.Fastboot => "Fastboot Command",
                KnownProtocol.SamsungOdin => "Samsung Odin Protocol",
                _ => proto
            };

            _eventSink(new SourceTelemetryEvent
            {
                ProcessId = pid,
                ThreadId = 0,
                Stage = SentinelStage.RawCommandExecution,
                HookedApiName = "L24_ChipsetProtocolBridge",
                CallerModuleOrigin = $"{callerTool} -> {protoCategory}",
                TargetResource = string.IsNullOrWhiteSpace(targetRes) ? protoCategory : targetRes,
                CommandCategory = protoCategory,
                DecodedCommandText = $"[{protoCategory}] ({dirStr}): {commandText}",
                PayloadSize = rawBytes.Length,
                RawPayloadHex = Convert.ToHexString(rawBytes)
            });
            return;
        }

        // 4. ADB / Interactive Shell / RIL IPC Commands & Responses
        if (cmd.Protocol == KnownProtocol.ADB ||
            proto.Contains("ADB", StringComparison.OrdinalIgnoreCase))
        {
            // Filter out binary ELF garbage chunks mistakenly tagged as commands
            if (!IsCleanPrintableOrHexCommand(commandText))
                return;

            bool isRilIpc = proto.Contains("ADB-RIL-IPC", StringComparison.OrdinalIgnoreCase);
            string adbCategory = isRilIpc ? "ADB RIL / AT IPC Command" : "ADB / Interactive Shell";
            string targetService = !string.IsNullOrWhiteSpace(cmd.Service) ? cmd.Service : "/data/local/tmp/AT";

            _eventSink(new SourceTelemetryEvent
            {
                ProcessId = pid,
                ThreadId = 0,
                Stage = SentinelStage.RawCommandExecution,
                HookedApiName = "WinUsbFilterAdbBridge",
                CallerModuleOrigin = $"WinUSB / ADB -> {targetService}",
                TargetResource = targetService,
                CommandCategory = adbCategory,
                DecodedCommandText = cmd.Direction == PacketDirection.HOST_TO_DEVICE
                    ? $"أمر تفاعلي مرسل للهاتف ({targetService}): {commandText}"
                    : $"رد الهاتف عبر ADB ({targetService}): {commandText}",
                PayloadSize = rawBytes.Length,
                RawPayloadHex = Convert.ToHexString(rawBytes)
            });
        }
    }

    private void HandleRawCaptured(RawCaptureEvent raw)
    {
        if (_isDisposed || raw == null || raw.RawPayload == null || raw.RawPayload.Length == 0) return;

        string proto = raw.Metadata != null && raw.Metadata.TryGetValue("Protocol", out var pVal) ? pVal : "";
        string dir = raw.Direction == PacketDirection.HOST_TO_DEVICE ? "OUT" : "IN";
        string portOrEp = raw.Metadata != null && raw.Metadata.TryGetValue("Port", out var portVal) && !string.IsNullOrWhiteSpace(portVal)
            ? portVal
            : (!string.IsNullOrWhiteSpace(raw.Endpoint) ? raw.Endpoint : raw.DeviceIdentity);

        // 1. Raw Serial / Modem Port Traffic (from SerialPortSensor, UpperFilter, or UsbEtwSensor)
        if (raw.Sensor == SensorType.Serial || raw.Transport == TransportType.SERIAL ||
            proto.Contains("SERIAL", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("MODEM", StringComparison.OrdinalIgnoreCase))
        {
            var (cat, decoded) = Decoders.RawPayloadClassifier.Classify("SerialPortCapture", portOrEp, 0, raw.RawPayload);
            _eventSink(new SourceTelemetryEvent
            {
                ProcessId = 0,
                ThreadId = 0,
                Stage = SentinelStage.RawCommandExecution,
                HookedApiName = "SerialAndModemBusBridge",
                CallerModuleOrigin = $"Serial/Modem ({dir}) -> {portOrEp}",
                TargetResource = portOrEp,
                CommandCategory = cat,
                DecodedCommandText = $"[{cat}] ({dir}) عبر المنفذ [{portOrEp}]: {decoded}",
                PayloadSize = raw.RawPayload.Length,
                RawPayloadHex = Convert.ToHexString(raw.RawPayload.AsSpan(0, Math.Min(raw.RawPayload.Length, 256)))
            });
            return;
        }

        // 2. Raw MTK BROM / DA Traffic
        if (proto.Contains("MTK", StringComparison.OrdinalIgnoreCase) ||
            PhoenixGSM.OmniTrace.Decoders.MtkProtocolDecoder.EvaluateMtk(raw.RawPayload) >= 0.75)
        {
            var mtkPkt = PhoenixGSM.OmniTrace.Decoders.MtkProtocolDecoder.DecodePacket(raw.RawPayload, raw.Direction);
            if (mtkPkt != null)
            {
                _eventSink(new SourceTelemetryEvent
                {
                    ProcessId = 0,
                    ThreadId = 0,
                    Stage = SentinelStage.RawCommandExecution,
                    HookedApiName = "MtkRawUsbBridge",
                    CallerModuleOrigin = $"MTK USB/VCOM ({dir})",
                    TargetResource = portOrEp,
                    CommandCategory = $"MediaTek {mtkPkt.Stage} Command",
                    DecodedCommandText = $"{mtkPkt.ToString()} ({dir})",
                    PayloadSize = raw.RawPayload.Length,
                    RawPayloadHex = Convert.ToHexString(raw.RawPayload.AsSpan(0, Math.Min(raw.RawPayload.Length, 256)))
                });
                return;
            }
        }

        // 3. Raw ADB / RIL-IPC / Interactive Commands
        bool isRelevantAdb = proto.Equals("ADB-RIL-IPC", StringComparison.OrdinalIgnoreCase) ||
                             proto.Equals("ADB-INTERACTIVE-CMD", StringComparison.OrdinalIgnoreCase) ||
                             (proto.Equals("ADB-STREAM", StringComparison.OrdinalIgnoreCase) && dir == "OUT");

        if (isRelevantAdb)
        {
            string ascii = Encoding.ASCII.GetString(raw.RawPayload).Trim('\0', '\r', '\n');
            string cmdText = raw.Metadata != null && raw.Metadata.TryGetValue("Command", out var cVal) && !string.IsNullOrWhiteSpace(cVal)
                ? cVal
                : (ascii.Length > 0 ? ascii : Convert.ToHexString(raw.RawPayload));

            if (!IsCleanPrintableOrHexCommand(cmdText))
                return;

            string activeShell = raw.Metadata != null && raw.Metadata.TryGetValue("ActiveShell", out var sh) && !string.IsNullOrWhiteSpace(sh)
                ? sh
                : "/data/local/tmp/AT";

            _eventSink(new SourceTelemetryEvent
            {
                ProcessId = 0,
                ThreadId = 0,
                Stage = SentinelStage.RawCommandExecution,
                HookedApiName = "WinUsbFilterAdbBridge",
                CallerModuleOrigin = $"WinUSB Kernel Filter -> {activeShell}",
                TargetResource = activeShell,
                CommandCategory = proto.Equals("ADB-RIL-IPC", StringComparison.OrdinalIgnoreCase) ? "ADB RIL / AT IPC Command" : "ADB / Interactive Shell",
                DecodedCommandText = $"أمر تفاعلي على السلك (USB {dir}): {cmdText}",
                PayloadSize = raw.RawPayload.Length,
                RawPayloadHex = Convert.ToHexString(raw.RawPayload.AsSpan(0, Math.Min(raw.RawPayload.Length, 256)))
            });
        }
    }

    public static bool IsCleanPrintableOrHexCommand(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return false;
        string trimmed = text.Trim();

        // Reject ELF binary stream headers or chunks with replacement '?' floods
        if (trimmed.Contains("ELF") && trimmed.Contains("DATA")) return false;
        int questionMarks = trimmed.Count(c => c == '?');
        if (questionMarks > 3 && (double)questionMarks / trimmed.Length > 0.08) return false;

        int nonPrintable = 0;
        foreach (char c in trimmed)
        {
            if (c < 0x20 && c != '\r' && c != '\n' && c != '\t') nonPrintable++;
            else if (c > 0x7E) nonPrintable++;
        }
        return (double)nonPrintable / trimmed.Length <= 0.10;
    }

    public void ReportInteractiveCommand(string commandText, string targetTool = "/data/local/tmp/AT", int pid = 0)
    {
        if (_isDisposed || string.IsNullOrWhiteSpace(commandText)) return;
        if (!IsCleanPrintableOrHexCommand(commandText)) return;

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
