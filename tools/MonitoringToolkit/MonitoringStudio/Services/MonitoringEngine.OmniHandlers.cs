using System;
using System.IO;
using System.Linq;
using System.Text;
using PhoenixGSM.MonitoringStudio.Models;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.MonitoringStudio.Services;

public partial class MonitoringEngine
{
    private void HandleOmniCommand(LogicalCommandEvent cmd)
    {
        // 0. Prevent duplicate UI emission for commands already emitted directly by KernelDriver
        if (cmd.Details.TryGetValue("EmittedByKernelDriver", out var emittedByKd) && emittedByKd == "true")
        {
            return;
        }

        // 1. Suppress dumb SUBPROCESS_EXECUTION without actual command
        if (cmd.Command.Equals("SUBPROCESS_EXECUTION", StringComparison.OrdinalIgnoreCase))
        {
            bool hasValidCli = cmd.Details.TryGetValue("CommandLine", out var cli) &&
                               !string.IsNullOrWhiteSpace(cli) &&
                               !cli.Equals("SUBPROCESS_EXECUTION", StringComparison.OrdinalIgnoreCase);
            if (!hasValidCli)
            {
                return;
            }
        }

        // 2. Suppress background noise processes in InProcess/Process events
        if (cmd.Protocol == KnownProtocol.InProcess)
        {
            string caller = cmd.Details.TryGetValue("Caller", out var clr) ? clr : (cmd.Attribution?.ImageName ?? "");
            if (ExcludedNoiseProcesses.Any(np => caller.Contains(np, StringComparison.OrdinalIgnoreCase)))
            {
                return;
            }
        }

        // 3. Filter empty or duplicate WMIC hardware queries
        if (cmd.Details.TryGetValue("ProtocolName", out var protoName) && protoName == "WMIC")
        {
            cmd.Details.TryGetValue("CommandLine", out var wmicCli);
            if (ShouldFilterWmicQuery(wmicCli, cmd.Command))
                return;
        }

        bool isStreamIn = cmd.Command.StartsWith("<<");
        bool isStreamOut = cmd.Command.StartsWith(">>");

        // 4. Suppress SUB-STREAM events merging raw WRTE, CLSE, OKAY, OPEN, CNXN headers
        if (isStreamOut || isStreamIn)
        {
            string cleanCmd = cmd.Command.TrimStart('<', '>', ' ');
            if (cleanCmd.StartsWith("WRTE") || cleanCmd.StartsWith("CLSE") ||
                cleanCmd.StartsWith("OKAY") || cleanCmd.StartsWith("OPEN") ||
                cleanCmd.StartsWith("CNXN"))
            {
                return;
            }
        }

        string evidenceHashes = string.Join(", ", cmd.EvidenceHashes.Select(h => h.Length > 8 ? h[..8] : h));

        EventSourceCategory category;
        if (cmd.Details.TryGetValue("Category", out var customCatStr) &&
            Enum.TryParse<EventSourceCategory>(customCatStr, true, out var parsedCat))
        {
            category = parsedCat;
        }
        else
        {
            category = cmd.Protocol switch
            {
                KnownProtocol.SerialAt when cmd.Transport == TransportType.FILE => EventSourceCategory.TempFileAt,
                KnownProtocol.SerialAt => EventSourceCategory.SerialPort,
                KnownProtocol.Mtp or KnownProtocol.Ptp => EventSourceCategory.Mtp,
                KnownProtocol.MtkBrom or KnownProtocol.MtkDa => EventSourceCategory.MediaTek,
                KnownProtocol.SpreadtrumFdl => EventSourceCategory.UnisocSpd,
                KnownProtocol.QualcommSahara or KnownProtocol.QualcommFirehose => EventSourceCategory.QualcommEdl,
                KnownProtocol.HostCommand => EventSourceCategory.Cmd,
                KnownProtocol.InProcess => EventSourceCategory.InProcess,
                KnownProtocol.AppleUsbmuxd or
                KnownProtocol.AppleLockdown or
                KnownProtocol.AppleRecovery or
                KnownProtocol.AppleDfu or
                KnownProtocol.AppleRamdiskSsh or
                KnownProtocol.ApplePurpleDiag => EventSourceCategory.AppleIos,
                _ => EventSourceCategory.AdbProxy
            };
        }

        string sourceTag;
        if (cmd.Details.TryGetValue("SourceTag", out var customTag) && !string.IsNullOrWhiteSpace(customTag))
        {
            sourceTag = customTag;
        }
        else
        {
            sourceTag = cmd.Protocol switch
            {
                KnownProtocol.SerialAt when cmd.Transport == TransportType.FILE => "TEMP-AT",
                KnownProtocol.SerialAt => "SERIAL-AT",
                KnownProtocol.Mtp or KnownProtocol.Ptp => "MTP",
                KnownProtocol.MtkBrom => "MTK-BROM",
                KnownProtocol.MtkDa => "MTK-DA",
                KnownProtocol.SpreadtrumFdl => "SPD-FDL",
                KnownProtocol.QualcommSahara => "EDL-SAHARA",
                KnownProtocol.QualcommFirehose => "EDL-FIREHOSE",
                KnownProtocol.AppleUsbmuxd => "APPLE-MUX",
                KnownProtocol.AppleLockdown => "APPLE-LOCK",
                KnownProtocol.AppleRecovery => "APPLE-REC",
                KnownProtocol.AppleDfu => "APPLE-DFU",
                KnownProtocol.AppleRamdiskSsh => "APPLE-SSH",
                KnownProtocol.ApplePurpleDiag => "APPLE-DIAG",
                KnownProtocol.HostCommand => "CMD/SHELL",
                KnownProtocol.InProcess => "IN-PROCESS",
                _ when isStreamOut => "STREAM >>",
                _ when isStreamIn => "STREAM <<",
                _ => "OMNITRACE"
            };
        }

        string endpointOrTarget;
        if (!string.IsNullOrEmpty(cmd.Service) && 
            (cmd.Service.Contains("/data/local/tmp") || cmd.Service.Contains("athun") || cmd.Service.Contains("trd") || cmd.Service.Contains("su") || cmd.Service.Contains("chmod")))
        {
            endpointOrTarget = cmd.Service.StartsWith("shell:", StringComparison.OrdinalIgnoreCase)
                ? cmd.Service["shell:".Length..].Trim()
                : (cmd.Service.StartsWith("exec:", StringComparison.OrdinalIgnoreCase)
                    ? cmd.Service["exec:".Length..].Trim()
                    : cmd.Service.Trim());
        }
        else if (cmd.Protocol == KnownProtocol.Mtp)
        {
            endpointOrTarget = "MTP / Media Device";
        }
        else if (cmd.Protocol is KnownProtocol.MtkBrom or KnownProtocol.MtkDa)
        {
            endpointOrTarget = cmd.Details.TryGetValue("Chipset", out var cs) ? cs : (!string.IsNullOrEmpty(cmd.DeviceIdentity) ? cmd.DeviceIdentity : "MediaTek Device");
        }
        else if (cmd.Protocol == KnownProtocol.SpreadtrumFdl)
        {
            endpointOrTarget = cmd.Details.TryGetValue("ChipVersion", out var cv) ? cv : (!string.IsNullOrEmpty(cmd.DeviceIdentity) ? cmd.DeviceIdentity : "Unisoc / Spreadtrum");
        }
        else if (cmd.Protocol is KnownProtocol.QualcommSahara or KnownProtocol.QualcommFirehose)
        {
            endpointOrTarget = cmd.Details.TryGetValue("MemoryType", out var mt) ? $"Qualcomm 9008 ({mt})" : (!string.IsNullOrEmpty(cmd.DeviceIdentity) ? cmd.DeviceIdentity : "Qualcomm EDL (9008)");
        }
        else if (cmd.Protocol == KnownProtocol.SerialAt)
        {
            if (cmd.Transport == TransportType.FILE)
            {
                if (!string.IsNullOrEmpty(cmd.SessionIdentity) && cmd.SessionIdentity.StartsWith("TEMP_AT_", StringComparison.OrdinalIgnoreCase))
                {
                    endpointOrTarget = cmd.SessionIdentity["TEMP_AT_".Length..];
                }
                else
                {
                    endpointOrTarget = Path.GetFileName(cmd.DeviceIdentity);
                }
            }
            else if (!string.IsNullOrEmpty(cmd.SessionIdentity) && cmd.SessionIdentity.StartsWith("SERIAL_", StringComparison.OrdinalIgnoreCase))
            {
                endpointOrTarget = cmd.SessionIdentity["SERIAL_".Length..];
            }
            else if (!string.IsNullOrEmpty(cmd.DeviceIdentity) && cmd.DeviceIdentity.StartsWith("SERIAL\\", StringComparison.OrdinalIgnoreCase))
            {
                endpointOrTarget = cmd.DeviceIdentity["SERIAL\\".Length..];
            }
            else
            {
                endpointOrTarget = !string.IsNullOrEmpty(cmd.SessionIdentity) ? cmd.SessionIdentity : cmd.DeviceIdentity;
            }
        }
        else if (cmd.Details.TryGetValue("Caller", out var caller) && !string.IsNullOrWhiteSpace(caller))
        {
            endpointOrTarget = caller;
        }
        else
        {
            endpointOrTarget = string.IsNullOrEmpty(cmd.SessionIdentity) ? cmd.DeviceIdentity : $"{cmd.DeviceIdentity}:{cmd.SessionIdentity}";
        }

        string dir;
        if (cmd.Transport == TransportType.FILE)
        {
            dir = "FILE >>";
        }
        else if (isStreamOut)
        {
            dir = ">>";
        }
        else if (isStreamIn)
        {
            dir = "<<";
        }
        else
        {
            dir = cmd.Direction == PacketDirection.HOST_TO_DEVICE ? "OUT" : "IN";
        }

        string proto = cmd.Details.TryGetValue("ProtocolName", out var pName) && !string.IsNullOrWhiteSpace(pName)
            ? pName
            : (cmd.Transport == TransportType.FILE
                ? "STAGED-AT"
                : ((isStreamOut || isStreamIn) ? "SUB-STREAM" : cmd.Protocol.ToString().ToUpperInvariant()));

        string summary;
        if (cmd.Details.TryGetValue("Summary", out var customSummary) && !string.IsNullOrWhiteSpace(customSummary))
        {
            summary = customSummary;
        }
        else if (cmd.Transport == TransportType.FILE)
        {
            summary = $"[{cmd.Attribution?.ImageName ?? "Tool.exe"}] Staged AT: {cmd.Command}";
        }
        else if (isStreamOut || isStreamIn)
        {
            summary = $"[{sourceTag}] [{endpointOrTarget}] {cmd.Command}";
        }
        else
        {
            summary = $"[{cmd.Protocol}] {cmd.Command} ({cmd.Confidence:P0} conf)";
        }

        string payloadAscii;
        string additionalDetails;
        if (cmd.Details.TryGetValue("TechnicalDetails", out var customDetails) && !string.IsNullOrWhiteSpace(customDetails))
        {
            payloadAscii = customDetails;
            additionalDetails = customDetails;
        }
        else if (cmd.Transport == TransportType.FILE)
        {
            payloadAscii = $"Staged AT Command: {cmd.Command}\nCreator: {cmd.Attribution?.ImageName ?? "Tool.exe"} (PID {cmd.Attribution?.ProcessId})\nSource File: {cmd.DeviceIdentity}\nService: {cmd.Service}\nConfidence: {cmd.Confidence:P2}\nTarget Hint: USB Modem Interface";
            additionalDetails = $"Active Target: {endpointOrTarget}\nService: {cmd.Service}\nDirection: {dir}\nTimestamp: {cmd.Timestamp:O}\nEvidence Packets: {cmd.RawEvidenceSequences.Count}\nEvidence Hashes: {string.Join(", ", cmd.EvidenceHashes)}";
        }
        else
        {
            payloadAscii = $"Command / Stream: {cmd.Command}\nTarget / Service: {cmd.Service}\nDevice: {cmd.DeviceIdentity}\nConfidence: {cmd.Confidence:P2}\nHashes: {evidenceHashes}";
            additionalDetails = $"Active Target: {endpointOrTarget}\nService: {cmd.Service}\nDirection: {dir}\nTimestamp: {cmd.Timestamp:O}\nEvidence Packets: {cmd.RawEvidenceSequences.Count}\nEvidence Hashes: {string.Join(", ", cmd.EvidenceHashes)}";
        }

        byte[] payloadBytes = cmd.Details.TryGetValue("CommandLine", out var rawCmd) && !string.IsNullOrWhiteSpace(rawCmd)
            ? Encoding.UTF8.GetBytes(rawCmd)
            : Encoding.UTF8.GetBytes(cmd.Command);

        if (cmd.Details.TryGetValue("CommandLine", out var cliText) && !string.IsNullOrWhiteSpace(cliText))
        {
            string exePath = cmd.Details.TryGetValue("ExecutablePath", out var ep) ? ep : "";
            string callerName = cmd.Details.TryGetValue("Caller", out var c) ? c : "";
            CheckAndEmitUrls(cliText, exePath, callerName, cmd.Timestamp.UtcDateTime);
        }

        if (cmd.Service.Equals("iproxy.exe", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                int.TryParse(cmd.Details.TryGetValue("PID", out var p) ? p : "0", out int iproxyPid);
                _omniService?.RamdiskWatcher.OnIproxyLaunched(iproxyPid, 0,
                    cmd.Details.TryGetValue("CommandLine", out var cl) ? cl : "",
                    cmd.Details.TryGetValue("Caller", out var cal) ? cal : "",
                    cmd.Details.TryGetValue("ExecutablePath", out var ep2) ? ep2 : "");
            }
            catch { }
        }

        EmitEvent(new LiveEventItem
        {
            Timestamp = cmd.Timestamp.UtcDateTime,
            Category = category,
            SourceTag = sourceTag,
            Direction = dir,
            EndpointOrTarget = endpointOrTarget,
            Protocol = proto,
            Command = cmd.Command,
            Summary = summary,
            RawPayload = payloadBytes,
            PayloadAscii = payloadAscii,
            PayloadHex = LiveEventItem.FormatHexDump(payloadBytes),
            AdditionalDetails = additionalDetails
        });
    }

    private void HandleOmniRaw(RawCaptureEvent raw)
    {
        if (raw.Sensor == SensorType.VirtualProxy) return;
        if (raw.Sensor == SensorType.Serial) return;
        if (raw.Metadata != null && raw.Metadata.TryGetValue("Source", out var src) && src.StartsWith("KernelDriver", StringComparison.OrdinalIgnoreCase)) return;
        if (raw.Sensor == SensorType.USB) return;
        if (raw.Sensor == SensorType.Network) return;
        if (raw.Sensor == SensorType.FileSystem) return;
        if (raw.Direction == PacketDirection.INTERNAL) return;
        if (raw.Metadata != null && raw.Metadata.TryGetValue("ExecutionType", out var execType) && execType == "InProcessDirect") return;

        if (raw.RawPayload == null || raw.RawPayload.Length == 0) return;

        var category = raw.Sensor switch
        {
            SensorType.Serial => EventSourceCategory.SerialPort,
            SensorType.Process => EventSourceCategory.Process,
            SensorType.VirtualProxy => EventSourceCategory.AdbProxy,
            SensorType.FileSystem => EventSourceCategory.TempFileAt,
            _ => EventSourceCategory.UsbDriver
        };

        string dir = raw.Direction == PacketDirection.HOST_TO_DEVICE ? "OUT" : "IN";
        string target;
        if (raw.Sensor == SensorType.Serial)
        {
            target = !string.IsNullOrEmpty(raw.Endpoint) ? raw.Endpoint : raw.DeviceIdentity;
        }
        else
        {
            target = string.IsNullOrEmpty(raw.DeviceIdentity) || raw.DeviceIdentity.Equals("USB_UNKNOWN", StringComparison.OrdinalIgnoreCase)
                ? (raw.Metadata != null && raw.Metadata.TryGetValue("ProcessName", out var proc) ? $"{proc}:{raw.Endpoint}" : $"USB:{raw.Endpoint}")
                : $"{raw.DeviceIdentity}:{raw.Endpoint}";
        }

        EmitEvent(new LiveEventItem
        {
            Category = category,
            SourceTag = $"OMNI-{raw.Sensor}",
            Direction = dir,
            EndpointOrTarget = target,
            Protocol = raw.Transport.ToString().ToUpperInvariant(),
            Command = $"RAW #{raw.SequenceNumber}",
            Summary = $"{raw.Sensor} transfer ({raw.Length}B, SHA: {(raw.PayloadHash.Length > 8 ? raw.PayloadHash[..8] : raw.PayloadHash)})",
            RawPayload = raw.RawPayload,
            PayloadAscii = Encoding.UTF8.GetString(raw.RawPayload),
            PayloadHex = LiveEventItem.FormatHexDump(raw.RawPayload),
            AdditionalDetails = $"Sensor: {raw.Sensor}\nTransport: {raw.Transport}\nHash: {raw.PayloadHash}\nSession: {raw.SessionIdentity}"
        });
    }
}
