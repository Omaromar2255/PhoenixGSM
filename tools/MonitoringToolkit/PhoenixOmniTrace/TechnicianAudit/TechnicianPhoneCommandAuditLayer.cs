using System;
using System.Text;
using System.Threading;
using PhoenixGSM.OmniTrace.Bus;
using PhoenixGSM.OmniTrace.Commands;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.TechnicianAudit;

/// <summary>
/// Dedicated Autonomous Layer for intercepting, normalizing, and persistently auditing
/// every command sent from the technician's computer to the client's mobile phone across
/// all phone modes and protocols (ADB, AT Modem, MTK BROM/DA, Qualcomm EDL 9008, Unisoc SPD, Apple iOS, Serial, USB URBs, etc.).
/// </summary>
public sealed class TechnicianPhoneCommandAuditLayer : IDisposable
{
    private readonly OmniTraceEventBus? _bus;
    private readonly TechnicianCommandAuditStore _store;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, TechnicianAuditRecord> _lastCommandByTarget = new(StringComparer.OrdinalIgnoreCase);
    private TechnicianAuditRecord? _lastGlobalCommand;
    private long _idCounter = 0;
    private bool _isDisposed;

    public TechnicianCommandAuditStore Store => _store;

    public event Action<TechnicianAuditRecord>? OnCommandAudited;

    /// <summary>
    /// Master toggle for the technician-to-client phone command audit layer.
    /// Disabled by default (false) so that no records or log files are created until explicitly needed.
    /// </summary>
    public bool IsEnabled { get; set; } = false;

    /// <summary>
    /// Optional toggle to capture, normalize, and persistently audit incoming responses from the client phone (DEVICE ➔ HOST).
    /// When enabled, both the outbound command sent to the phone and the incoming reply from the phone are recorded and logged.
    /// Default is false for pure outbound command auditing.
    /// </summary>
    public bool CaptureDeviceResponses { get; set; } = false;

    // Real-Time Counters
    public int TotalAuditedCount { get; private set; }
    public int OutboundCommandsCount { get; private set; }
    public int InboundResponsesCount { get; private set; }
    public int AdbCount { get; private set; }
    public int AtCount { get; private set; }
    public int MtkCount { get; private set; }
    public int EdlCount { get; private set; }
    public int SpdCount { get; private set; }
    public int AppleCount { get; private set; }
    public int FastbootCount { get; private set; }
    public int OtherCount { get; private set; }

    public TechnicianPhoneCommandAuditLayer(OmniTraceEventBus? bus = null, string? customLogDirectory = null, bool defaultEnabled = false)
    {
        _bus = bus;
        IsEnabled = defaultEnabled;
        _store = new TechnicianCommandAuditStore(customLogDirectory);

        if (_bus != null)
        {
            _bus.OnLogicalCommand += HandleLogicalCommand;
            _bus.OnRawCaptured += HandleRawPacket;
        }
    }

    /// <summary>
    /// Explicitly audit a command or payload known to be sent from the technician to the client phone.
    /// Used by kernel USB driver hooks, COM port monitors, and transparent proxies.
    /// </summary>
    public TechnicianAuditRecord? AuditOutboundCommand(
        string rawCommand,
        string protocol,
        string mode = "Normal",
        string targetDevice = "",
        string technicianTool = "Technician",
        int processId = 0,
        byte[]? payloadBytes = null,
        string technicalDetails = "")
    {
        if (!IsEnabled)
            return null;

        if (string.IsNullOrWhiteSpace(rawCommand) && (payloadBytes == null || payloadBytes.Length == 0))
            return null;

        string cleanCommand = NormalizeCommand(rawCommand, protocol, payloadBytes);
        if (string.IsNullOrWhiteSpace(cleanCommand))
            return null;

        byte[] rawBytes = payloadBytes ?? Encoding.UTF8.GetBytes(rawCommand);
        string hash = TechnicianAuditRecord.ComputeSha256(rawBytes);
        string risk = EvaluateRiskLevel(cleanCommand, protocol);
        string resolvedMode = ResolveDeviceMode(mode, protocol, cleanCommand);

        var record = new TechnicianAuditRecord
        {
            Id = Interlocked.Increment(ref _idCounter),
            Timestamp = DateTime.UtcNow,
            Protocol = protocol.ToUpperInvariant(),
            Mode = resolvedMode,
            PureCommand = cleanCommand,
            RawCommand = rawCommand,
            TargetDeviceOrPort = targetDevice,
            TechnicianTool = technicianTool,
            TechnicianProcessId = processId,
            Direction = "HOST ➔ DEVICE",
            IsResponse = false,
            RawBytes = rawBytes,
            HexPayload = FormatHex(rawBytes),
            Sha256Hash = hash,
            RiskLevel = risk,
            TechnicalDetails = technicalDetails
        };

        // Cache last command for response pairing
        _lastGlobalCommand = record;
        if (!string.IsNullOrEmpty(targetDevice))
        {
            _lastCommandByTarget[targetDevice] = record;
        }
        if (!string.IsNullOrEmpty(protocol))
        {
            _lastCommandByTarget[protocol] = record;
        }

        // Increment Statistics
        IncrementCounters(record.Protocol, isResponse: false);

        // 1. Save to disk immediately in background store
        _store.SaveRecord(record);

        // 2. Dispatch event to UI and listeners
        OnCommandAudited?.Invoke(record);

        return record;
    }

    /// <summary>
    /// Explicitly audit an incoming response or status payload received from the client mobile phone (Device to Host).
    /// Used by kernel USB driver hooks, COM port monitors, ADB proxy, and decoders when response capturing is enabled.
    /// </summary>
    public TechnicianAuditRecord? AuditInboundResponse(
        string rawResponse,
        string protocol,
        string mode = "Normal",
        string targetDevice = "",
        string technicianTool = "Phone",
        int processId = 0,
        byte[]? payloadBytes = null,
        string technicalDetails = "",
        long? relatedCommandId = null)
    {
        if (!IsEnabled)
            return null;

        if (string.IsNullOrWhiteSpace(rawResponse) && (payloadBytes == null || payloadBytes.Length == 0))
            return null;

        string cleanResponse = NormalizeResponse(rawResponse, protocol, payloadBytes);
        if (string.IsNullOrWhiteSpace(cleanResponse))
            return null;

        byte[] rawBytes = payloadBytes ?? Encoding.UTF8.GetBytes(rawResponse);
        string hash = TechnicianAuditRecord.ComputeSha256(rawBytes);
        string riskOrStatus = EvaluateResponseStatus(cleanResponse, protocol);
        string resolvedMode = ResolveDeviceMode(mode, protocol, cleanResponse);

        // Find related command if not explicitly supplied
        TechnicianAuditRecord? relatedCmd = null;
        if (relatedCommandId.HasValue)
        {
            if (_lastGlobalCommand?.Id == relatedCommandId.Value)
                relatedCmd = _lastGlobalCommand;
        }
        else
        {
            if (!string.IsNullOrEmpty(targetDevice) && _lastCommandByTarget.TryGetValue(targetDevice, out var cmdByTarget))
            {
                relatedCmd = cmdByTarget;
            }
            else if (!string.IsNullOrEmpty(protocol) && _lastCommandByTarget.TryGetValue(protocol, out var cmdByProto))
            {
                relatedCmd = cmdByProto;
            }
            else
            {
                relatedCmd = _lastGlobalCommand;
            }
        }

        if (technicianTool == "Phone" && relatedCmd != null && !string.IsNullOrEmpty(relatedCmd.TechnicianTool))
        {
            technicianTool = relatedCmd.TechnicianTool;
            if (processId == 0) processId = relatedCmd.TechnicianProcessId;
        }

        var record = new TechnicianAuditRecord
        {
            Id = Interlocked.Increment(ref _idCounter),
            Timestamp = DateTime.UtcNow,
            Protocol = protocol.ToUpperInvariant(),
            Mode = resolvedMode,
            PureCommand = cleanResponse,
            RawCommand = rawResponse,
            TargetDeviceOrPort = !string.IsNullOrEmpty(targetDevice) ? targetDevice : (relatedCmd?.TargetDeviceOrPort ?? ""),
            TechnicianTool = technicianTool,
            TechnicianProcessId = processId,
            Direction = "DEVICE ➔ HOST",
            IsResponse = true,
            RelatedCommandId = relatedCmd?.Id,
            RelatedCommandText = relatedCmd?.PureCommand,
            RawBytes = rawBytes,
            HexPayload = FormatHex(rawBytes),
            Sha256Hash = hash,
            RiskLevel = riskOrStatus,
            TechnicalDetails = technicalDetails
        };

        // If paired with a command, update that command's DeviceResponse property
        if (relatedCmd != null)
        {
            relatedCmd.DeviceResponse = cleanResponse;
            relatedCmd.ResponseTimestamp = record.Timestamp;
        }

        // Increment Statistics
        IncrementCounters(record.Protocol, isResponse: true);

        // 1. Save to disk immediately in background store
        _store.SaveRecord(record);

        // 2. Dispatch event to UI and listeners
        OnCommandAudited?.Invoke(record);

        return record;
    }

    private void HandleLogicalCommand(LogicalCommandEvent cmd)
    {
        if (cmd == null || !IsEnabled) return;

        // Discard internal sensor artifact/file notifications that are not real phone commands
        if (cmd.Command.StartsWith("[MODEM-DATA]", StringComparison.OrdinalIgnoreCase) ||
            cmd.Command.StartsWith("[ARTIFACT VAULT]", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        bool isOutbound = cmd.Direction == PacketDirection.HOST_TO_DEVICE ||
                          cmd.Command.StartsWith(">>") ||
                          cmd.Transport == TransportType.FILE;

        if (isOutbound)
        {
            // Discard host internal executions unrelated to client phone
            if (cmd.Protocol == KnownProtocol.InProcess && !cmd.Command.Contains("060100") && !cmd.Command.Contains("AT"))
                return;

            string protoName = DetermineProtocolName(cmd);
            string mode = DetermineDeviceModeFromCommand(cmd, protoName);
            string target = !string.IsNullOrEmpty(cmd.SessionIdentity) ? cmd.SessionIdentity : cmd.DeviceIdentity;
            string tool = cmd.Attribution?.ImageName ?? "Tool.exe";
            int pid = cmd.Attribution?.ProcessId ?? 0;

            AuditOutboundCommand(
                rawCommand: cmd.Command,
                protocol: protoName,
                mode: mode,
                targetDevice: target,
                technicianTool: tool,
                processId: pid,
                payloadBytes: null,
                technicalDetails: $"Service: {cmd.Service}; Transport: {cmd.Transport}; Evidence: {cmd.RawEvidenceSequences.Count} pkts");
        }
        else if (CaptureDeviceResponses)
        {
            bool isInbound = cmd.Direction == PacketDirection.DEVICE_TO_HOST ||
                             cmd.Command.StartsWith("<<");

            if (!isInbound) return;

            // Discard host internal executions
            if (cmd.Protocol == KnownProtocol.InProcess)
                return;

            string protoName = DetermineProtocolName(cmd);
            string mode = DetermineDeviceModeFromCommand(cmd, protoName);
            string target = !string.IsNullOrEmpty(cmd.SessionIdentity) ? cmd.SessionIdentity : cmd.DeviceIdentity;
            string tool = cmd.Attribution?.ImageName ?? "Phone";
            int pid = cmd.Attribution?.ProcessId ?? 0;

            AuditInboundResponse(
                rawResponse: cmd.Command,
                protocol: protoName,
                mode: mode,
                targetDevice: target,
                technicianTool: tool,
                processId: pid,
                payloadBytes: null,
                technicalDetails: $"Response to service: {cmd.Service}; Transport: {cmd.Transport}; Evidence: {cmd.RawEvidenceSequences.Count} pkts");
        }
    }

    private void HandleRawPacket(RawCaptureEvent raw)
    {
        if (raw == null || !IsEnabled || raw.RawPayload == null || raw.RawPayload.Length == 0) return;

        int pid = 0;
        if (raw.Metadata != null && raw.Metadata.TryGetValue("PID", out var pidStr))
        {
            int.TryParse(pidStr, out pid);
        }

        byte[] data = raw.RawPayload;
        string ascii = Encoding.ASCII.GetString(data).Trim('\0', '\r', '\n');

        if (raw.Direction == PacketDirection.HOST_TO_DEVICE)
        {
            // Check if raw USB Bulk OUT or Serial TX packet contains identifiable command signatures
            if (ascii.StartsWith("AT", StringComparison.OrdinalIgnoreCase))
            {
                AuditOutboundCommand(ascii, "AT-MODEM", "Modem / Diag", raw.DeviceIdentity ?? "COM", "Technician", pid, data);
            }
            else if (data.Length >= 4 && data[0] == 0xA0 && data[1] == 0x0A && data[2] == 0x50 && data[3] == 0x05)
            {
                AuditOutboundCommand("BROM_START_HANDSHAKE (0xA0 0x0A 0x50 0x05)", "MTK-BROM", "MTK BROM", raw.DeviceIdentity ?? "USB", "Technician", pid, data);
            }
            else if (ascii.Contains("<?xml") || ascii.Contains("<data>") || ascii.Contains("<program") || ascii.Contains("<patch"))
            {
                AuditOutboundCommand(ascii, "QCOM-FIREHOSE", "Qualcomm EDL 9008", raw.DeviceIdentity ?? "9008", "Technician", pid, data);
            }
            else if (ascii.StartsWith("FASTBOOT", StringComparison.OrdinalIgnoreCase))
            {
                AuditOutboundCommand(ascii, "FASTBOOT", "Fastboot", raw.DeviceIdentity ?? "USB", "Technician", pid, data);
            }
        }
        else if (CaptureDeviceResponses && raw.Direction == PacketDirection.DEVICE_TO_HOST)
        {
            // Check if raw USB Bulk IN or Serial RX packet contains identifiable response signatures
            if (ascii.StartsWith("OK", StringComparison.OrdinalIgnoreCase) ||
                ascii.StartsWith("ERROR", StringComparison.OrdinalIgnoreCase) ||
                ascii.StartsWith("+CME ERROR", StringComparison.OrdinalIgnoreCase) ||
                ascii.StartsWith("+CMS ERROR", StringComparison.OrdinalIgnoreCase) ||
                ascii.StartsWith("+CSQ:", StringComparison.OrdinalIgnoreCase) ||
                ascii.StartsWith("+CPIN:", StringComparison.OrdinalIgnoreCase) ||
                ascii.StartsWith("+CGMM:", StringComparison.OrdinalIgnoreCase) ||
                ascii.StartsWith("+GMM:", StringComparison.OrdinalIgnoreCase))
            {
                AuditInboundResponse(ascii, "AT-MODEM", "Modem / Diag", raw.DeviceIdentity ?? "COM", "Phone", pid, data);
            }
            else if (data.Length >= 4 && (
                (data[0] == 0x5F && data[1] == 0xF5 && data[2] == 0xAF && data[3] == 0xFA) ||
                (data[0] == 0x00 && data[1] == 0x01 && data[2] == 0x00 && data[3] == 0x00) ||
                data[0] == 0xC8))
            {
                string desc = (data[0] == 0xC8) ? "DA_STATUS_CONFIRM (0xC8)" : $"BROM_HANDSHAKE_ACK (0x{data[0]:X2} 0x{data[1]:X2})";
                AuditInboundResponse(desc, "MTK-BROM", "MTK BROM", raw.DeviceIdentity ?? "USB", "Phone", pid, data);
            }
            else if (ascii.StartsWith("OKAY", StringComparison.OrdinalIgnoreCase) ||
                     ascii.StartsWith("FAIL", StringComparison.OrdinalIgnoreCase) ||
                     ascii.StartsWith("INFO", StringComparison.OrdinalIgnoreCase) ||
                     ascii.StartsWith("DATA", StringComparison.OrdinalIgnoreCase))
            {
                AuditInboundResponse(ascii, "FASTBOOT", "Fastboot", raw.DeviceIdentity ?? "USB", "Phone", pid, data);
            }
            else if (ascii.Contains("<response") || ascii.Contains("<log value=") || (ascii.Contains("value=\"ACK\"") || ascii.Contains("value=\"NAK\"")))
            {
                AuditInboundResponse(ascii, "QCOM-FIREHOSE", "Qualcomm EDL 9008", raw.DeviceIdentity ?? "9008", "Phone", pid, data);
            }
            else if (data.Length >= 4 && data[0] == 0x02)
            {
                AuditInboundResponse("SAHARA_HELLO_RESP (0x02)", "QCOM-SAHARA", "Qualcomm EDL 9008", raw.DeviceIdentity ?? "9008", "Phone", pid, data);
            }
            else if (data.Length >= 4 && data[0] == 0x7E && (data.Length > 2 && data[2] == 0x80))
            {
                AuditInboundResponse("BSL_REP_ACK (0x80)", "SPD-FDL", "Unisoc FDL", raw.DeviceIdentity ?? "USB", "Phone", pid, data);
            }
        }
    }

    private string NormalizeCommand(string rawCommand, string protocol, byte[]? payloadBytes)
    {
        string cmd = (rawCommand ?? "").Trim();

        // 1. ADB Normalization
        if (protocol.Contains("ADB", StringComparison.OrdinalIgnoreCase))
        {
            if (cmd.StartsWith("OPEN -> shell:", StringComparison.OrdinalIgnoreCase))
                return cmd["OPEN -> shell:".Length..].Trim();
            if (cmd.StartsWith("OPEN -> exec:", StringComparison.OrdinalIgnoreCase))
                return cmd["OPEN -> exec:".Length..].Trim();
            if (cmd.StartsWith("OPEN shell:", StringComparison.OrdinalIgnoreCase))
                return cmd["OPEN shell:".Length..].Trim();
            if (cmd.StartsWith("shell:", StringComparison.OrdinalIgnoreCase))
                return cmd["shell:".Length..].Trim();
            if (cmd.StartsWith("OPEN -> ", StringComparison.OrdinalIgnoreCase))
                return cmd["OPEN -> ".Length..].Trim();
            if (cmd.StartsWith("WRTE -> ", StringComparison.OrdinalIgnoreCase))
                return cmd["WRTE -> ".Length..].Trim();
            if (cmd.StartsWith("WRTE", StringComparison.OrdinalIgnoreCase) && payloadBytes != null && payloadBytes.Length > 0)
                return Encoding.UTF8.GetString(payloadBytes).Trim('\0', '\r', '\n');
            if (cmd is "OKAY" or "CLSE" or "CNXN")
                return string.Empty; // Zero-action framing
        }

        // 2. AT Modem Normalization
        if (protocol.Contains("AT", StringComparison.OrdinalIgnoreCase))
        {
            if (cmd.StartsWith("[MODEM-USB] OUT: ", StringComparison.OrdinalIgnoreCase))
                cmd = cmd["[MODEM-USB] OUT: ".Length..].Trim();
            if (cmd is "<CR>" or "<LF>" or "<CRLF>")
                return string.Empty;
        }

        // 3. Fastboot Normalization
        if (protocol.Contains("FASTBOOT", StringComparison.OrdinalIgnoreCase))
        {
            if (cmd.StartsWith("FASTBOOT: ", StringComparison.OrdinalIgnoreCase))
                return cmd["FASTBOOT: ".Length..].Trim();
            if (cmd.StartsWith("FASTBOOT ", StringComparison.OrdinalIgnoreCase))
                return cmd["FASTBOOT ".Length..].Trim();
        }

        // 4. Shell / Script Cleanups
        if (cmd.StartsWith(">>", StringComparison.OrdinalIgnoreCase))
            cmd = cmd[2..].Trim();

        return cmd;
    }

    private string DetermineProtocolName(LogicalCommandEvent cmd)
    {
        return cmd.Protocol switch
        {
            KnownProtocol.ADB => "ADB-SHELL",
            KnownProtocol.Fastboot => "FASTBOOT",
            KnownProtocol.SerialAt when cmd.Transport == TransportType.FILE => "STAGED-AT",
            KnownProtocol.SerialAt => "AT-MODEM",
            KnownProtocol.MtkBrom => "MTK-BROM",
            KnownProtocol.MtkDa => "MTK-DA",
            KnownProtocol.SpreadtrumFdl => "SPD-FDL",
            KnownProtocol.QualcommSahara => "QCOM-SAHARA",
            KnownProtocol.QualcommFirehose => "QCOM-FIREHOSE",
            KnownProtocol.AppleDfu => "APPLE-DFU",
            KnownProtocol.AppleRecovery => "APPLE-RECOVERY",
            KnownProtocol.AppleLockdown => "APPLE-LOCKDOWN",
            KnownProtocol.AppleRamdiskSsh => "APPLE-RAMDISK",
            KnownProtocol.ApplePurpleDiag => "APPLE-DIAG",
            KnownProtocol.HostCommand when cmd.Command.Contains("fastboot", StringComparison.OrdinalIgnoreCase) => "FASTBOOT",
            KnownProtocol.HostCommand => "CLI-EXEC",
            _ => cmd.Protocol.ToString().ToUpperInvariant()
        };
    }

    private string DetermineDeviceModeFromCommand(LogicalCommandEvent cmd, string proto)
    {
        if (proto.Contains("FASTBOOT") || cmd.Command.Contains("fastboot", StringComparison.OrdinalIgnoreCase))
            return "Fastboot";
        if (proto.Contains("BROM")) return "MTK BROM";
        if (proto.Contains("MTK-DA")) return "MTK Preloader";
        if (proto.Contains("QCOM") || proto.Contains("FIREHOSE") || proto.Contains("SAHARA")) return "Qualcomm EDL 9008";
        if (proto.Contains("SPD") || proto.Contains("FDL")) return "Unisoc FDL";
        if (proto.Contains("DFU")) return "Apple DFU";
        if (proto.Contains("RECOVERY")) return "Apple Recovery";
        if (proto.Contains("AT")) return "Modem / Diag";
        if (cmd.Command.Contains("reboot recovery", StringComparison.OrdinalIgnoreCase)) return "Rebooting -> Recovery";
        if (cmd.Command.Contains("reboot bootloader", StringComparison.OrdinalIgnoreCase)) return "Rebooting -> Bootloader";

        return "Normal / ADB";
    }

    private string ResolveDeviceMode(string mode, string protocol, string command)
    {
        if (!string.IsNullOrWhiteSpace(mode) && mode != "Normal") return mode;
        if (protocol.Contains("FASTBOOT")) return "Fastboot";
        if (protocol.Contains("BROM")) return "MTK BROM";
        if (protocol.Contains("MTK")) return "MTK Preloader";
        if (protocol.Contains("EDL") || protocol.Contains("QCOM") || protocol.Contains("FIREHOSE")) return "Qualcomm EDL 9008";
        if (protocol.Contains("SPD") || protocol.Contains("FDL")) return "Unisoc FDL";
        if (protocol.Contains("DFU")) return "Apple DFU";
        if (protocol.Contains("RECOVERY")) return "Apple Recovery";
        if (protocol.Contains("AT")) return "Modem / Diag";
        if (command.Contains("reboot recovery", StringComparison.OrdinalIgnoreCase)) return "Recovery Mode";
        if (command.Contains("reboot bootloader", StringComparison.OrdinalIgnoreCase)) return "Bootloader Mode";
        return "Normal / ADB";
    }

    private string EvaluateRiskLevel(string cleanCommand, string protocol)
    {
        string c = cleanCommand.ToLowerInvariant();
        if (c.Contains("frp") || c.Contains("bypass") || c.Contains("remove") || c.Contains("erase") || c.Contains("unlock"))
            return "FRP / BYPASS";
        if (c.Contains("flash") || c.Contains("write") || c.Contains("format") || c.Contains("<program") || c.Contains("download"))
            return "PARTITION WRITE";
        if (c.Contains("root") || c.Contains("su") || c.Contains("chmod 777") || c.Contains("exploit") || c.Contains("checkm8"))
            return "ROOT / EXPLOIT";
        if (c.Contains("bootloader") || c.Contains("oem unlock") || c.Contains("da_jump"))
            return "BOOTLOADER";
        if (c.Contains("reboot"))
            return "REBOOT";
        if (c.Contains("shell") || c.Contains("pm ") || c.Contains("am ") || c.Contains("setprop"))
            return "SHELL EXEC";

        return "INFO / READ";
    }

    public string NormalizeResponse(string rawResponse, string protocol, byte[]? payloadBytes)
    {
        string resp = (rawResponse ?? "").Trim();

        if (resp.StartsWith("<<", StringComparison.OrdinalIgnoreCase))
            resp = resp[2..].Trim();

        // 1. ADB Shell STDOUT Normalization
        if (protocol.Contains("ADB", StringComparison.OrdinalIgnoreCase))
        {
            if (resp.StartsWith("WRTE -> ", StringComparison.OrdinalIgnoreCase))
                resp = resp["WRTE -> ".Length..].Trim();
            if (resp.StartsWith("WRTE", StringComparison.OrdinalIgnoreCase) && payloadBytes != null && payloadBytes.Length > 0)
                return Encoding.UTF8.GetString(payloadBytes).Trim('\0', '\r', '\n');
            if (resp is "OKAY" or "CLSE" or "CNXN")
                return resp;
        }

        // 2. AT Modem Normalization
        if (protocol.Contains("AT", StringComparison.OrdinalIgnoreCase))
        {
            if (resp.StartsWith("[MODEM-USB] IN: ", StringComparison.OrdinalIgnoreCase))
                resp = resp["[MODEM-USB] IN: ".Length..].Trim();
            if (resp is "<CR>" or "<LF>" or "<CRLF>")
                return string.Empty;
        }

        // 3. Fastboot Normalization
        if (protocol.Contains("FASTBOOT", StringComparison.OrdinalIgnoreCase))
        {
            if (resp.StartsWith("FASTBOOT: ", StringComparison.OrdinalIgnoreCase))
                resp = resp["FASTBOOT: ".Length..].Trim();
            if (resp.StartsWith("FASTBOOT ", StringComparison.OrdinalIgnoreCase))
                resp = resp["FASTBOOT ".Length..].Trim();
        }

        return resp.Trim('\r', '\n', '\0', ' ');
    }

    private string EvaluateResponseStatus(string cleanResponse, string protocol)
    {
        string r = cleanResponse.ToLowerInvariant();
        if (r.StartsWith("fail") || r.Contains("error") || r.Contains("failed") || r.Contains("value=\"nak\"") || r.Contains("denied") || r.Contains("not support"))
            return "ERROR / FAIL";
        if (r.Contains("uid=0") || r.Contains("root") || r.Contains("context=u:r:su") || r.Contains("/su") || r.StartsWith("su ") || r.Contains(" su ") || r.Equals("su") || r.Contains("unlocked: yes"))
            return "ROOT / PRIVILEGED";
        if (r.StartsWith("okay") || r.Equals("ok") || r.EndsWith("ok") || r.Contains("\nok") || r.Contains("\rok") || r.Contains("success") || r.Contains("da_status_ok") || r.Contains("ack") || r.Contains("value=\"ack\"") || r.Contains("bsl_rep_ack"))
            return "SUCCESS / OK";
        if (r.Contains("ro.") || r.Contains("version") || r.Contains("model") || r.Contains("csq") || r.Contains("cpin") || r.Contains("serialno"))
            return "DEVICE INFO";

        return "DATA / RESP";
    }

    private void IncrementCounters(string protocol, bool isResponse = false)
    {
        TotalAuditedCount++;
        if (isResponse)
            InboundResponsesCount++;
        else
            OutboundCommandsCount++;

        string p = protocol.ToUpperInvariant();
        if (p.Contains("ADB") || p.Contains("SHELL")) AdbCount++;
        else if (p.Contains("AT")) AtCount++;
        else if (p.Contains("MTK")) MtkCount++;
        else if (p.Contains("EDL") || p.Contains("QCOM") || p.Contains("FIREHOSE") || p.Contains("SAHARA")) EdlCount++;
        else if (p.Contains("SPD") || p.Contains("FDL")) SpdCount++;
        else if (p.Contains("APPLE")) AppleCount++;
        else if (p.Contains("FASTBOOT")) FastbootCount++;
        else OtherCount++;
    }

    private static string FormatHex(byte[] data)
    {
        if (data == null || data.Length == 0) return string.Empty;
        var sb = new StringBuilder();
        int max = Math.Min(data.Length, 65536);
        for (int i = 0; i < max; i++)
        {
            sb.Append($"{data[i]:X2} ");
            if ((i + 1) % 16 == 0) sb.Append("\n");
        }
        if (data.Length > max) sb.Append($"... [{data.Length - max:N0} more bytes - Total size: {data.Length:N0} bytes]");
        return sb.ToString().TrimEnd();
    }

    public void Flush()
    {
        _store.Flush();
    }

    public void Dispose()
    {
        if (_isDisposed) return;
        _isDisposed = true;

        if (_bus != null)
        {
            _bus.OnLogicalCommand -= HandleLogicalCommand;
            _bus.OnRawCaptured -= HandleRawPacket;
        }

        _store.Flush();
        _store.Dispose();
    }
}
