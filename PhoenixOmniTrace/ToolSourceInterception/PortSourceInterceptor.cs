using System;
using System.Text;
using System.Text.RegularExpressions;

namespace PhoenixGSM.OmniTrace.ToolSourceInterception;

/// <summary>
/// Specialized interceptor for Port / COM / Serial and Modem AT commands
/// captured directly from the tool's process via WriteFile or DeviceIoControl on COM handles.
/// فاحص ومفكك أوامر المنافذ التسلسلية وأوامر AT للمودم من المصدر مباشرة
/// </summary>
public static class PortSourceInterceptor
{
    private static readonly Regex AtCommandRegex = new(
        @"(AT[A-Z0-9\+\^\%\$\#\*\?\=\,\""\:\s]+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static bool TryParsePortCommand(
        byte[] payload,
        string toolName,
        int pid,
        int parentPid,
        string endpoint,
        string mechanism,
        out ToolSourceCommandRecord? record)
    {
        record = null;
        if (payload == null || payload.Length == 0) return false;

        string text = Encoding.UTF8.GetString(payload).Trim('\0', '\r', '\n', ' ');

        // 1. Text-based AT Commands
        var match = AtCommandRegex.Match(text);
        if (match.Success || text.StartsWith("AT", StringComparison.OrdinalIgnoreCase))
        {
            string pureCmd = match.Success ? match.Groups[1].Value.Trim() : text;
            string risk = EvaluateAtRisk(pureCmd);
            string opCategory = CategorizeAtCommand(pureCmd);

            var sb = new StringBuilder();
            sb.AppendLine("Modem / Serial Port AT Command Execution");
            sb.AppendLine($"Tool: {toolName} (PID {pid}, Parent PID {parentPid})");
            sb.AppendLine($"Target Port: {endpoint}");
            sb.AppendLine($"Classification: {opCategory}");
            sb.AppendLine($"Full Command String: {pureCmd}");
            sb.AppendLine($"Capture Vector: {mechanism}");

            record = new ToolSourceCommandRecord
            {
                Timestamp = DateTime.UtcNow,
                Mode = ToolSourceMode.SerialPort,
                ToolName = toolName,
                ProcessId = pid,
                ParentProcessId = parentPid,
                PureCommand = pureCmd,
                RawCommand = text,
                InterceptMechanism = mechanism,
                TargetEndpoint = string.IsNullOrWhiteSpace(endpoint) ? "\\\\.\\COM_MODEM" : endpoint,
                RawPayload = payload,
                PayloadHex = ToolSourceCommandRecord.FormatHexDump(payload),
                PayloadAscii = pureCmd,
                TechnicalDetails = sb.ToString(),
                RiskLevel = risk,
                Status = "CAPTURED_AT_SOURCE"
            };

            return true;
        }

        // 2. Qualcomm Diag HDLC Packet Framing (0x7E ... 0x7E)
        if (payload.Length >= 4 && payload[0] == 0x7E && payload[^1] == 0x7E)
        {
            byte diagCmd = payload[1];
            string diagName = ResolveQualcommDiagCommand(diagCmd);

            var sb = new StringBuilder();
            sb.AppendLine("Qualcomm Diag HDLC Serial Frame");
            sb.AppendLine($"Tool: {toolName} (PID {pid})");
            sb.AppendLine($"Diag Command Code: 0x{diagCmd:X2} ({diagName})");
            sb.AppendLine($"Target Port: {endpoint}");
            sb.AppendLine($"Frame Length: {payload.Length} bytes");

            string risk = diagCmd == 0x4B || diagCmd == 0x26 ? "CRITICAL" : "WARNING";

            record = new ToolSourceCommandRecord
            {
                Timestamp = DateTime.UtcNow,
                Mode = ToolSourceMode.SerialPort,
                ToolName = toolName,
                ProcessId = pid,
                ParentProcessId = parentPid,
                PureCommand = $"QCOM_DIAG: {diagName} (0x{diagCmd:X2})",
                RawCommand = $"HDLC 0x7E Cmd=0x{diagCmd:X2} Len={payload.Length}",
                InterceptMechanism = mechanism,
                TargetEndpoint = string.IsNullOrWhiteSpace(endpoint) ? "\\\\.\\COM_DIAG" : endpoint,
                RawPayload = payload,
                PayloadHex = ToolSourceCommandRecord.FormatHexDump(payload),
                PayloadAscii = Encoding.ASCII.GetString(payload.Length > 128 ? payload[..128] : payload),
                TechnicalDetails = sb.ToString(),
                RiskLevel = risk,
                Status = "CAPTURED_AT_SOURCE"
            };

            return true;
        }

        // 3. Fallback for generic port data directed to COM port handle
        if (endpoint.Contains("COM", StringComparison.OrdinalIgnoreCase) && payload.Length > 0)
        {
            string shortAscii = Encoding.ASCII.GetString(payload.Length > 80 ? payload[..80] : payload);
            record = new ToolSourceCommandRecord
            {
                Timestamp = DateTime.UtcNow,
                Mode = ToolSourceMode.SerialPort,
                ToolName = toolName,
                ProcessId = pid,
                ParentProcessId = parentPid,
                PureCommand = $"PORT_RAW_WRITE ({payload.Length} bytes): {shortAscii.Trim()}",
                RawCommand = shortAscii.Trim(),
                InterceptMechanism = mechanism,
                TargetEndpoint = endpoint,
                RawPayload = payload,
                PayloadHex = ToolSourceCommandRecord.FormatHexDump(payload),
                PayloadAscii = shortAscii,
                TechnicalDetails = $"Serial Port RAW stream written by {toolName} (PID {pid}) to {endpoint}.",
                RiskLevel = "INFO",
                Status = "CAPTURED_AT_SOURCE"
            };
            return true;
        }

        return false;
    }

    private static string EvaluateAtRisk(string cmd)
    {
        string upper = cmd.ToUpperInvariant();
        if (upper.Contains("FACTORST") || upper.Contains("FORMAT") || upper.Contains("WIPE")) return "CRITICAL";
        if (upper.Contains("EGMR=1,7") || upper.Contains("EGMR=1,10")) return "CRITICAL"; // IMEI repair
        if (upper.Contains("MSL") || upper.Contains("DATALOCK") || upper.Contains("CLCK")) return "CRITICAL"; // SIM unlock
        if (upper.Contains("PRECONFG") || upper.Contains("SWVER") || upper.Contains("KSTRING")) return "WARNING";
        return "INFO";
    }

    private static string CategorizeAtCommand(string cmd)
    {
        string upper = cmd.ToUpperInvariant();
        if (upper.Contains("FACTORST")) return "Samsung Factory Reset / FRP Bypass";
        if (upper.Contains("EGMR")) return "MediaTek IMEI Modification / Repair";
        if (upper.Contains("MSL")) return "Samsung MSL Security Bypass";
        if (upper.Contains("CLCK")) return "SIM Lock / Carrier Lock Manipulation";
        if (upper.Contains("DATALOCK")) return "Huawei DataLock Security Bypass";
        if (upper.Contains("CGSN")) return "Device IMEI Query";
        if (upper.Contains("PRECONFG")) return "CSC / Region Configuration Change";
        if (upper.Contains("DEVCONINFO")) return "Device Hardware Information Query";
        return "Standard / Proprietary Modem AT Command";
    }

    private static string ResolveQualcommDiagCommand(byte cmd)
    {
        return cmd switch
        {
            0x00 => "DIAG_VERNO_F (Version Number)",
            0x0C => "DIAG_CONTROL_F (Mode Control)",
            0x26 => "DIAG_NV_WRITE_F (Non-Volatile NV Item Write)",
            0x27 => "DIAG_NV_READ_F (Non-Volatile NV Item Read)",
            0x4B => "DIAG_SUBSYS_CMD_F (Subsystem Command)",
            0x79 => "DIAG_RPC_F (Remote Procedure Call)",
            0x80 => "DIAG_LOG_F (Diagnostic Logging)",
            _ => $"DIAG_CMD_0x{cmd:X2}"
        };
    }
}
