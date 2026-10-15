using System;
using System.Buffers.Binary;
using System.Text;

namespace PhoenixGSM.OmniTrace.ToolSourceInterception;

/// <summary>
/// Specialized interceptor for MediaTek (MTK) BROM, Preloader, and Download-Agent (DA)
/// commands captured directly from the tool's process before/during USB connection.
/// فاحص ومفكك أوامر ميديا تيك BROM و DA من المصدر مباشرة
/// </summary>
public static class MtkBromSourceInterceptor
{
    public static bool TryParseMtkCommand(
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

        byte b0 = payload[0];

        // 1. Check BROM Start Handshake (0xA0 0x0A 0x50 0x05)
        if (payload.Length >= 4 &&
            payload[0] == 0xA0 && payload[1] == 0x0A && payload[2] == 0x50 && payload[3] == 0x05)
        {
            record = BuildRecord(
                "MTK_BROM_HANDSHAKE: Start Sync (0xA0 0x0A 0x50 0x05)",
                "BROM Handshake Sync",
                "WARNING",
                payload, toolName, pid, parentPid, endpoint, mechanism,
                "MediaTek BootROM initial handshake sequence. Establishes hardware sync with MTK chip.");
            return true;
        }

        // 2. Check Single Byte Handshake or ACK
        if (payload.Length == 1 && (b0 == 0xA0 || b0 == 0x0A || b0 == 0x50 || b0 == 0x05))
        {
            string byteName = b0 switch
            {
                0xA0 => "SYNC_START (0xA0)",
                0x0A => "SYNC_ACK1 (0x0A)",
                0x50 => "SYNC_ACK2 (0x50)",
                0x05 => "SYNC_ACK3 (0x05)",
                _ => $"SYNC (0x{b0:X2})"
            };
            record = BuildRecord(
                $"MTK_BROM_SYNC: {byteName}",
                $"BROM Sync Byte 0x{b0:X2}",
                "INFO",
                payload, toolName, pid, parentPid, endpoint, mechanism,
                $"MediaTek BootROM synchronization step: {byteName}");
            return true;
        }

        // 3. Known MTK BROM Command Opcodes
        string? cmdName = ResolveBromCommand(b0);
        if (cmdName != null)
        {
            string risk = EvaluateBromRisk(b0, payload);
            string details = DescribeBromCommand(b0, payload);

            record = BuildRecord(
                $"MTK_BROM_CMD: {cmdName}",
                $"BROM Command 0x{b0:X2} ({cmdName})",
                risk,
                payload, toolName, pid, parentPid, endpoint, mechanism,
                details);
            return true;
        }

        // 4. Download-Agent (DA) High-Level String Signatures
        string ascii = Encoding.ASCII.GetString(payload);
        if (ascii.Contains("EMMC_BOOT", StringComparison.OrdinalIgnoreCase) ||
            ascii.Contains("UFS_BOOT", StringComparison.OrdinalIgnoreCase) ||
            ascii.Contains("DA_EXT", StringComparison.OrdinalIgnoreCase) ||
            ascii.Contains("ERASE_FRP", StringComparison.OrdinalIgnoreCase) ||
            ascii.Contains("UNLOCK_BL", StringComparison.OrdinalIgnoreCase) ||
            ascii.Contains("FORMAT", StringComparison.OrdinalIgnoreCase))
        {
            string risk = ascii.Contains("ERASE", StringComparison.OrdinalIgnoreCase) ||
                          ascii.Contains("FORMAT", StringComparison.OrdinalIgnoreCase) ||
                          ascii.Contains("UNLOCK", StringComparison.OrdinalIgnoreCase)
                ? "CRITICAL"
                : "WARNING";

            record = BuildRecord(
                $"MTK_DA_OP: {ExtractDaOperation(ascii)}",
                $"DA Payload ({payload.Length} bytes)",
                risk,
                payload, toolName, pid, parentPid, endpoint, mechanism,
                $"MediaTek Download-Agent (DA) Operation Command: {ascii[..Math.Min(ascii.Length, 120)]}");
            return true;
        }

        return false;
    }

    private static string? ResolveBromCommand(byte op)
    {
        return op switch
        {
            0xD8 => "CMD_GET_HW_CODE (Detect Chipset MT67xx/MT68xx)",
            0xD7 => "CMD_GET_BL_VER (Bootloader Version)",
            0xD4 => "CMD_GET_HW_SUB_CODE",
            0xD2 => "CMD_GET_TARGET_CONFIG (SLA/DAA Security State)",
            0xD5 => "CMD_JUMP_DA (Boot Download-Agent)",
            0xC7 => "CMD_SEND_DA (Download-Agent Payload Stage)",
            0xC1 => "CMD_READ32 (Direct Register Read)",
            0xC2 => "CMD_WRITE32 (Direct Register Write / Auth Exploit)",
            0xC3 => "CMD_READ16",
            0xC4 => "CMD_WRITE16",
            0xDA => "CMD_GET_MEID",
            0xDC => "CMD_GET_SOC_ID",
            _ => null
        };
    }

    private static string EvaluateBromRisk(byte op, byte[] payload)
    {
        return op switch
        {
            0xD5 => "CRITICAL", // CMD_JUMP_DA (Code execution on device)
            0xC2 => "CRITICAL", // CMD_WRITE32 (Register tampering / SLA exploit)
            0xC7 => "WARNING",  // CMD_SEND_DA
            0xD2 => "WARNING",  // Auth status check
            _ => "INFO"
        };
    }

    private static string DescribeBromCommand(byte op, byte[] payload)
    {
        var sb = new StringBuilder();
        sb.AppendLine("MediaTek BootROM Low-Level Command");
        sb.AppendLine($"Opcode: 0x{op:X2} ({ResolveBromCommand(op)})");
        sb.AppendLine($"Payload Size: {payload.Length} bytes");

        if (op == 0xC2 && payload.Length >= 9) // WRITE32 [addr 4B] [count 4B] ...
        {
            uint addr = BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(1, 4));
            sb.AppendLine($"Target Register Address: 0x{addr:X8}");
        }
        else if (op == 0xC1 && payload.Length >= 5) // READ32 [addr 4B]
        {
            uint addr = BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(1, 4));
            sb.AppendLine($"Read Register Address: 0x{addr:X8}");
        }

        return sb.ToString();
    }

    private static string ExtractDaOperation(string ascii)
    {
        if (ascii.Contains("ERASE_FRP", StringComparison.OrdinalIgnoreCase)) return "ERASE_FRP (Factory Reset Protection Wipe)";
        if (ascii.Contains("UNLOCK_BL", StringComparison.OrdinalIgnoreCase)) return "UNLOCK_BOOTLOADER";
        if (ascii.Contains("FORMAT", StringComparison.OrdinalIgnoreCase)) return "FORMAT_PARTITION";
        if (ascii.Contains("EMMC_BOOT", StringComparison.OrdinalIgnoreCase)) return "EMMC_BOOT_INIT";
        if (ascii.Contains("UFS_BOOT", StringComparison.OrdinalIgnoreCase)) return "UFS_BOOT_INIT";
        return "GENERIC_DA_OPERATION";
    }

    private static ToolSourceCommandRecord BuildRecord(
        string pureCmd,
        string rawCmd,
        string risk,
        byte[] payload,
        string toolName,
        int pid,
        int parentPid,
        string endpoint,
        string mechanism,
        string techDetails)
    {
        return new ToolSourceCommandRecord
        {
            Timestamp = DateTime.UtcNow,
            Mode = ToolSourceMode.MtkBrom,
            ToolName = toolName,
            ProcessId = pid,
            ParentProcessId = parentPid,
            PureCommand = pureCmd,
            RawCommand = rawCmd,
            InterceptMechanism = mechanism,
            TargetEndpoint = string.IsNullOrWhiteSpace(endpoint) ? "USB\\VID_0E8D&PID_0003 (MTK BROM)" : endpoint,
            RawPayload = payload,
            PayloadHex = ToolSourceCommandRecord.FormatHexDump(payload),
            PayloadAscii = Encoding.ASCII.GetString(payload.Length > 256 ? payload[..256] : payload),
            TechnicalDetails = techDetails,
            RiskLevel = risk,
            Status = "CAPTURED_AT_SOURCE"
        };
    }
}
