using System;
using System.Buffers.Binary;
using System.Text;

namespace PhoenixGSM.OmniTrace.ToolSourceInterception;

/// <summary>
/// Specialized interceptor for Samsung Odin / Download mode (Loke protocol)
/// commands captured directly from the tool's process before wire encapsulation.
/// فاحص ومفكك أوامر سامسونج داونلود وأودين (بروتوكول Loke) من المصدر مباشرة
/// </summary>
public static class OdinSourceInterceptor
{
    private static readonly byte[] OdinMagic = "ODIN"u8.ToArray();
    private static readonly byte[] LokeMagic = "LOKE"u8.ToArray();

    public static bool TryParseOdinCommand(
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

        // 1. Check Odin / Loke Protocol Magic Handshake
        if (payload.Length >= 4 && (payload.AsSpan(0, 4).SequenceEqual(OdinMagic) || payload.AsSpan(0, 4).SequenceEqual(LokeMagic)))
        {
            string magic = Encoding.ASCII.GetString(payload[..4]);
            record = BuildRecord(
                $"ODIN_HANDSHAKE: Session Init ({magic})",
                $"Odin Handshake Magic: {magic}",
                "INFO",
                payload, toolName, pid, parentPid, endpoint, mechanism,
                $"Samsung Odin / Loke Protocol session initialization handshake from {toolName}.");
            return true;
        }

        // 2. PIT File Magic Header (0x12 0x34 0x56 0x78)
        if (payload.Length >= 4 &&
            payload[0] == 0x78 && payload[1] == 0x56 && payload[2] == 0x34 && payload[3] == 0x12)
        {
            int partCount = payload.Length > 28 ? BinaryPrimitives.ReadInt32LittleEndian(payload.AsSpan(24, 4)) : 0;
            string partitions = ExtractPitPartitions(payload);

            record = BuildRecord(
                $"ODIN_PIT: Partition Information Table ({partCount} partitions)",
                $"Samsung PIT Table Structure ({payload.Length} bytes)",
                "CRITICAL",
                payload, toolName, pid, parentPid, endpoint, mechanism,
                $"Samsung PIT (Partition Information Table) binary payload.\nTotal Partitions: {partCount}\nIdentified: {partitions}");
            return true;
        }

        // 3. Known Odin / Loke Protocol Control Packets
        byte cmdCode = payload[0];
        string? lokeCmd = ResolveLokeCommand(cmdCode);
        if (lokeCmd != null)
        {
            string risk = EvaluateOdinRisk(cmdCode);
            string param = ExtractLokeParams(cmdCode, payload);

            record = BuildRecord(
                $"ODIN_CMD: {lokeCmd}{param}",
                $"Loke Opcode 0x{cmdCode:X2} ('{(char)cmdCode}')",
                risk,
                payload, toolName, pid, parentPid, endpoint, mechanism,
                $"Samsung Download Mode (Loke Protocol) Command:\nCommand: {lokeCmd}\nPayload Size: {payload.Length} bytes\nParameters: {param}");
            return true;
        }

        // 4. String Signatures for TAR.MD5 Flashing Packages
        string ascii = Encoding.ASCII.GetString(payload.Length > 512 ? payload[..512] : payload);
        if (ascii.Contains("boot.img", StringComparison.OrdinalIgnoreCase) ||
            ascii.Contains("recovery.img", StringComparison.OrdinalIgnoreCase) ||
            ascii.Contains("system.img", StringComparison.OrdinalIgnoreCase) ||
            ascii.Contains("userdata.img", StringComparison.OrdinalIgnoreCase) ||
            ascii.Contains("param.bin", StringComparison.OrdinalIgnoreCase) ||
            ascii.Contains("sboot.bin", StringComparison.OrdinalIgnoreCase))
        {
            string fileTarget = ExtractTarTarget(ascii);
            record = BuildRecord(
                $"ODIN_FLASH_IMAGE: {fileTarget}",
                $"Samsung Odin Flash Payload ({payload.Length} bytes)",
                "CRITICAL",
                payload, toolName, pid, parentPid, endpoint, mechanism,
                $"Samsung Odin partition image flashing stream.\nTarget File: {fileTarget}\nChunk Size: {payload.Length} bytes.");
            return true;
        }

        return false;
    }

    private static string? ResolveLokeCommand(byte code)
    {
        return code switch
        {
            0x64 => "PIT_REQUEST (Read Partition Info Table)",
            0x65 => "FLASH_PARTITION_START (Begin Writing Partition)",
            0x66 => "FLASH_DATA_CHUNK (Transfer Partition Data)",
            0x67 => "FLASH_PARTITION_END (Verify Partition Checksum)",
            0x68 => "REBOOT_DEVICE (Reboot to System/Recovery)",
            0x69 => "CLOSE_SESSION (End Odin Session)",
            0x6A => "TOTAL_BYTES_NOTIFICATION (Transfer Size Declaration)",
            _ => null
        };
    }

    private static string EvaluateOdinRisk(byte code)
    {
        return code switch
        {
            0x65 => "CRITICAL", // FLASH_PARTITION_START (Writing to phone's flash memory)
            0x66 => "CRITICAL", // FLASH_DATA_CHUNK
            0x68 => "WARNING",  // REBOOT_DEVICE
            0x64 => "INFO",     // PIT_REQUEST
            _ => "INFO"
        };
    }

    private static string ExtractLokeParams(byte code, byte[] payload)
    {
        if (code == 0x65 && payload.Length > 4) // Partition Name usually follows
        {
            string name = Encoding.ASCII.GetString(payload[1..Math.Min(payload.Length, 32)]).Trim('\0', ' ');
            if (!string.IsNullOrWhiteSpace(name)) return $" [Partition={name}]";
        }
        else if (code == 0x6A && payload.Length >= 5) // Total Bytes [4B]
        {
            uint totalBytes = BinaryPrimitives.ReadUInt32LittleEndian(payload.AsSpan(1, 4));
            return $" [Total={totalBytes / (1024.0 * 1024.0):F2} MB]";
        }
        return string.Empty;
    }

    private static string ExtractPitPartitions(byte[] payload)
    {
        var sb = new StringBuilder();
        string ascii = Encoding.ASCII.GetString(payload);
        string[] candidates = ["BOOT", "RECOVERY", "SYSTEM", "USERDATA", "EFS", "RADIO", "MODEM", "CACHE", "HIDDEN", "PERSISTENT", "PARAM"];
        foreach (var c in candidates)
        {
            if (ascii.Contains(c, StringComparison.OrdinalIgnoreCase))
            {
                if (sb.Length > 0) sb.Append(", ");
                sb.Append(c);
            }
        }
        return sb.Length > 0 ? sb.ToString() : "Standard Samsung Partitions";
    }

    private static string ExtractTarTarget(string ascii)
    {
        string[] files = ["boot.img", "recovery.img", "system.img", "userdata.img", "param.bin", "sboot.bin", "modem.bin", "vendor.img"];
        foreach (var f in files)
        {
            if (ascii.Contains(f, StringComparison.OrdinalIgnoreCase)) return f;
        }
        return "TAR Partition Stream";
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
            Mode = ToolSourceMode.SamsungOdin,
            ToolName = toolName,
            ProcessId = pid,
            ParentProcessId = parentPid,
            PureCommand = pureCmd,
            RawCommand = rawCmd,
            InterceptMechanism = mechanism,
            TargetEndpoint = string.IsNullOrWhiteSpace(endpoint) ? "SAMSUNG Mobile USB CDC Composite" : endpoint,
            RawPayload = payload,
            PayloadHex = ToolSourceCommandRecord.FormatHexDump(payload),
            PayloadAscii = Encoding.ASCII.GetString(payload.Length > 256 ? payload[..256] : payload),
            TechnicalDetails = techDetails,
            RiskLevel = risk,
            Status = "CAPTURED_AT_SOURCE"
        };
    }
}
