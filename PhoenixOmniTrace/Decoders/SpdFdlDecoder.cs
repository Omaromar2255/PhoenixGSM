using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.Decoders;

/// <summary>
/// Information model for a decoded Spreadtrum / Unisoc FDL protocol frame.
/// </summary>
public sealed class SpdDecodedPacket
{
    public ushort CommandType { get; set; }
    public string CommandName { get; set; } = string.Empty;
    public ushort DataLength { get; set; }
    public string Summary { get; set; } = string.Empty;
    public string VersionOrChipString { get; set; } = string.Empty;
    public string PartitionTarget { get; set; } = string.Empty;
    public Dictionary<string, string> Details { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    public override string ToString()
    {
        string ver = !string.IsNullOrEmpty(VersionOrChipString) ? $" [{VersionOrChipString}]" : "";
        string part = !string.IsNullOrEmpty(PartitionTarget) ? $" (Target: {PartitionTarget})" : "";
        return $"[SPD FDL] {CommandName}{ver}{part}: {Summary}";
    }
}

/// <summary>
/// LAYER 7D — Spreadtrum / Unisoc (SPD) Bootloader & FDL Protocol Decoder
/// Decodes HDLC 0x7E framed Boot System Loader (BSL) & Flash Download Loader (FDL)
/// commands used on Unisoc SC9863A, T606, T610, T612, T616, T700, and SC7731E chips.
/// </summary>
public static class SpdFdlDecoder
{
    public const byte HDLC_FLAG = 0x7E;
    public const byte HDLC_ESCAPE = 0x7D;

    private static readonly Dictionary<ushort, string> SpdCommands = new()
    {
        [0x0000] = "BSL_CMD_CHECK_BAUD",
        [0x0001] = "BSL_CMD_CONNECT",
        [0x0002] = "BSL_CMD_START_DATA",
        [0x0003] = "BSL_CMD_MIDST_DATA",
        [0x0004] = "BSL_CMD_END_DATA",
        [0x0005] = "BSL_CMD_EXEC_DATA",
        [0x0006] = "BSL_CMD_NORMAL_RESET",
        [0x0007] = "BSL_CMD_READ_FLASH",
        [0x0010] = "BSL_CMD_CHANGE_BAUD",
        [0x001A] = "BSL_CMD_ERASE_FLASH",
        [0x001B] = "BSL_CMD_REPARTITION",
        [0x0021] = "BSL_CMD_READ_SECTOR_SIZE",
        [0x002C] = "BSL_CMD_READ_CHIP_UID",
        [0x0035] = "BSL_CMD_READ_SECURITY_DATA",
        [0x0037] = "BSL_CMD_DISABLE_TRANS_CODE",

        // Responses
        [0x0080] = "BSL_REP_ACK",
        [0x0081] = "BSL_REP_VER",
        [0x0082] = "BSL_REP_INCOMPATIBLE_PARTITION",
        [0x0083] = "BSL_REP_OPERATION_FAILED",
        [0x0084] = "BSL_REP_INVALID_ADDR",
        [0x008F] = "BSL_REP_NOT_SUPPORTED"
    };

    /// <summary>
    /// Unescapes HDLC bytes: 0x7D 0x5E -> 0x7E, 0x7D 0x5D -> 0x7D
    /// </summary>
    public static byte[] Unescape(ReadOnlySpan<byte> data)
    {
        // Strip outer 0x7E delimiters if present
        int start = 0;
        int end = data.Length;
        if (end > 0 && data[0] == HDLC_FLAG) start++;
        if (end > start && data[end - 1] == HDLC_FLAG) end--;

        var ms = new MemoryStream();
        for (int i = start; i < end; i++)
        {
            if (data[i] == HDLC_ESCAPE && i + 1 < end)
            {
                byte next = data[i + 1];
                if (next == 0x5E) { ms.WriteByte(0x7E); i++; }
                else if (next == 0x5D) { ms.WriteByte(0x7D); i++; }
                else ms.WriteByte(data[i]);
            }
            else
            {
                ms.WriteByte(data[i]);
            }
        }
        return ms.ToArray();
    }

    /// <summary>
    /// Evaluates if buffer matches Spreadtrum/Unisoc FDL HDLC framing.
    /// </summary>
    public static double EvaluateSpd(ReadOnlySpan<byte> buf)
    {
        if (buf.Length < 6) return 0.0;

        // Framing starts or ends with 0x7E
        if (buf[0] != HDLC_FLAG && buf[^1] != HDLC_FLAG) return 0.0;

        byte[] unescaped = Unescape(buf);
        if (unescaped.Length < 4) return 0.0;

        // Extract Big-Endian Type and Length
        ushort type = (ushort)((unescaped[0] << 8) | unescaped[1]);
        ushort len = (ushort)((unescaped[2] << 8) | unescaped[3]);

        if (SpdCommands.ContainsKey(type))
        {
            if (unescaped.Length >= 4 + len) return 0.98;
            return 0.88;
        }

        return 0.0;
    }

    /// <summary>
    /// Decodes an SPD FDL protocol packet.
    /// </summary>
    public static SpdDecodedPacket? DecodePacket(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length < 4) return null;

        byte[] unescaped = Unescape(buffer);
        if (unescaped.Length < 4) return null;

        ushort type = (ushort)((unescaped[0] << 8) | unescaped[1]);
        ushort len = (ushort)((unescaped[2] << 8) | unescaped[3]);

        string cmdName = SpdCommands.TryGetValue(type, out var name) ? name : $"CMD_0x{type:X4}";

        var packet = new SpdDecodedPacket
        {
            CommandType = type,
            CommandName = cmdName,
            DataLength = len
        };

        ReadOnlySpan<byte> payload = unescaped.Length >= 4 + len ? unescaped.AsSpan(4, len) : (unescaped.Length > 4 ? unescaped.AsSpan(4) : []);

        switch (type)
        {
            case 0x0000:
                packet.Summary = "Checking Baud rate / FDL synchronization sync";
                break;

            case 0x0001:
                packet.Summary = "Handshake connect request to Unisoc Bootloader";
                break;

            case 0x0002: // START_DATA
                packet.Summary = "Staging firmware image download (Address & Size setup)";
                break;

            case 0x0003: // MIDST_DATA
                packet.Summary = $"Flashing image data block ({len} bytes chunk)";
                break;

            case 0x0004: // END_DATA
                packet.Summary = "Completed firmware image data transfer";
                break;

            case 0x0005: // EXEC_DATA
                packet.Summary = "Jumping execution to FDL loader in RAM";
                break;

            case 0x0006: // NORMAL_RESET
                packet.Summary = "Resetting device to normal boot mode";
                break;

            case 0x001B: // REPARTITION
                packet.Summary = "Updating device partition table (PIT / GPT)";
                break;

            case 0x002C: // READ_CHIP_UID
                packet.Summary = "Querying Unique Chip Hardware UID";
                break;

            case 0x0080: // ACK
                packet.Summary = "Bootloader ACK: Operation completed successfully";
                break;

            case 0x0081: // VER
                string verStr = Encoding.ASCII.GetString(payload).TrimEnd('\0').Trim();
                packet.VersionOrChipString = verStr;
                packet.Summary = $"Bootloader Version Response: {verStr}";
                packet.Details["ChipVersion"] = verStr;
                break;

            case 0x0082:
                packet.Summary = "Bootloader Error: Incompatible partition";
                break;

            case 0x0083:
                packet.Summary = "Bootloader Error: Operation failed";
                break;

            default:
                packet.Summary = $"SPD Frame Type 0x{type:X4} ({cmdName}, len={len})";
                break;
        }

        // Scan payload for known partition names (e.g. splloader, uboot, boot, recovery, system, persist)
        if (payload.Length > 0)
        {
            string ascii = Encoding.ASCII.GetString(payload[..Math.Min(payload.Length, 128)]);
            foreach (var part in new[] { "splloader", "fdl1", "fdl2", "uboot", "boot", "recovery", "system", "userdata", "persist", "cache", "prodnv", "misc" })
            {
                if (ascii.Contains(part, StringComparison.OrdinalIgnoreCase))
                {
                    packet.PartitionTarget = part;
                    packet.Summary += $" [Partition: {part}]";
                    packet.Details["Partition"] = part;
                    break;
                }
            }
        }

        packet.Details["CommandType"] = $"0x{type:X4}";
        packet.Details["CommandName"] = cmdName;
        packet.Details["DataLength"] = len.ToString();

        return packet;
    }
}
