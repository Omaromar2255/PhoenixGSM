using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.Decoders;

/// <summary>
/// Information model for a decoded Qualcomm EDL (Sahara or Firehose XML) event.
/// </summary>
public sealed class QualcommEdlDecodedPacket
{
    public string Phase { get; set; } = "SAHARA"; // SAHARA or FIREHOSE
    public string Action { get; set; } = string.Empty;
    public string TargetPartitionOrFile { get; set; } = string.Empty;
    public string MemoryType { get; set; } = string.Empty;
    public string Summary { get; set; } = string.Empty;
    public bool IsAck { get; set; }
    public Dictionary<string, string> Details { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    public override string ToString()
    {
        string target = !string.IsNullOrEmpty(TargetPartitionOrFile) ? $" [{TargetPartitionOrFile}]" : "";
        string mem = !string.IsNullOrEmpty(MemoryType) ? $" ({MemoryType})" : "";
        return $"[QUALCOMM EDL {Phase}] {Action}{target}{mem}: {Summary}";
    }
}

/// <summary>
/// LAYER 7E — Qualcomm Emergency Download (EDL 9008) Protocol Decoder
/// Decodes both Phase 1 (Sahara binary loader bootstrap) and Phase 2 (Firehose XML flashing protocol),
/// extracting partition filenames, sector ranges, memory types (eMMC/UFS), and operational status.
/// </summary>
public static class QualcommEdlDecoder
{
    private static readonly Dictionary<uint, string> SaharaCommands = new()
    {
        [0x01] = "SAHARA_HELLO_REQ",
        [0x02] = "SAHARA_HELLO_RESP",
        [0x03] = "SAHARA_READ_DATA",
        [0x04] = "SAHARA_END_IMAGE_TX",
        [0x05] = "SAHARA_DONE_REQ",
        [0x06] = "SAHARA_DONE_RESP",
        [0x07] = "SAHARA_RESET_REQ",
        [0x08] = "SAHARA_RESET_RESP",
        [0x09] = "SAHARA_MEMORY_DEBUG",
        [0x0A] = "SAHARA_MEMORY_READ",
        [0x0B] = "SAHARA_CMD_EXEC",
        [0x0C] = "SAHARA_CMD_EXEC_RESP",
        [0x0D] = "SAHARA_64BIT_MEMORY_DEBUG"
    };

    private static readonly Regex XmlAttrRegex = new(
        @"(\w+)\s*=\s*[""']([^""']*)[""']",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>
    /// Evaluates if buffer matches Qualcomm Sahara binary protocol.
    /// </summary>
    public static double EvaluateSahara(ReadOnlySpan<byte> buf)
    {
        if (buf.Length < 8) return 0.0;

        uint cmd = BitConverter.ToUInt32(buf[..4]);
        uint len = BitConverter.ToUInt32(buf[4..8]);

        if (SaharaCommands.ContainsKey(cmd))
        {
            if (cmd == 0x01 && len == 48) return 0.99; // Sahara HELLO_REQ is 48 bytes
            if (cmd == 0x02 && len == 48) return 0.99; // Sahara HELLO_RESP is 48 bytes
            if (len >= 8 && len <= 1024) return 0.92;
            return 0.80;
        }

        return 0.0;
    }

    /// <summary>
    /// Evaluates if buffer matches Qualcomm Firehose XML protocol.
    /// </summary>
    public static double EvaluateFirehose(ReadOnlySpan<byte> buf)
    {
        if (buf.Length < 10) return 0.0;

        string text = Encoding.UTF8.GetString(buf[..Math.Min(buf.Length, 256)]);
        if (text.Contains("<?xml", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("<data>", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("<configure", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("<program", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("<response", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("<log value=", StringComparison.OrdinalIgnoreCase))
        {
            return 0.98;
        }

        return 0.0;
    }

    /// <summary>
    /// Decodes an EDL packet (automatically detecting Sahara binary or Firehose XML).
    /// </summary>
    public static QualcommEdlDecodedPacket? DecodePacket(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length < 4) return null;

        // 1. Check Firehose XML
        if (EvaluateFirehose(buffer) > 0.5)
        {
            return DecodeFirehoseXml(buffer);
        }

        // 2. Check Sahara Binary
        if (EvaluateSahara(buffer) > 0.5)
        {
            return DecodeSaharaBinary(buffer);
        }

        return null;
    }

    private static QualcommEdlDecodedPacket DecodeSaharaBinary(ReadOnlySpan<byte> buffer)
    {
        uint cmd = BitConverter.ToUInt32(buffer[..4]);
        uint len = BitConverter.ToUInt32(buffer[4..8]);

        string name = SaharaCommands.TryGetValue(cmd, out var sName) ? sName : $"SAHARA_CMD_0x{cmd:X2}";

        var packet = new QualcommEdlDecodedPacket
        {
            Phase = "SAHARA",
            Action = name,
            Details =
            {
                ["SaharaCmd"] = $"0x{cmd:X2} ({name})",
                ["PacketLength"] = len.ToString()
            }
        };

        switch (cmd)
        {
            case 0x01: // HELLO_REQ
                packet.Summary = "Device in EDL mode broadcasting Sahara Hello (Handshake ready)";
                break;

            case 0x02: // HELLO_RESP
                packet.Summary = "Host sending Sahara Hello response with client capabilities";
                break;

            case 0x03: // READ_DATA
                if (buffer.Length >= 20)
                {
                    uint imageId = BitConverter.ToUInt32(buffer.Slice(8, 4));
                    uint offset = BitConverter.ToUInt32(buffer.Slice(12, 4));
                    uint sLen = BitConverter.ToUInt32(buffer.Slice(16, 4));
                    packet.Summary = $"Device requesting loader chunk (ImageID={imageId}, Offset=0x{offset:X}, Size={sLen}B)";
                    packet.Details["ImageId"] = imageId.ToString();
                    packet.Details["ChunkOffset"] = $"0x{offset:X}";
                    packet.Details["ChunkSize"] = sLen.ToString();
                }
                else
                {
                    packet.Summary = "Device requesting programmer image chunk from host";
                }
                break;

            case 0x04: // END_IMAGE_TX
                packet.Summary = "Sahara image transmission completed (Programmer loaded)";
                break;

            case 0x05: // DONE_REQ
                packet.Summary = "Host requesting Sahara session completion";
                break;

            case 0x06: // DONE_RESP
                packet.Summary = "Device confirmed Sahara completion (Transitioning to Firehose mode)";
                break;

            case 0x07: // RESET_REQ
                packet.Summary = "Host requesting emergency target reset";
                break;

            default:
                packet.Summary = $"Sahara Packet: {name}";
                break;
        }

        return packet;
    }

    private static QualcommEdlDecodedPacket DecodeFirehoseXml(ReadOnlySpan<byte> buffer)
    {
        string xml = Encoding.UTF8.GetString(buffer);

        var packet = new QualcommEdlDecodedPacket
        {
            Phase = "FIREHOSE",
            Action = "FIREHOSE_XML",
            Summary = "Qualcomm Firehose XML transaction"
        };

        var attrs = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match m in XmlAttrRegex.Matches(xml))
        {
            attrs[m.Groups[1].Value] = m.Groups[2].Value;
            packet.Details[m.Groups[1].Value] = m.Groups[2].Value;
        }

        if (xml.Contains("<configure", StringComparison.OrdinalIgnoreCase))
        {
            packet.Action = "CONFIGURE";
            string mem = attrs.TryGetValue("MemoryName", out var m) ? m : "eMMC/UFS";
            packet.MemoryType = mem;
            packet.Summary = $"Configuring Firehose target storage: {mem}";
        }
        else if (xml.Contains("<program", StringComparison.OrdinalIgnoreCase))
        {
            packet.Action = "PROGRAM / FLASH";
            string file = attrs.TryGetValue("filename", out var f) ? f : "partition";
            string sectors = attrs.TryGetValue("num_partition_sectors", out var s) ? s : "";
            packet.TargetPartitionOrFile = file;
            packet.Summary = $"Flashing partition: {file} ({sectors} sectors)";
        }
        else if (xml.Contains("<read", StringComparison.OrdinalIgnoreCase))
        {
            packet.Action = "READ / DUMP";
            string file = attrs.TryGetValue("filename", out var f) ? f : "dump";
            packet.TargetPartitionOrFile = file;
            packet.Summary = $"Dumping partition to: {file}";
        }
        else if (xml.Contains("<erase", StringComparison.OrdinalIgnoreCase))
        {
            packet.Action = "ERASE / WIPE";
            string start = attrs.TryGetValue("start_sector", out var st) ? st : "0";
            string count = attrs.TryGetValue("num_partition_sectors", out var c) ? c : "";
            packet.Summary = $"Wiping partition sectors (Start: {start}, Count: {count})";
        }
        else if (xml.Contains("<power", StringComparison.OrdinalIgnoreCase))
        {
            packet.Action = "POWER / RESET";
            string val = attrs.TryGetValue("value", out var v) ? v : "reset";
            packet.Summary = $"Executing Power action: {val}";
        }
        else if (xml.Contains("<response", StringComparison.OrdinalIgnoreCase))
        {
            packet.Action = "RESPONSE";
            string val = attrs.TryGetValue("value", out var v) ? v : "";
            packet.IsAck = val.Equals("ACK", StringComparison.OrdinalIgnoreCase);
            packet.Summary = $"Target Response: {val}";
        }
        else if (xml.Contains("<log", StringComparison.OrdinalIgnoreCase))
        {
            packet.Action = "LOG";
            string val = attrs.TryGetValue("value", out var v) ? v : "";
            packet.Summary = $"Target Log: {val}";
        }

        return packet;
    }
}
