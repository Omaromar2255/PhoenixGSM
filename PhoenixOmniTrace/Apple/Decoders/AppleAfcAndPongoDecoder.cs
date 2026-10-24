using System;
using System.Collections.Generic;
using System.Text;
using PhoenixGSM.OmniTrace.Apple.Models;

namespace PhoenixGSM.OmniTrace.Apple.Decoders;

/// <summary>
/// Decoder for:
/// 1. Apple File Conduit (AFC / AFC2) binary protocol ("CFA6LPAA" magic header).
/// 2. Checkra1n / Palera1n / WinRa1n / UnlockTool PongoOS USB shell commands & responses (VID_05AC&PID_4141).
/// 3. Apple MobileBackup2 / MDM Bypass (`CloudConfigurationDetails.plist`) payloads.
/// </summary>
public static class AppleAfcAndPongoDecoder
{
    // "CFA6LPAA" — 8-byte magic header of Apple File Conduit (AFC) protocol
    private static readonly byte[] AfcMagic = "CFA6LPAA"u8.ToArray();

    private static readonly string[] PongoCommands =
    [
        "sep auto", "sep decrypt", "sep ", "fuse lock", "modload", "ramdisk",
        "kpf", "xargs", "bootx", "bootux", "bootr", "spin", "vm_allocate"
    ];

    public static double EvaluateAfc(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length >= 32 && buffer[..8].SequenceEqual(AfcMagic))
        {
            return 0.99;
        }
        return 0.0;
    }

    public static double EvaluatePongoOs(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length < 3) return 0.0;
        string text = Encoding.ASCII.GetString(buffer[..Math.Min(buffer.Length, 512)]).Trim();

        if (text.Contains("PongoOS", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("checkra1n", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("palera1n", StringComparison.OrdinalIgnoreCase))
        {
            return 0.98;
        }

        foreach (string cmd in PongoCommands)
        {
            if (text.StartsWith(cmd, StringComparison.OrdinalIgnoreCase) && text.Length <= 256)
            {
                return 0.94;
            }
        }

        return 0.0;
    }

    public static AppleDecodedCommand? DecodeAfcPacket(ReadOnlySpan<byte> buffer, bool isInboundResponse = false)
    {
        if (buffer.Length < 32 || !buffer[..8].SequenceEqual(AfcMagic))
            return null;

        ulong entireLength = BitConverter.ToUInt64(buffer.Slice(8, 8));
        ulong thisLength = BitConverter.ToUInt64(buffer.Slice(16, 8));
        ulong packetNum = BitConverter.ToUInt64(buffer.Slice(24, 8));
        ulong operation = buffer.Length >= 40 ? BitConverter.ToUInt64(buffer.Slice(32, 8)) : 0;

        string opName = GetAfcOperationName(operation);
        string pathOrArgs = string.Empty;

        if (buffer.Length > 40)
        {
            int metaLen = (int)Math.Min((ulong)buffer.Length, thisLength) - 40;
            if (metaLen > 0)
            {
                pathOrArgs = Encoding.UTF8.GetString(buffer.Slice(40, Math.Min(metaLen, 256)))
                    .Replace('\0', ' ')
                    .Trim();
            }
        }

        bool isResponse = isInboundResponse || operation == 0x01 || operation == 0x02 || operation == 0x0D;
        var cmd = new AppleDecodedCommand
        {
            Mode = AppleDeviceMode.Normal,
            Category = "AFC",
            Operation = $"AFC:{opName}",
            Parameters = pathOrArgs,
            Summary = string.IsNullOrWhiteSpace(pathOrArgs)
                ? $"AFC [{opName}] (Pkt={packetNum}, Total={entireLength}B)"
                : $"AFC [{opName}] -> {pathOrArgs} (Total={entireLength}B)"
        };

        cmd.Details["AfcOperationCode"] = $"0x{operation:X2}";
        cmd.Details["EntireLength"] = entireLength.ToString();
        cmd.Details["HeaderAndMetaLength"] = thisLength.ToString();
        cmd.Details["PacketNumber"] = packetNum.ToString();
        cmd.Details["IsResponse"] = isResponse.ToString();
        if (!string.IsNullOrWhiteSpace(pathOrArgs))
        {
            cmd.Details["TargetPath"] = pathOrArgs;
        }

        return cmd;
    }

    public static AppleDecodedCommand? DecodePongoPacket(ReadOnlySpan<byte> buffer, bool isInboundResponse = false)
    {
        if (buffer.Length == 0) return null;

        string text = Encoding.ASCII.GetString(buffer[..Math.Min(buffer.Length, 512)]).Trim('\0', '\r', '\n', ' ');
        if (string.IsNullOrWhiteSpace(text)) return null;

        string firstToken = text.Split(' ', StringSplitOptions.RemoveEmptyEntries)[0];
        var cmd = new AppleDecodedCommand
        {
            Mode = AppleDeviceMode.PwnedDfu,
            Category = "PongoOS",
            Operation = isInboundResponse ? "PongoOS:Response" : $"PongoOS:{firstToken}",
            Parameters = text,
            Summary = isInboundResponse
                ? $"PongoOS Device Response: {text}"
                : $"PongoOS Command: {text}"
        };

        cmd.Details["IsResponse"] = isInboundResponse.ToString();
        return cmd;
    }

    private static string GetAfcOperationName(ulong op) => op switch
    {
        0x01 => "STATUS_RESPONSE",
        0x02 => "DATA_PAYLOAD",
        0x03 => "READ_DIR",
        0x04 => "READ_FILE",
        0x05 => "WRITE_FILE",
        0x06 => "WRITE_PART",
        0x07 => "TRUNCATE",
        0x08 => "REMOVE_PATH",
        0x09 => "MAKE_DIR",
        0x0A => "GET_FILE_INFO",
        0x0B => "GET_DEVINFO",
        0x0C => "WRITE_FILE_ATOM",
        0x0D => "FILE_OPEN",
        0x0E => "FILE_OPEN_RES",
        0x0F => "FILE_READ",
        0x10 => "FILE_WRITE",
        0x11 => "FILE_SEEK",
        0x12 => "FILE_TELL",
        0x14 => "FILE_CLOSE",
        0x15 => "FILE_SET_SIZE",
        0x18 => "RENAME_PATH",
        0x1B => "FILE_LOCK",
        0x1C => "MAKE_LINK",
        0x1D => "GET_FILE_HASH",
        0x22 => "REMOVE_PATH_AND_CONTENTS",
        _ => $"OP_0x{op:X2}"
    };
}
