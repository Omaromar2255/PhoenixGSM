using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using PhoenixGSM.OmniTrace.Apple.Models;

namespace PhoenixGSM.OmniTrace.Apple.Decoders;

/// <summary>
/// Decoder for Apple DFU Mode (SecureROM), handling USB DFU class transfers (DFU_DNLOAD, DFU_GETSTATUS),
/// checkm8 exploit sequence tracking, and Pwned DFU state extraction.
/// </summary>
public static class AppleDfuDecoder
{
    private static readonly Regex DfuIdRegex = new(
        @"(CPID:([0-9A-Fa-f]+)|BDID:([0-9A-Fa-f]+)|ECID:([0-9A-Fa-f]+)|PWND:\[([^\]]+)\])",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public static double Evaluate(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length == 0) return 0.0;

        string text = Encoding.ASCII.GetString(buffer[..Math.Min(buffer.Length, 512)]);

        // 1. Check for DFU descriptor string
        if (text.Contains("MODE:DFU", StringComparison.OrdinalIgnoreCase) ||
            (text.Contains("CPID:", StringComparison.OrdinalIgnoreCase) && text.Contains("CPFM:", StringComparison.OrdinalIgnoreCase)))
        {
            return 0.99;
        }

        // 2. Check for Pwned DFU exploit tag
        if (text.Contains("PWND:[", StringComparison.OrdinalIgnoreCase))
        {
            return 0.99;
        }

        // 3. USB DFU Control Packet (DFU_DNLOAD / DFU_GETSTATUS)
        if (buffer.Length >= 8 && (buffer[0] == 0x21 || buffer[0] == 0xA1))
        {
            byte req = buffer[1];
            if (req == 1 || req == 2 || req == 3 || req == 4 || req == 6) // DFU requests
            {
                return 0.92;
            }
        }

        return 0.0;
    }

    public static AppleDecodedCommand? DecodePacket(ReadOnlySpan<byte> buffer, bool isInboundResponse = false)
    {
        if (buffer.Length == 0) return null;

        string text = Encoding.ASCII.GetString(buffer[..Math.Min(buffer.Length, 512)]);
        bool isPwned = text.Contains("PWND:[", StringComparison.OrdinalIgnoreCase);

        var cmd = new AppleDecodedCommand
        {
            Mode = isPwned ? AppleDeviceMode.PwnedDfu : AppleDeviceMode.Dfu,
            Category = "SecureROM"
        };

        // 0. Handle 6-byte USB DFU GETSTATUS response from device
        if (buffer.Length == 6 && (buffer[0] <= 0x0F && buffer[4] <= 0x0A))
        {
            byte bStatus = buffer[0];
            uint pollTimeout = (uint)(buffer[1] | (buffer[2] << 8) | (buffer[3] << 16));
            byte bState = buffer[4];

            string stateName = bState switch
            {
                0 => "appIDLE",
                1 => "appDETACH",
                2 => "dfuIDLE",
                3 => "dfuDNLOAD-SYNC",
                4 => "dfuDNBUSY",
                5 => "dfuDNLOAD-IDLE",
                6 => "dfuMANIFEST-SYNC",
                7 => "dfuMANIFEST",
                8 => "dfuMANIFEST-WAIT-RESET",
                9 => "dfuUPLOAD-IDLE",
                10 => "dfuERROR",
                _ => $"dfuState_{bState}"
            };

            cmd.Operation = "DFU:StatusResponse";
            cmd.Parameters = $"Status={bStatus}, State={stateName}, Timeout={pollTimeout}ms";
            cmd.Summary = $"DFU Status Response -> State={stateName}, Status={bStatus}";
            cmd.Details["IsResponse"] = "true";
            cmd.Details["DfuStatus"] = bStatus.ToString();
            cmd.Details["DfuState"] = stateName;
            return cmd;
        }

        // Extract hardware identifiers
        var matches = DfuIdRegex.Matches(text);
        foreach (Match m in matches)
        {
            string part = m.Value;
            if (part.StartsWith("CPID:", StringComparison.OrdinalIgnoreCase)) cmd.Cpid = part[5..];
            else if (part.StartsWith("BDID:", StringComparison.OrdinalIgnoreCase)) cmd.Bdid = part[5..];
            else if (part.StartsWith("ECID:", StringComparison.OrdinalIgnoreCase)) cmd.Ecid = part[5..];
            else if (part.StartsWith("PWND:", StringComparison.OrdinalIgnoreCase))
            {
                cmd.Details["ExploitToken"] = part;
                cmd.Mode = AppleDeviceMode.PwnedDfu;
            }
        }

        // Handle USB DFU request
        if (buffer.Length >= 8 && (buffer[0] == 0x21 || buffer[0] == 0xA1))
        {
            byte req = buffer[1];
            ushort wValue = BitConverter.ToUInt16(buffer[2..4]);
            ushort wLength = BitConverter.ToUInt16(buffer[6..8]);

            string reqName = req switch
            {
                1 => "DFU_DNLOAD",
                2 => "DFU_UPLOAD",
                3 => "DFU_GETSTATUS",
                4 => "DFU_CLRSTATUS",
                6 => "DFU_ABORT",
                _ => $"DFU_REQ_{req}"
            };

            cmd.Operation = $"DFU:{reqName}";
            cmd.Parameters = $"wValue={wValue}, wLength={wLength}";
            cmd.Summary = $"DFU Request [{reqName}] (Len={wLength})";
            return cmd;
        }

        cmd.Operation = isPwned ? "DFU:PwnedState" : "DFU:DeviceInfo";
        cmd.Summary = isPwned
            ? $"PWNED DFU Device: CPID={cmd.Cpid ?? "N/A"}, ECID={cmd.Ecid ?? "N/A"} [{cmd.Details.GetValueOrDefault("ExploitToken", "pwned")}]"
            : $"SecureROM DFU Device: CPID={cmd.Cpid ?? "N/A"}, ECID={cmd.Ecid ?? "N/A"}";

        return cmd;
    }
}
