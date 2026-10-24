using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using PhoenixGSM.OmniTrace.Apple.Models;

namespace PhoenixGSM.OmniTrace.Apple.Decoders;

/// <summary>
/// Decoder for Apple Recovery Mode (iBoot / irecovery), handling bootloader commands,
/// environment variable reads/writes, restore handshakes, and chip identifiers.
/// </summary>
public static class AppleRecoveryDecoder
{
    private static readonly string[] RecoveryCommands =
    [
        "getenv", "setenv", "saveenv", "bgcolor", "reboot", "fsboot",
        "go", "send", "upload", "reset", "cmd", "ramdisk", "diag"
    ];

    private static readonly Regex RecoveryIdRegex = new(
        @"(CPID:([0-9A-Fa-f]+)|BDID:([0-9A-Fa-f]+)|ECID:([0-9A-Fa-f]+)|SRTG:\[([^\]]+)\])",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public static double Evaluate(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length == 0) return 0.0;

        string text = Encoding.ASCII.GetString(buffer[..Math.Min(buffer.Length, 512)]).Trim();

        // If explicitly in DFU or Pwned DFU mode, this is not Recovery
        if (text.Contains("MODE:DFU", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("PWND:[", StringComparison.OrdinalIgnoreCase))
        {
            return 0.0;
        }

        // 1. Check for iBoot USB serial number descriptor pattern
        if (text.Contains("CPID:", StringComparison.OrdinalIgnoreCase) &&
            text.Contains("ECID:", StringComparison.OrdinalIgnoreCase))
        {
            if (text.Contains("MODE:Recovery", StringComparison.OrdinalIgnoreCase) || text.Contains("iBoot-", StringComparison.OrdinalIgnoreCase))
            {
                return 0.99;
            }
            return 0.94;
        }

        // 2. Check for irecovery command prefixes
        foreach (var cmd in RecoveryCommands)
        {
            if (text.StartsWith(cmd + " ", StringComparison.OrdinalIgnoreCase) ||
                text.Equals(cmd, StringComparison.OrdinalIgnoreCase))
            {
                return 0.95;
            }
        }

        // 3. Check for restore plist
        if (text.Contains("RestoreStage", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("RAMDiskLoad", StringComparison.OrdinalIgnoreCase))
        {
            return 0.95;
        }

        return 0.0;
    }

    public static AppleDecodedCommand? DecodePacket(ReadOnlySpan<byte> buffer, bool isInboundResponse = false)
    {
        if (buffer.Length == 0) return null;

        string text = Encoding.ASCII.GetString(buffer).Trim();
        var cmd = new AppleDecodedCommand
        {
            Mode = AppleDeviceMode.Recovery,
            Category = "iBoot"
        };

        // Parse hardware descriptor if present
        if (text.Contains("CPID:", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("ECID:", StringComparison.OrdinalIgnoreCase))
        {
            var matches = RecoveryIdRegex.Matches(text);
            foreach (Match m in matches)
            {
                string part = m.Value;
                if (part.StartsWith("CPID:", StringComparison.OrdinalIgnoreCase)) cmd.Cpid = part[5..];
                else if (part.StartsWith("BDID:", StringComparison.OrdinalIgnoreCase)) cmd.Bdid = part[5..];
                else if (part.StartsWith("ECID:", StringComparison.OrdinalIgnoreCase)) cmd.Ecid = part[5..];
                else if (part.StartsWith("SRTG:", StringComparison.OrdinalIgnoreCase)) cmd.Details["iBootVersion"] = part;
            }

            cmd.Operation = "iBoot:DeviceInfo";
            cmd.Summary = $"iBoot Hardware ID: ECID={cmd.Ecid ?? "N/A"}, CPID={cmd.Cpid ?? "N/A"}";
            cmd.Details["IsResponse"] = "true";
            return cmd;
        }

        // Parse command line or inbound phone response
        string[] tokens = text.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
        bool isCmd = tokens.Length > 0 && Array.Exists(RecoveryCommands, rc => rc.Equals(tokens[0], StringComparison.OrdinalIgnoreCase));

        if (isInboundResponse || !isCmd)
        {
            cmd.Operation = "iBoot:Response";
            cmd.Parameters = text;
            cmd.Summary = $"iBoot Phone Response -> {text}";
            cmd.Details["IsResponse"] = "true";
            return cmd;
        }

        if (tokens.Length > 0)
        {
            cmd.Operation = $"iBoot:{tokens[0]}";
            if (tokens.Length > 1)
            {
                cmd.Parameters = tokens[1].Trim();
            }
        }
        else
        {
            cmd.Operation = "iBoot:Unknown";
        }

        cmd.Summary = string.IsNullOrEmpty(cmd.Parameters)
            ? $"iBoot [{tokens[0]}]"
            : $"iBoot [{tokens[0]}] -> {cmd.Parameters}";
        cmd.Details["IsResponse"] = "false";

        return cmd;
    }
}
