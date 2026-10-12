using System;
using System.Collections.Generic;
using System.Text;
using PhoenixGSM.OmniTrace.Apple.Models;

namespace PhoenixGSM.OmniTrace.Apple.Decoders;

/// <summary>
/// Decoder for Apple Factory Diagnostics & Purple Mode communication over USB CDC Serial (usbser.sys)
/// or DCSD Alex engineering cables. Parses SysCfg NAND parameters (SN, WiFi/BT MAC, Board ID, Region).
/// </summary>
public static class ApplePurpleDiagDecoder
{
    private static readonly string[] SysCfgKeys =
    [
        "SrNm", "WmMC", "BTMAC", "Mod#", "Regn", "MLB#", "BMac", "WMac",
        "NSn#", "LCM#", "Batt", "diag", "rtcoff", "syscfg"
    ];

    public static double Evaluate(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length == 0) return 0.0;

        string text = Encoding.ASCII.GetString(buffer[..Math.Min(buffer.Length, 512)]).Trim();

        if (text.StartsWith("syscfg ", StringComparison.OrdinalIgnoreCase) ||
            text.Equals("syscfg", StringComparison.OrdinalIgnoreCase))
        {
            return 0.99;
        }

        foreach (var key in SysCfgKeys)
        {
            if (text.Contains(key, StringComparison.OrdinalIgnoreCase) &&
                (text.Contains("=") || text.Contains(":") || text.Contains("print") || text.Contains("add")))
            {
                return 0.95;
            }
        }

        return 0.0;
    }

    public static AppleDecodedCommand? DecodePacket(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length == 0) return null;

        string text = Encoding.ASCII.GetString(buffer).Trim();
        var cmd = new AppleDecodedCommand
        {
            Mode = AppleDeviceMode.PurpleDiag,
            Category = "PurpleDiag"
        };

        if (text.StartsWith("syscfg ", StringComparison.OrdinalIgnoreCase))
        {
            string[] parts = text.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            cmd.Operation = parts.Length > 1 ? $"SysCfg:{parts[1]}" : "SysCfg";
            cmd.Parameters = text;
            cmd.Summary = $"SysCfg Operation: {text}";

            // Check if reading/writing specific parameters
            if (text.Contains("SrNm", StringComparison.OrdinalIgnoreCase)) cmd.Details["Parameter"] = "SerialNumber";
            if (text.Contains("WmMC", StringComparison.OrdinalIgnoreCase)) cmd.Details["Parameter"] = "WiFi_MAC";
            if (text.Contains("BTMAC", StringComparison.OrdinalIgnoreCase)) cmd.Details["Parameter"] = "Bluetooth_MAC";
            return cmd;
        }

        cmd.Operation = "Diag:Serial";
        cmd.Parameters = text;
        cmd.Summary = $"Purple Diag Serial: {text}";
        return cmd;
    }
}
