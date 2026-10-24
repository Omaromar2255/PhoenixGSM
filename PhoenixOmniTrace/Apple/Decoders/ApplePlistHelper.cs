using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace PhoenixGSM.OmniTrace.Apple.Decoders;

/// <summary>
/// Lightweight helper for extracting essential key-value attributes from both
/// XML plists and Binary Apple property lists (bplist00), including device responses.
/// </summary>
public static class ApplePlistHelper
{
    private static readonly byte[] BplistMagic = "bplist00"u8.ToArray();

    private static readonly Regex XmlKeyValueRegex = new(
        @"<key>([^<]+)</key>\s*(?:<(string|integer|real|data)>([^<]*)</\2>|<(true|false)\s*/>)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public static bool IsPlist(ReadOnlySpan<byte> data)
    {
        if (data.Length < 8) return false;
        if (data.StartsWith(BplistMagic)) return true;

        int checkLen = Math.Min(data.Length, 384);
        string header = Encoding.UTF8.GetString(data[..checkLen]);
        return header.Contains("<?xml", StringComparison.OrdinalIgnoreCase) ||
               header.Contains("<plist", StringComparison.OrdinalIgnoreCase) ||
               header.Contains("<!DOCTYPE plist", StringComparison.OrdinalIgnoreCase);
    }

    public static Dictionary<string, string> ExtractKeyValues(ReadOnlySpan<byte> data)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (data.Length < 8) return result;

        if (data.StartsWith(BplistMagic))
        {
            ExtractFromBinaryPlist(data, result);
        }
        else
        {
            ExtractFromXmlPlist(data, result);
        }

        return result;
    }

    private static void ExtractFromXmlPlist(ReadOnlySpan<byte> data, Dictionary<string, string> result)
    {
        try
        {
            string xml = Encoding.UTF8.GetString(data);
            var matches = XmlKeyValueRegex.Matches(xml);
            foreach (Match m in matches)
            {
                string key = m.Groups[1].Value.Trim();
                string boolTag = m.Groups[4].Value.Trim();
                string val = !string.IsNullOrEmpty(boolTag) ? boolTag : m.Groups[3].Value.Trim();

                if (!string.IsNullOrEmpty(key) && !result.ContainsKey(key))
                {
                    if (m.Groups[2].Value.Equals("data", StringComparison.OrdinalIgnoreCase) && val.Length > 64)
                    {
                        val = $"[Base64 Data: {val.Length} chars]";
                    }
                    result[key] = val;
                }
            }
        }
        catch { }
    }

    private static void ExtractFromBinaryPlist(ReadOnlySpan<byte> data, Dictionary<string, string> result)
    {
        try
        {
            string ascii = Encoding.ASCII.GetString(data);
            string[] knownKeys =
            [
                "MessageType", "ClientVersionString", "ProgName", "BundleID",
                "Request", "QueryType", "Label", "Key", "Domain", "Service", "PairRecord",
                "Value", "Result", "Status", "Error", "Port", "PortNumber", "DeviceID",
                "DeviceName", "ProductType", "ProductVersion", "BuildVersion",
                "UniqueDeviceID", "SerialNumber", "ActivationState", "BrickState",
                "InternationalMobileEquipmentIdentity", "MobileEquipmentIdentifier",
                "UniqueChipID", "DieID", "HardwareModel", "MLBSerialNumber",
                "BasebandVersion", "BasebandStatus", "PasswordProtected",
                "MobileGestalt", "SavageSerialNumber", "YonkersSerialNumber"
            ];

            foreach (var k in knownKeys)
            {
                int idx = ascii.IndexOf(k, StringComparison.Ordinal);
                if (idx >= 0 && idx + k.Length + 1 < ascii.Length)
                {
                    int start = idx + k.Length;
                    while (start < ascii.Length && (ascii[start] < 32 || ascii[start] > 126))
                    {
                        start++;
                    }

                    int end = start;
                    while (end < ascii.Length && ascii[end] >= 32 && ascii[end] <= 126)
                    {
                        end++;
                    }

                    if (end > start && (end - start) < 128)
                    {
                        string val = ascii[start..end].Trim();
                        if (!string.IsNullOrWhiteSpace(val) && !val.Equals(k, StringComparison.OrdinalIgnoreCase))
                        {
                            result[k] = val;
                        }
                    }
                }
            }
        }
        catch { }
    }
}
