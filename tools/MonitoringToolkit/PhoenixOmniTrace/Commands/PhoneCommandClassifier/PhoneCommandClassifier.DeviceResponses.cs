using System;
using System.Collections.Generic;
using System.Linq;

namespace PhoenixGSM.OmniTrace.Commands;

public static partial class PhoneCommandClassifier
{
    public static bool IsPhoneDeviceResponse(
        string command,
        string summary,
        string direction,
        string protocol,
        string categoryName,
        string additionalDetails = "")
    {
        string cmd = (command ?? "").Trim();
        string sum = (summary ?? "").Trim();
        string dir = (direction ?? "").Trim().ToUpperInvariant();
        string proto = (protocol ?? "").Trim();
        string cat = (categoryName ?? "").Trim();

        if (cat.Equals("Process", StringComparison.OrdinalIgnoreCase) ||
            cat.Equals("NetworkUrl", StringComparison.OrdinalIgnoreCase) ||
            cat.Equals("InProcess", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (sum.Contains("updater.exe", StringComparison.OrdinalIgnoreCase) ||
            sum.Contains("drvinst.exe", StringComparison.OrdinalIgnoreCase) ||
            cmd.Contains("GoogleUpdater", StringComparison.OrdinalIgnoreCase) ||
            sum.Contains("svchost.exe", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        bool isInbound = dir is "IN" or "DEV->HOST" or "<<" or "--" ||
                         sum.StartsWith("[ADB-STREAM] IN:", StringComparison.OrdinalIgnoreCase) ||
                         sum.StartsWith("[USB-RAW] IN", StringComparison.OrdinalIgnoreCase) ||
                         sum.StartsWith("[ADB-GETPROP-SUMMARY]", StringComparison.OrdinalIgnoreCase) ||
                         cmd.StartsWith("DATA IN", StringComparison.OrdinalIgnoreCase);

        if (cat.Equals("AdbProxy", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("ADB", StringComparison.OrdinalIgnoreCase) ||
            proto.Equals("RAW-BULK", StringComparison.OrdinalIgnoreCase))
        {
            if (proto.Equals("ADB-STREAM", StringComparison.OrdinalIgnoreCase) ||
                sum.StartsWith("[ADB-GETPROP-SUMMARY]", StringComparison.OrdinalIgnoreCase))
            {
                if (cmd.StartsWith("device::ro.product.", StringComparison.OrdinalIgnoreCase)) return false;
                return true;
            }

            if (proto.Equals("RAW-BULK", StringComparison.OrdinalIgnoreCase) && isInbound)
            {
                if (sum.Contains("STAT...", StringComparison.Ordinal) ||
                    sum.Contains("vC=+", StringComparison.Ordinal))
                {
                    return false;
                }
                return true;
            }

            if (isInbound && (cmd.StartsWith("<<") ||
                              cmd.StartsWith("WRTE") ||
                              cmd.StartsWith("OKAY") ||
                              cmd.StartsWith("FAIL") ||
                              sum.Contains("<<") ||
                              sum.Contains("shell:")))
            {
                if (cmd is "CLSE" or "CNXN") return false;
                return true;
            }
            return isInbound && cmd.StartsWith("<<");
        }

        if (cat.Equals("SerialPort", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("AT", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("SERIAL", StringComparison.OrdinalIgnoreCase))
        {
            if (cmd.StartsWith("[") && cmd.Contains("]: [") && !isInbound)
                return false;

            if (cmd.StartsWith("OK", StringComparison.OrdinalIgnoreCase) ||
                cmd.StartsWith("ERROR", StringComparison.OrdinalIgnoreCase) ||
                cmd.StartsWith("+CME ERROR", StringComparison.OrdinalIgnoreCase) ||
                cmd.StartsWith("+CSQ:", StringComparison.OrdinalIgnoreCase) ||
                cmd.StartsWith("+CPIN:", StringComparison.OrdinalIgnoreCase) ||
                cmd.StartsWith("+CGMM:", StringComparison.OrdinalIgnoreCase) ||
                cmd.StartsWith("+GMM:", StringComparison.OrdinalIgnoreCase) ||
                sum.Contains("[MODEM-USB] IN", StringComparison.OrdinalIgnoreCase) ||
                (isInbound && cmd.StartsWith("<<")))
            {
                return true;
            }
            return isInbound && !cmd.StartsWith("RAW #");
        }

        if (proto.Contains("FASTBOOT", StringComparison.OrdinalIgnoreCase))
        {
            return isInbound ||
                   cmd.StartsWith("OKAY", StringComparison.OrdinalIgnoreCase) ||
                   cmd.StartsWith("FAIL", StringComparison.OrdinalIgnoreCase) ||
                   cmd.StartsWith("INFO", StringComparison.OrdinalIgnoreCase) ||
                   cmd.StartsWith("DATA", StringComparison.OrdinalIgnoreCase);
        }

        if (cat.Equals("MediaTek", StringComparison.OrdinalIgnoreCase) || proto.Contains("MTK", StringComparison.OrdinalIgnoreCase))
        {
            return isInbound || cmd is "DA_STATUS_OK" or "DA_STATUS_CONFIRM" or "DA_STATUS_FAIL" || sum.Contains("BROM ACK");
        }

        if (cat.Equals("QualcommEdl", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("SAHARA", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("FIREHOSE", StringComparison.OrdinalIgnoreCase))
        {
            return isInbound || cmd.Contains("<response") || cmd.Contains("ACK") || sum.Contains("HELLO_RESP");
        }

        if (cat.Equals("UnisocSpd", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("SPD", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("FDL", StringComparison.OrdinalIgnoreCase))
        {
            return isInbound || cmd.Contains("ACK") || sum.Contains("BSL_REP_ACK");
        }

        if (cat.Equals("AppleIos", StringComparison.OrdinalIgnoreCase))
        {
            return isInbound;
        }

        return false;
    }

    public static string? ExtractPureResponse(
        string command,
        string summary,
        string direction,
        string protocol,
        string categoryName,
        string payloadAscii = "",
        string additionalDetails = "")
    {
        if (!IsPhoneDeviceResponse(command, summary, direction, protocol, categoryName, additionalDetails))
            return null;

        string cmd = (command ?? "").Trim();
        string sum = (summary ?? "").Trim();
        string payload = (payloadAscii ?? "").Trim();

        if (cmd.Equals("GETPROP SUMMARY", StringComparison.OrdinalIgnoreCase))
        {
            return sum.Replace("[ADB-GETPROP-SUMMARY]", "").Trim();
        }

        if (cmd.StartsWith("DATA IN", StringComparison.OrdinalIgnoreCase))
        {
            string rawResp = !string.IsNullOrWhiteSpace(payload) ? payload : sum;
            int colonIdx = rawResp.IndexOf(": ", StringComparison.Ordinal);
            if (rawResp.StartsWith("[USB-RAW]", StringComparison.OrdinalIgnoreCase) && colonIdx > 0)
            {
                rawResp = rawResp[(colonIdx + 2)..];
            }
            return CleanResponseText(rawResp);
        }

        if (cmd.StartsWith("<<", StringComparison.OrdinalIgnoreCase))
            cmd = cmd[2..].Trim();

        if (cmd.StartsWith("[MODEM-USB] IN: ", StringComparison.OrdinalIgnoreCase))
            cmd = cmd["[MODEM-USB] IN: ".Length..].Trim();

        if (cmd.StartsWith("WRTE -> ", StringComparison.OrdinalIgnoreCase))
            cmd = cmd["WRTE -> ".Length..].Trim();

        string candidate = !string.IsNullOrWhiteSpace(cmd) ? cmd : payload;
        return CleanResponseText(candidate);
    }

    private static string? CleanResponseText(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        string cleaned = text.Trim('\r', '\n', '\t', ' ', '\0', '.');
        if (string.IsNullOrWhiteSpace(cleaned)) return null;
        if (cleaned.StartsWith("STAT...", StringComparison.Ordinal) ||
            cleaned.StartsWith("vC=+", StringComparison.Ordinal) ||
            cleaned.StartsWith("53 54 41 54", StringComparison.OrdinalIgnoreCase) ||
            cleaned.StartsWith("53544154", StringComparison.OrdinalIgnoreCase))
            return null;

        var lines = cleaned.Split(new[] { "\r\n", "\r", "\n", " | " }, StringSplitOptions.RemoveEmptyEntries)
                           .Select(l => l.Trim())
                           .Where(l => !string.IsNullOrWhiteSpace(l) &&
                                       !l.All(c => c == '*' || c == '-' || c == ' ') &&
                                       !IsTransportProtocolSymbol(l))
                           .ToList();

        if (lines.Count == 0) return null;
        return string.Join(" | ", lines).Replace("OK..#", "OK #");
    }

    private static bool IsTransportProtocolSymbol(string line)
    {
        string t = line.Trim('\r', '\n', '\t', ' ', '\0', '.');
        if (t.Equals("STAT", StringComparison.OrdinalIgnoreCase) ||
            t.Equals("CLSE", StringComparison.OrdinalIgnoreCase) ||
            t.Equals("WRTE", StringComparison.OrdinalIgnoreCase) ||
            t.Equals("OKAY", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        string hexClean = t.Replace(" ", "");
        if (hexClean.StartsWith("53544154", StringComparison.OrdinalIgnoreCase) || // STAT
            hexClean.StartsWith("434C5345", StringComparison.OrdinalIgnoreCase) || // CLSE
            hexClean.StartsWith("57525445", StringComparison.OrdinalIgnoreCase) || // WRTE
            hexClean.StartsWith("4F4B4159", StringComparison.OrdinalIgnoreCase))   // OKAY
        {
            return true;
        }

        return false;
    }
}
