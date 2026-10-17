using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PhoenixGSM.OmniTrace.Commands;

/// <summary>
/// Dedicated classifier to isolate pure Host-to-Device commands directed to a connected phone,
/// classify their exact command type (ADB-SHELL, ADB-AT-RIL, MODEM-AT, MTK-BROM, etc.),
/// filter out binary ELF transfer chunks and host OS background noise, and pair clean device responses.
/// </summary>
public static class PhoneCommandClassifier
{
    public static bool IsCorruptedBinaryOrSyncNoise(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return true;
        string trimmed = text.Trim();

        // 1. Sync protocol control tokens & empty framing
        if (trimmed.Equals("sync:", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("STAT", StringComparison.Ordinal) ||
            trimmed.StartsWith("SEND", StringComparison.Ordinal) ||
            trimmed.StartsWith("DONE", StringComparison.Ordinal) ||
            trimmed.Contains("DONE?", StringComparison.Ordinal) ||
            trimmed.Equals("WRTEa", StringComparison.Ordinal) ||
            trimmed.Equals("OPEN -> WRTEa", StringComparison.OrdinalIgnoreCase) ||
            trimmed.Equals("WRTE -> WRTEa", StringComparison.OrdinalIgnoreCase) ||
            trimmed.Equals("host::", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // 2. ELF binary chunks leaked into text
        if (trimmed.Contains(",33188DATA", StringComparison.Ordinal) ||
            trimmed.Contains(",33261DATA", StringComparison.Ordinal) ||
            (trimmed.Contains("ELF") && (trimmed.Contains("Q?td") || trimmed.Contains("/system/"))) ||
            trimmed.Contains("/system/?bin/l", StringComparison.Ordinal))
        {
            return true;
        }

        // 3. Any non-whitespace control character (< 0x20 or >= 0x7F) or '?' replacement character
        //    (except legitimate AT queries ending in '?' or '=?' or URL query strings in shell commands)
        bool isShellOrAt = trimmed.StartsWith("shell:", StringComparison.OrdinalIgnoreCase) ||
                           trimmed.StartsWith("AT", StringComparison.OrdinalIgnoreCase);

        int questionCount = 0;
        foreach (char c in trimmed)
        {
            if (c < 0x20 && c != '\r' && c != '\n' && c != '\t')
                return true;
            if (c >= 0x7F)
                return true;
            if (c == '?')
                questionCount++;
        }

        if (questionCount > 0)
        {
            if (!isShellOrAt) return true;
            if (questionCount > 2) return true;
        }

        if (trimmed.Length < 2) return true;

        return false;
    }

    public static bool IsPhoneDirectedCommand(
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

        // 0. Reject corrupted binary ELF chunks and low-level sync tokens immediately
        if (IsCorruptedBinaryOrSyncNoise(cmd))
        {
            return false;
        }

        // Exclude handshake packets (AUTH, CNXN) and unparsed generic frame noise (e.g. "... Frame (... bytes)")
        if (cmd.Equals("AUTH", StringComparison.OrdinalIgnoreCase) ||
            cmd.StartsWith("43 4E 58 4E", StringComparison.OrdinalIgnoreCase) ||
            System.Text.RegularExpressions.Regex.IsMatch(cmd, @"(?i)Frame\s*\([^)]*bytes\)$") ||
            System.Text.RegularExpressions.Regex.IsMatch(sum, @"(?i)Frame\s*\([^)]*bytes\)$"))
        {
            return false;
        }

        // Reject bare "/data/local/tmp/AT" when it is merely the filename argument to STAT/SEND
        if (cmd.Equals("/data/local/tmp/AT", StringComparison.OrdinalIgnoreCase) &&
            !sum.Contains("shell:/data/local/tmp/AT", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // 1. Exclude host-side internal processes and external network downloads
        if (cat.Equals("Process", StringComparison.OrdinalIgnoreCase) ||
            cat.Equals("NetworkUrl", StringComparison.OrdinalIgnoreCase) ||
            cat.Equals("InProcess", StringComparison.OrdinalIgnoreCase) ||
            proto.Equals("GSM-TOOL", StringComparison.OrdinalIgnoreCase) ||
            proto.Equals("INPROCESS", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // 2. Exclude Windows host services & background update pollers
        if (sum.Contains("updater.exe", StringComparison.OrdinalIgnoreCase) ||
            sum.Contains("drvinst.exe", StringComparison.OrdinalIgnoreCase) ||
            cmd.Contains("GoogleUpdater", StringComparison.OrdinalIgnoreCase) ||
            cmd.Contains("NOTEPAD:", StringComparison.OrdinalIgnoreCase) ||
            cmd.Contains("SEARCHPROTOCOLHOST:", StringComparison.OrdinalIgnoreCase) ||
            cmd.Equals("SUBPROCESS_EXECUTION", StringComparison.OrdinalIgnoreCase) ||
            sum.Contains("svchost.exe", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // 3. Staged / In-Flight Pushed Artifacts & ADB-SYNC PUSH
        if (cat.Equals("ArtifactVault", StringComparison.OrdinalIgnoreCase) ||
            proto.Equals("ADB-SYNC", StringComparison.OrdinalIgnoreCase) ||
            cmd.StartsWith("PUSH ", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        bool isOutbound = dir is "OUT" or "HOST->DEV" or ">>" or "FILE >>" or "--";

        // 4. ADB Proxy & ADB Wire commands directed to phone
        if (cat.Equals("AdbProxy", StringComparison.OrdinalIgnoreCase) || 
            proto.Contains("ADB", StringComparison.OrdinalIgnoreCase))
        {
            if (proto.Equals("ADB-STREAM", StringComparison.OrdinalIgnoreCase) && !isOutbound)
            {
                return false;
            }
            if (sum.StartsWith("[ADB-STREAM] IN:", StringComparison.OrdinalIgnoreCase) ||
                sum.StartsWith("[ADB-GETPROP-SUMMARY]", StringComparison.OrdinalIgnoreCase) ||
                cmd.Equals("GETPROP SUMMARY", StringComparison.OrdinalIgnoreCase) ||
                cmd.StartsWith("device::ro.product.", StringComparison.OrdinalIgnoreCase) ||
                cmd.StartsWith("Result: Parcel(", StringComparison.OrdinalIgnoreCase) ||
                cmd.Equals("Enforcing", StringComparison.OrdinalIgnoreCase) ||
                cmd.Equals("Permissive", StringComparison.OrdinalIgnoreCase) ||
                cmd.Equals("restarting in USB mode", StringComparison.OrdinalIgnoreCase) ||
                cmd.Contains("SAMSUNG AT Ril Command TOOL", StringComparison.OrdinalIgnoreCase) ||
                cmd.Contains("Samsung System UID Tools", StringComparison.OrdinalIgnoreCase) ||
                cmd.StartsWith("Product Name", StringComparison.OrdinalIgnoreCase) ||
                cmd.StartsWith("Product Model", StringComparison.OrdinalIgnoreCase) ||
                cmd.StartsWith("Serial Number", StringComparison.OrdinalIgnoreCase) ||
                cmd.StartsWith("Build  Number", StringComparison.OrdinalIgnoreCase) ||
                cmd.Contains("AuthKey :", StringComparison.OrdinalIgnoreCase) ||
                cmd.Contains("AuthKey:", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (proto.Equals("ADB-RIL-IPC", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (cmd.StartsWith("OPEN ->", StringComparison.OrdinalIgnoreCase) ||
                cmd.StartsWith("OPEN shell:", StringComparison.OrdinalIgnoreCase) ||
                cmd.StartsWith("shell:", StringComparison.OrdinalIgnoreCase) ||
                cmd.StartsWith("usb:", StringComparison.OrdinalIgnoreCase) ||
                cmd.StartsWith("reboot", StringComparison.OrdinalIgnoreCase) ||
                cmd.StartsWith("060100", StringComparison.OrdinalIgnoreCase) ||
                cmd.StartsWith("120D00", StringComparison.OrdinalIgnoreCase) ||
                sum.Contains("chmod", StringComparison.OrdinalIgnoreCase) ||
                sum.Contains("pm ", StringComparison.OrdinalIgnoreCase) ||
                sum.Contains("am ", StringComparison.OrdinalIgnoreCase) ||
                sum.Contains("logcat", StringComparison.OrdinalIgnoreCase) ||
                sum.Contains("service call", StringComparison.OrdinalIgnoreCase) ||
                sum.Contains("/data/local/tmp", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (cmd is "OKAY" or "CLSE" or "CNXN" or "PHONE CONNECTED" or "PHONE REMOVED")
            {
                return false;
            }

            if (isOutbound && cmd.StartsWith("WRTE", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return isOutbound && !string.IsNullOrWhiteSpace(cmd);
        }

        // 5. Modem AT Commands & Samsung RIL Injections directed to phone
        if (cat.Equals("SerialPort", StringComparison.OrdinalIgnoreCase) || 
            proto.Contains("AT", StringComparison.OrdinalIgnoreCase) || 
            proto.Contains("SERIAL", StringComparison.OrdinalIgnoreCase))
        {
            if (cmd.StartsWith("[") && cmd.Contains("]: ["))
            {
                return false;
            }

            if (cmd is "PORT ATTACHED" or "PORT REMOVED" or "PHONE CONNECTED" or "PHONE REMOVED")
            {
                return false;
            }

            if (cmd.StartsWith("AT", StringComparison.OrdinalIgnoreCase) ||
                cmd.StartsWith("AT+", StringComparison.OrdinalIgnoreCase) ||
                cmd.StartsWith("AT^", StringComparison.OrdinalIgnoreCase) ||
                cmd.StartsWith("AT%", StringComparison.OrdinalIgnoreCase) ||
                cmd.StartsWith("AT$", StringComparison.OrdinalIgnoreCase) ||
                cmd.StartsWith("AT*", StringComparison.OrdinalIgnoreCase) ||
                cmd.StartsWith("AT#", StringComparison.OrdinalIgnoreCase) ||
                cmd.Contains("OEM_HOOK", StringComparison.OrdinalIgnoreCase) ||
                cmd.StartsWith("060100", StringComparison.OrdinalIgnoreCase) ||
                cmd.StartsWith("120D00", StringComparison.OrdinalIgnoreCase) ||
                cmd.Contains("/data/local/tmp", StringComparison.OrdinalIgnoreCase) ||
                sum.Contains("OEM_HOOK", StringComparison.OrdinalIgnoreCase) ||
                sum.Contains("[MODEM-USB] OUT", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (isOutbound && !cmd.StartsWith("[") && !cmd.StartsWith("RAW #"))
            {
                return true;
            }

            return false;
        }

        // 6. Fastboot Flash & Config Commands
        if (proto.Contains("FASTBOOT", StringComparison.OrdinalIgnoreCase))
        {
            return isOutbound || 
                   cmd.StartsWith("flash", StringComparison.OrdinalIgnoreCase) ||
                   cmd.StartsWith("erase", StringComparison.OrdinalIgnoreCase) ||
                   cmd.StartsWith("oem", StringComparison.OrdinalIgnoreCase) ||
                   cmd.StartsWith("reboot", StringComparison.OrdinalIgnoreCase);
        }

        // 7. MediaTek BROM / DA Commands directed to phone
        if (cat.Equals("MediaTek", StringComparison.OrdinalIgnoreCase) || proto.Contains("MTK", StringComparison.OrdinalIgnoreCase))
        {
            if (isOutbound && cmd is not "DA_STATUS_FAIL" and not "DA_STATUS_OK")
            {
                return true;
            }
            return false;
        }

        // 8. Qualcomm EDL / Sahara / Firehose Commands directed to phone
        if (cat.Equals("QualcommEdl", StringComparison.OrdinalIgnoreCase) || 
            proto.Contains("SAHARA", StringComparison.OrdinalIgnoreCase) || 
            proto.Contains("FIREHOSE", StringComparison.OrdinalIgnoreCase))
        {
            return isOutbound;
        }

        // 9. Unisoc / Spreadtrum FDL Commands directed to phone
        if (cat.Equals("UnisocSpd", StringComparison.OrdinalIgnoreCase) || 
            proto.Contains("SPD", StringComparison.OrdinalIgnoreCase) || 
            proto.Contains("FDL", StringComparison.OrdinalIgnoreCase))
        {
            return isOutbound;
        }

        // 10. Apple iOS Device Commands
        if (cat.Equals("AppleIos", StringComparison.OrdinalIgnoreCase))
        {
            return isOutbound;
        }

        // 11. Raw USB transfers carrying commands to phone
        if (cat.Equals("UsbDriver", StringComparison.OrdinalIgnoreCase) && isOutbound)
        {
            if (sum.Contains("shell:", StringComparison.OrdinalIgnoreCase) ||
                sum.Contains("chmod", StringComparison.OrdinalIgnoreCase) ||
                sum.Contains("/data/local/tmp", StringComparison.OrdinalIgnoreCase) ||
                sum.Contains("reboot", StringComparison.OrdinalIgnoreCase) ||
                sum.Contains("AT+", StringComparison.OrdinalIgnoreCase) ||
                cmd.Contains("060100", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Returns a clear, standardized Command Type label for organized export (e.g. ADB-SHELL, ADB-AT-RIL, MODEM-AT, MTK-BROM).
    /// </summary>
    public static string ClassifyCommandTypeTag(
        string command,
        string protocol,
        string categoryName,
        string summary = "")
    {
        string cmd = (command ?? "").Trim();
        string proto = (protocol ?? "").Trim();
        string cat = (categoryName ?? "").Trim();

        bool isAtToolExecution = cmd.Equals("/data/local/tmp/AT", StringComparison.OrdinalIgnoreCase) ||
                                 cmd.StartsWith("/data/local/tmp/AT ", StringComparison.OrdinalIgnoreCase);

        if (cat.Equals("ArtifactVault", StringComparison.OrdinalIgnoreCase) ||
            proto.Equals("ADB-SYNC", StringComparison.OrdinalIgnoreCase) ||
            cmd.StartsWith("PUSH ", StringComparison.OrdinalIgnoreCase) ||
            (!cmd.StartsWith("shell:", StringComparison.OrdinalIgnoreCase) &&
             !isAtToolExecution &&
             (cmd.StartsWith("/data/local/tmp/", StringComparison.OrdinalIgnoreCase) ||
              cmd.StartsWith("/sdcard/", StringComparison.OrdinalIgnoreCase))))
        {
            return "ADB-PUSH";
        }

        if (proto.Equals("ADB-RIL-IPC", StringComparison.OrdinalIgnoreCase) ||
            cmd.StartsWith("060100", StringComparison.OrdinalIgnoreCase) ||
            cmd.StartsWith("120D00", StringComparison.OrdinalIgnoreCase) ||
            cmd.StartsWith("514200", StringComparison.OrdinalIgnoreCase) ||
            cmd.StartsWith("516400", StringComparison.OrdinalIgnoreCase) ||
            (cmd.Length >= 64 && cmd.All(Uri.IsHexDigit)))
        {
            return "ADB-AT-RIL";
        }

        if (cat.Equals("MediaTek", StringComparison.OrdinalIgnoreCase) || proto.Contains("MTK", StringComparison.OrdinalIgnoreCase))
        {
            return proto.Contains("DA", StringComparison.OrdinalIgnoreCase) ? "MTK-DA" : "MTK-BROM";
        }

        if (proto.Contains("FASTBOOT", StringComparison.OrdinalIgnoreCase))
        {
            return "FASTBOOT";
        }

        if (cat.Equals("QualcommEdl", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("FIREHOSE", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("SAHARA", StringComparison.OrdinalIgnoreCase))
        {
            return proto.Contains("FIREHOSE", StringComparison.OrdinalIgnoreCase) ? "QCOM-FIREHOSE" : "QCOM-SAHARA";
        }

        if (cat.Equals("UnisocSpd", StringComparison.OrdinalIgnoreCase) || proto.Contains("SPD", StringComparison.OrdinalIgnoreCase))
        {
            return "SPD-FDL";
        }

        if (cat.Equals("SerialPort", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("SERIAL", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("MODEM", StringComparison.OrdinalIgnoreCase) ||
            cmd.StartsWith("AT", StringComparison.OrdinalIgnoreCase))
        {
            if (proto.Contains("DIAG", StringComparison.OrdinalIgnoreCase)) return "QUALCOMM-DIAG";
            if (cat.Equals("TempFileAt", StringComparison.OrdinalIgnoreCase) || proto.Contains("STAGED", StringComparison.OrdinalIgnoreCase)) return "STAGED-AT-FILE";
            return "MODEM-AT";
        }

        if (cmd.StartsWith("usb:", StringComparison.OrdinalIgnoreCase) ||
            cmd.StartsWith("reboot", StringComparison.OrdinalIgnoreCase))
        {
            return "ADB-MODE";
        }

        if (cmd.Contains("/data/local/tmp/AT", StringComparison.OrdinalIgnoreCase) &&
            !cmd.Contains("chmod", StringComparison.OrdinalIgnoreCase))
        {
            return "ADB-AT-TOOL";
        }

        if (cmd.StartsWith("shell:", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("ADB", StringComparison.OrdinalIgnoreCase) ||
            cat.Equals("AdbProxy", StringComparison.OrdinalIgnoreCase))
        {
            return "ADB-SHELL";
        }

        return !string.IsNullOrWhiteSpace(proto) ? proto.ToUpperInvariant() : "PHONE-CMD";
    }

    public static string DecodeInlineRilHexAnnotation(string pureCmd)
    {
        if (string.IsNullOrWhiteSpace(pureCmd)) return string.Empty;
        string clean = pureCmd.Trim();
        if (clean.Length < 12 || clean.Length > 256 || clean.Length % 2 != 0) return string.Empty;
        if (!clean.All(Uri.IsHexDigit)) return string.Empty;

        try
        {
            byte[] bytes = Convert.FromHexString(clean);
            var parts = new List<string>();
            var sb = new StringBuilder();
            foreach (byte b in bytes)
            {
                if (b >= 32 && b <= 126)
                {
                    sb.Append((char)b);
                }
                else
                {
                    if (sb.Length >= 3)
                    {
                        parts.Add(sb.ToString());
                    }
                    sb.Clear();
                }
            }
            if (sb.Length >= 3)
            {
                parts.Add(sb.ToString());
            }

            if (parts.Count > 0)
            {
                return $"[ASCII: {string.Join(" | ", parts.Distinct())}]";
            }
        }
        catch { }

        return string.Empty;
    }

    public static string? ExtractPureCommand(
        string command,
        string summary,
        string direction,
        string protocol,
        string categoryName,
        string payloadAscii = "",
        string additionalDetails = "")
    {
        if (!IsPhoneDirectedCommand(command, summary, direction, protocol, categoryName, additionalDetails))
            return null;

        string cmd = (command ?? "").Trim();
        string sum = (summary ?? "").Trim();
        string proto = (protocol ?? "").Trim();
        string cat = (categoryName ?? "").Trim();
        string details = (additionalDetails ?? "").Trim();
        string payload = (payloadAscii ?? "").Trim();

        // 1. Artifacts Pushed to Device (/data/local/tmp/...)
        if (cat.Equals("ArtifactVault", StringComparison.OrdinalIgnoreCase) ||
            proto.Equals("ADB-SYNC", StringComparison.OrdinalIgnoreCase))
        {
            if (cmd.StartsWith("PUSH ", StringComparison.OrdinalIgnoreCase))
                return cmd["PUSH ".Length..].Trim();
            if (sum.Contains("/data/local/tmp", StringComparison.OrdinalIgnoreCase))
            {
                int idx = sum.IndexOf("/data/local/tmp", StringComparison.OrdinalIgnoreCase);
                int endIdx = sum.IndexOf(' ', idx);
                string path = endIdx > idx ? sum[idx..endIdx] : sum[idx..];
                return path.Trim();
            }
            if (details.Contains("Target Device Path:", StringComparison.OrdinalIgnoreCase))
            {
                foreach (var line in details.Split('\n'))
                {
                    if (line.StartsWith("Target Device Path:", StringComparison.OrdinalIgnoreCase))
                        return line["Target Device Path:".Length..].Trim();
                }
            }
            return !string.IsNullOrWhiteSpace(cmd) ? cmd : sum;
        }

        // 2. ADB Wire & ADB Shell Executions
        if (cat.Equals("AdbProxy", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("ADB", StringComparison.OrdinalIgnoreCase))
        {
            if (details.Contains("Full Command: adb ", StringComparison.OrdinalIgnoreCase))
            {
                int idx = details.IndexOf("Full Command: adb ", StringComparison.OrdinalIgnoreCase);
                int lineEnd = details.IndexOf('\n', idx);
                string adbCmd = lineEnd > idx 
                    ? details[(idx + "Full Command: adb ".Length)..lineEnd].Trim()
                    : details[(idx + "Full Command: adb ".Length)..].Trim();
                
                if (!string.IsNullOrWhiteSpace(adbCmd))
                    return adbCmd;
            }

            if (cmd.StartsWith("OPEN -> ", StringComparison.OrdinalIgnoreCase))
            {
                string inner = cmd["OPEN -> ".Length..].Trim();
                if (inner.StartsWith("shell:", StringComparison.OrdinalIgnoreCase))
                    inner = inner["shell:".Length..].Trim();
                if (IsCorruptedBinaryOrSyncNoise(inner)) return null;
                return inner;
            }

            if (cmd.StartsWith("OPEN ", StringComparison.OrdinalIgnoreCase))
            {
                string inner = cmd["OPEN ".Length..].Trim();
                if (inner.StartsWith("shell:", StringComparison.OrdinalIgnoreCase))
                    inner = inner["shell:".Length..].Trim();
                if (IsCorruptedBinaryOrSyncNoise(inner)) return null;
                return inner;
            }

            if (cmd.StartsWith("shell:", StringComparison.OrdinalIgnoreCase))
            {
                string inner = cmd["shell:".Length..].Trim();
                if (IsCorruptedBinaryOrSyncNoise(inner)) return null;
                return inner;
            }

            if (cmd.StartsWith("WRTE -> ", StringComparison.OrdinalIgnoreCase))
            {
                string inner = cmd["WRTE -> ".Length..].Trim();
                if (inner.StartsWith("shell:", StringComparison.OrdinalIgnoreCase))
                    inner = inner["shell:".Length..].Trim();
                if (IsCorruptedBinaryOrSyncNoise(inner)) return null;
                return inner;
            }

            if (cmd.StartsWith("WRTE", StringComparison.OrdinalIgnoreCase))
            {
                if (!string.IsNullOrWhiteSpace(payload) && !IsCorruptedBinaryOrSyncNoise(payload))
                    return payload.Trim('\r', '\n', '\0', ' ');
                return null;
            }

            if (cmd is "OKAY" or "CLSE" or "CNXN")
                return null;

            string annotation = DecodeInlineRilHexAnnotation(cmd);
            return !string.IsNullOrEmpty(annotation) ? $"{cmd}  {annotation}" : cmd;
        }

        // 3. Modem / Serial / Samsung RIL OEM Hook
        if (cat.Equals("SerialPort", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("AT", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("SERIAL", StringComparison.OrdinalIgnoreCase))
        {
            if (cmd.StartsWith("[MODEM-USB] OUT: ", StringComparison.OrdinalIgnoreCase))
                cmd = cmd["[MODEM-USB] OUT: ".Length..].Trim();

            if (cmd is "<CR>" or "<LF>" or "<CRLF>")
                return null;

            if (cmd.StartsWith("[") && cmd.Contains("]: ["))
                return null;

            return cmd.Trim('\r', '\n', '\0', ' ');
        }

        // 4. Fastboot
        if (proto.Contains("FASTBOOT", StringComparison.OrdinalIgnoreCase))
        {
            if (cmd.StartsWith("FASTBOOT: ", StringComparison.OrdinalIgnoreCase))
                return cmd["FASTBOOT: ".Length..].Trim();
            if (cmd.StartsWith("FASTBOOT ", StringComparison.OrdinalIgnoreCase))
                return cmd["FASTBOOT ".Length..].Trim();
            return cmd;
        }

        // 5. MediaTek BROM / DA
        if (cat.Equals("MediaTek", StringComparison.OrdinalIgnoreCase) || proto.Contains("MTK", StringComparison.OrdinalIgnoreCase))
        {
            if (cmd is "DA_STATUS_FAIL" or "DA_STATUS_OK") return null;
            return cmd;
        }

        // 6. Generic Outbound
        return !string.IsNullOrWhiteSpace(cmd) ? cmd : null;
    }

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

    public static bool IsPhoneInteraction(
        string command,
        string summary,
        string direction,
        string protocol,
        string categoryName,
        string additionalDetails = "",
        bool includeResponses = false)
    {
        if (IsPhoneDirectedCommand(command, summary, direction, protocol, categoryName, additionalDetails))
            return true;

        if (includeResponses && IsPhoneDeviceResponse(command, summary, direction, protocol, categoryName, additionalDetails))
            return true;

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
        if (cleaned.StartsWith("STAT...", StringComparison.Ordinal) || cleaned.StartsWith("vC=+", StringComparison.Ordinal))
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
        return t.Equals("STAT", StringComparison.OrdinalIgnoreCase) ||
               t.Equals("CLSE", StringComparison.OrdinalIgnoreCase) ||
               t.Equals("WRTE", StringComparison.OrdinalIgnoreCase);
    }
}
