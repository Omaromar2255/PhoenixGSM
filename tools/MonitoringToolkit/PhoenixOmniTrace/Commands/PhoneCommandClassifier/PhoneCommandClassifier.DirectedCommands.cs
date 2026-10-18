using System;
using System.Text.RegularExpressions;

namespace PhoenixGSM.OmniTrace.Commands;

public static partial class PhoneCommandClassifier
{
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
        if (IsCorruptedBinaryOrSyncNoise(cmd) ||
            cmd.Contains(".phx_keep_", StringComparison.OrdinalIgnoreCase) ||
            sum.Contains(".phx_keep_", StringComparison.OrdinalIgnoreCase) ||
            cmd.Contains("phx_pull_", StringComparison.OrdinalIgnoreCase) ||
            sum.Contains("phx_pull_", StringComparison.OrdinalIgnoreCase) ||
            cmd.Contains("FORK-SERVER SERVER", StringComparison.OrdinalIgnoreCase) ||
            cmd.Equals("ADB ADB", StringComparison.OrdinalIgnoreCase) ||
            cmd.Contains("/data/local/tmp/adb.log", StringComparison.OrdinalIgnoreCase) ||
            sum.Contains("/data/local/tmp/adb.log", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // Exclude handshake packets (AUTH, CNXN) and unparsed generic frame noise (e.g. "... Frame (... bytes)")
        if (cmd.Equals("AUTH", StringComparison.OrdinalIgnoreCase) ||
            cmd.StartsWith("43 4E 58 4E", StringComparison.OrdinalIgnoreCase) ||
            Regex.IsMatch(cmd, @"(?i)Frame\s*\([^)]*bytes\)$") ||
            Regex.IsMatch(sum, @"(?i)Frame\s*\([^)]*bytes\)$"))
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
}
