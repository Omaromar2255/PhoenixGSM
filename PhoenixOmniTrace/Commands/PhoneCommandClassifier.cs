using System;

namespace PhoenixGSM.OmniTrace.Commands;

/// <summary>
/// Dedicated classifier to isolate pure Host-to-Device commands directed to a connected phone.
/// Discards host OS background noise (GoogleUpdater, drvinst), inbound phone property/log dumps,
/// and low-level zero-action keep-alive frames.
/// </summary>
public static class PhoneCommandClassifier
{
    public static bool IsPhoneDirectedCommand(
        string command,
        string summary,
        string direction,
        string protocol,
        string categoryName,
        string additionalDetails = "")
    {
        string cmd = command ?? "";
        string sum = summary ?? "";
        string dir = (direction ?? "").Trim().ToUpperInvariant();
        string proto = protocol ?? "";
        string cat = categoryName ?? "";

        // 1. Exclude host-side internal processes and external network downloads
        if (cat.Equals("Process", StringComparison.OrdinalIgnoreCase) ||
            cat.Equals("NetworkUrl", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // 2. Exclude Windows host services & background update pollers
        if (sum.Contains("updater.exe", StringComparison.OrdinalIgnoreCase) ||
            sum.Contains("drvinst.exe", StringComparison.OrdinalIgnoreCase) ||
            cmd.Contains("GoogleUpdater", StringComparison.OrdinalIgnoreCase) ||
            sum.Contains("svchost.exe", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // 3. Staged / In-Flight Pushed Artifacts (Root tools, exploits, staged ELF/APK binaries)
        if (cat.Equals("ArtifactVault", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        bool isOutbound = dir is "OUT" or "HOST->DEV" or ">>" or "FILE >>" or "--";

        // 4. ADB Proxy & ADB Wire commands directed to phone
        if (cat.Equals("AdbProxy", StringComparison.OrdinalIgnoreCase) || 
            proto.Contains("ADB", StringComparison.OrdinalIgnoreCase))
        {
            if (cmd.StartsWith("OPEN ->", StringComparison.OrdinalIgnoreCase) ||
                cmd.StartsWith("OPEN shell:", StringComparison.OrdinalIgnoreCase) ||
                cmd.Contains("shell:", StringComparison.OrdinalIgnoreCase) ||
                cmd.Contains("sync:", StringComparison.OrdinalIgnoreCase) ||
                cmd.Contains("reboot", StringComparison.OrdinalIgnoreCase) ||
                cmd.StartsWith("WRTE -> STAT", StringComparison.OrdinalIgnoreCase) ||
                cmd.StartsWith("WRTE -> SEND", StringComparison.OrdinalIgnoreCase) ||
                sum.Contains("chmod", StringComparison.OrdinalIgnoreCase) ||
                sum.Contains("pm ", StringComparison.OrdinalIgnoreCase) ||
                sum.Contains("am ", StringComparison.OrdinalIgnoreCase) ||
                sum.Contains("logcat", StringComparison.OrdinalIgnoreCase) ||
                sum.Contains("service call", StringComparison.OrdinalIgnoreCase) ||
                sum.Contains("/data/local/tmp", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            // Exclude empty handshake ACKs (OKAY, CLSE, raw CNXN)
            if (cmd is "OKAY" or "CLSE" or "CNXN" && !sum.Contains("shell:", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            // Interactive STDIN stream to device binary (HOST -> DEV WRTE)
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
            // Exclude inbound property dump strings misclassified as AT
            if (cmd.StartsWith("[") && cmd.Contains("]: ["))
            {
                return false;
            }

            if (cmd.StartsWith("AT", StringComparison.OrdinalIgnoreCase) ||
                cmd.StartsWith("AT+", StringComparison.OrdinalIgnoreCase) ||
                cmd.StartsWith("AT^", StringComparison.OrdinalIgnoreCase) ||
                cmd.StartsWith("AT%", StringComparison.OrdinalIgnoreCase) ||
                cmd.StartsWith("AT$", StringComparison.OrdinalIgnoreCase) ||
                cmd.Contains("OEM_HOOK", StringComparison.OrdinalIgnoreCase) ||
                cmd.StartsWith("060100", StringComparison.OrdinalIgnoreCase) ||
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

        // 10. Apple iOS Device Commands (Lockdown, Recovery, DFU, Ramdisk)
        if (cat.Equals("AppleIos", StringComparison.OrdinalIgnoreCase))
        {
            return isOutbound;
        }

        // 11. Raw USB transfers carrying commands to phone
        if (cat.Equals("UsbDriver", StringComparison.OrdinalIgnoreCase) && isOutbound)
        {
            if (sum.Contains("shell:", StringComparison.OrdinalIgnoreCase) ||
                sum.Contains("OPEN", StringComparison.OrdinalIgnoreCase) ||
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
    /// Extracts the 100% pure, clean, un-truncated command directed to the mobile phone.
    /// Strips transport framing (e.g. "OPEN -> shell:", "OPEN -> ", "WRTE -> "),
    /// filters out low-level zero-action tokens and property dumps,
    /// and returns the exact executable command line or binary payload string.
    /// </summary>
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
        if (cat.Equals("ArtifactVault", StringComparison.OrdinalIgnoreCase))
        {
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
            // If full command is recorded in details, check if it's cleaner
            if (details.Contains("Full Command: adb ", StringComparison.OrdinalIgnoreCase))
            {
                int idx = details.IndexOf("Full Command: adb ", StringComparison.OrdinalIgnoreCase);
                int lineEnd = details.IndexOf('\n', idx);
                string adbCmd = lineEnd > idx 
                    ? details[(idx + "Full Command: adb ".Length)..lineEnd].Trim()
                    : details[(idx + "Full Command: adb ".Length)..].Trim();
                
                if (adbCmd.StartsWith("shell ", StringComparison.OrdinalIgnoreCase))
                    return adbCmd["shell ".Length..].Trim();
                if (!string.IsNullOrWhiteSpace(adbCmd))
                    return adbCmd;
            }

            if (cmd.StartsWith("OPEN -> shell:", StringComparison.OrdinalIgnoreCase))
                return cmd["OPEN -> shell:".Length..].Trim();

            if (cmd.StartsWith("OPEN -> exec:", StringComparison.OrdinalIgnoreCase))
                return cmd["OPEN -> exec:".Length..].Trim();

            if (cmd.StartsWith("OPEN -> ", StringComparison.OrdinalIgnoreCase))
            {
                string inner = cmd["OPEN -> ".Length..].Trim();
                if (inner.StartsWith("shell:", StringComparison.OrdinalIgnoreCase))
                    return inner["shell:".Length..].Trim();
                return inner;
            }

            if (cmd.StartsWith("OPEN shell:", StringComparison.OrdinalIgnoreCase))
                return cmd["OPEN shell:".Length..].Trim();

            if (cmd.StartsWith("shell:", StringComparison.OrdinalIgnoreCase))
                return cmd["shell:".Length..].Trim();

            if (cmd.StartsWith("WRTE -> ", StringComparison.OrdinalIgnoreCase))
                return cmd["WRTE -> ".Length..].Trim();

            if (cmd.StartsWith("WRTE", StringComparison.OrdinalIgnoreCase))
            {
                if (!string.IsNullOrWhiteSpace(payload))
                    return payload.Trim('\r', '\n', '\0', ' ');
                return null;
            }

            if (cmd is "OKAY" or "CLSE" or "CNXN")
                return null;

            return cmd;
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

    /// <summary>
    /// Identifies incoming responses received from the connected mobile phone (Device to Host).
    /// Filters out background keep-alive ping ACKs while capturing genuine status, stdout, and protocol responses.
    /// </summary>
    public static bool IsPhoneDeviceResponse(
        string command,
        string summary,
        string direction,
        string protocol,
        string categoryName,
        string additionalDetails = "")
    {
        string cmd = command ?? "";
        string sum = summary ?? "";
        string dir = (direction ?? "").Trim().ToUpperInvariant();
        string proto = protocol ?? "";
        string cat = categoryName ?? "";

        // 1. Exclude host processes and general network
        if (cat.Equals("Process", StringComparison.OrdinalIgnoreCase) ||
            cat.Equals("NetworkUrl", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // 2. Exclude Windows host services & background pollers
        if (sum.Contains("updater.exe", StringComparison.OrdinalIgnoreCase) ||
            sum.Contains("drvinst.exe", StringComparison.OrdinalIgnoreCase) ||
            cmd.Contains("GoogleUpdater", StringComparison.OrdinalIgnoreCase) ||
            sum.Contains("svchost.exe", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        bool isInbound = dir is "IN" or "DEV->HOST" or "<<" or "--";

        // 3. ADB Inbound Shell STDOUT & Responses
        if (cat.Equals("AdbProxy", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("ADB", StringComparison.OrdinalIgnoreCase))
        {
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

        // 4. AT Modem / Serial Responses
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

        // 5. Fastboot Responses
        if (proto.Contains("FASTBOOT", StringComparison.OrdinalIgnoreCase))
        {
            return isInbound ||
                   cmd.StartsWith("OKAY", StringComparison.OrdinalIgnoreCase) ||
                   cmd.StartsWith("FAIL", StringComparison.OrdinalIgnoreCase) ||
                   cmd.StartsWith("INFO", StringComparison.OrdinalIgnoreCase) ||
                   cmd.StartsWith("DATA", StringComparison.OrdinalIgnoreCase);
        }

        // 6. MediaTek BROM / DA Responses
        if (cat.Equals("MediaTek", StringComparison.OrdinalIgnoreCase) || proto.Contains("MTK", StringComparison.OrdinalIgnoreCase))
        {
            return isInbound || cmd is "DA_STATUS_OK" or "DA_STATUS_CONFIRM" or "DA_STATUS_FAIL" || sum.Contains("BROM ACK");
        }

        // 7. Qualcomm EDL / Sahara / Firehose Responses
        if (cat.Equals("QualcommEdl", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("SAHARA", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("FIREHOSE", StringComparison.OrdinalIgnoreCase))
        {
            return isInbound || cmd.Contains("<response") || cmd.Contains("ACK") || sum.Contains("HELLO_RESP");
        }

        // 8. Unisoc / Spreadtrum Responses
        if (cat.Equals("UnisocSpd", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("SPD", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("FDL", StringComparison.OrdinalIgnoreCase))
        {
            return isInbound || cmd.Contains("ACK") || sum.Contains("BSL_REP_ACK");
        }

        // 9. Apple iOS Responses
        if (cat.Equals("AppleIos", StringComparison.OrdinalIgnoreCase))
        {
            return isInbound;
        }

        return false;
    }

    /// <summary>
    /// Checks if the event is a phone interaction: an outbound command or (optionally) an incoming response.
    /// </summary>
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

    /// <summary>
    /// Extracts the clean response text received from the mobile phone without framing.
    /// </summary>
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
        if (cmd.StartsWith("<<", StringComparison.OrdinalIgnoreCase))
            cmd = cmd[2..].Trim();

        if (cmd.StartsWith("[MODEM-USB] IN: ", StringComparison.OrdinalIgnoreCase))
            cmd = cmd["[MODEM-USB] IN: ".Length..].Trim();

        if (cmd.StartsWith("WRTE -> ", StringComparison.OrdinalIgnoreCase))
            cmd = cmd["WRTE -> ".Length..].Trim();

        return !string.IsNullOrWhiteSpace(cmd) ? cmd : (!string.IsNullOrWhiteSpace(payloadAscii) ? payloadAscii : null);
    }
}
