using System;
using System.IO;
using PhoenixGSM.OmniTrace.Decoders;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.Commands;

public sealed partial class UniversalToolCommandInterceptor
{
    public static InterceptedToolCommand AnalyzeCommand(
        string cleanExe,
        string exePath,
        string cmdLine,
        string parentName,
        int parentPid,
        int pid,
        string engine,
        DateTime timestamp)
    {
        string trimmedCmd = (cmdLine ?? string.Empty).Trim();
        var item = new InterceptedToolCommand
        {
            ProcessId = pid,
            ParentProcessId = parentPid,
            ProcessName = cleanExe,
            ParentProcessName = parentName,
            ExecutablePath = exePath,
            CommandLine = trimmedCmd,
            Timestamp = timestamp,
            InterceptionEngine = engine
        };

        // ══════════════════════════════════════════════════════════════════════
        // CASE 1: libusb-win32 / WinUSB Filter Driver Commands (filter-x64, etc.)
        // ══════════════════════════════════════════════════════════════════════
        if (cleanExe.Contains("filter-") || cleanExe.Contains("install-filter") || trimmedCmd.Contains("filter-x64") || trimmedCmd.Contains("filter-x86"))
        {
            string action = trimmedCmd.Contains("remove", StringComparison.OrdinalIgnoreCase) || trimmedCmd.Contains("uninstall", StringComparison.OrdinalIgnoreCase)
                ? "UNINSTALL"
                : "INSTALL";

            string devMatch = ExtractDevicePattern(trimmedCmd);

            if (trimmedCmd.Contains("VID_0E8D", StringComparison.OrdinalIgnoreCase))
            {
                item.Category = "MediaTek";
                item.Protocol = KnownProtocol.MtkBrom;
                item.ProtocolName = "LIBUSB-FILTER";
                item.SourceTag = "MTK-FILTER";
                item.CommandAction = $"FILTER {action}: {devMatch} (MTK BROM/PRELOADER)";
                item.TargetOrEndpoint = devMatch;
            }
            else if (trimmedCmd.Contains("VID_05C6", StringComparison.OrdinalIgnoreCase) || trimmedCmd.Contains("9008", StringComparison.OrdinalIgnoreCase))
            {
                item.Category = "QualcommEdl";
                item.Protocol = KnownProtocol.QualcommSahara;
                item.ProtocolName = "LIBUSB-FILTER";
                item.SourceTag = "QCOM-FILTER";
                item.CommandAction = $"FILTER {action}: {devMatch} (QUALCOMM EDL 9008)";
                item.TargetOrEndpoint = devMatch;
            }
            else if (trimmedCmd.Contains("VID_1782", StringComparison.OrdinalIgnoreCase))
            {
                item.Category = "UnisocSpd";
                item.Protocol = KnownProtocol.SpreadtrumFdl;
                item.ProtocolName = "LIBUSB-FILTER";
                item.SourceTag = "SPD-FILTER";
                item.CommandAction = $"FILTER {action}: {devMatch} (SPD DIAG/FDL)";
                item.TargetOrEndpoint = devMatch;
            }
            else
            {
                item.Category = "Process";
                item.Protocol = KnownProtocol.HostCommand;
                item.ProtocolName = "LIBUSB-FILTER";
                item.SourceTag = "USB-FILTER";
                item.CommandAction = $"FILTER {action}: {devMatch}".Trim();
                item.TargetOrEndpoint = devMatch;
            }

            item.FormattedSummary = $"[{parentName}] {cleanExe} {trimmedCmd}";
            item.TechnicalDetails = $"Kernel Filter Driver Modification\nBinary: {exePath}\nAction: {action} Filter\nDevice Target: {devMatch}\nCaller: {parentName} (PID {parentPid})";
            return item;
        }

        // ══════════════════════════════════════════════════════════════════════
        // CASE 2: WMIC Queries (Hardware discovery before/during port wait)
        // ══════════════════════════════════════════════════════════════════════
        if (cleanExe.Equals("wmic.exe", StringComparison.OrdinalIgnoreCase) || trimmedCmd.StartsWith("wmic", StringComparison.OrdinalIgnoreCase) || trimmedCmd.Contains(@"wbem\wmic", StringComparison.OrdinalIgnoreCase))
        {
            item.Protocol = KnownProtocol.HostCommand;
            item.ProtocolName = "WMIC";
            item.SourceTag = "WMIC-QUERY";

            string wmicClass = ExtractWmicClass(trimmedCmd);
            if (string.IsNullOrWhiteSpace(wmicClass) || IsBareWmicCommand(trimmedCmd))
            {
                item.Category = "Cmd";
                item.CommandAction = "WMIC QUERY: \"\"";
                item.TargetOrEndpoint = "WMI";
                item.FormattedSummary = $"[{parentName}] wmic (empty)";
                item.TechnicalDetails = $"Empty WMI Query Execution\nCaller: {parentName} (PID {parentPid})";
                return item;
            }

            // Deduplicate repeating WMIC queries per tool / session
            string normalizedWmic = NormalizeWmicQuery(trimmedCmd);
            string wmicDedupeKey = $"{parentName}:{normalizedWmic}";
            if (!_seenSessionWmicQueries.TryAdd(wmicDedupeKey, 1))
            {
                item.Category = "Cmd";
                item.CommandAction = "WMIC QUERY: SUPPRESSED_DUPLICATE";
                item.TargetOrEndpoint = "WMI";
                item.FormattedSummary = $"[{parentName}] {trimmedCmd} (duplicate suppressed)";
                return item;
            }

            if (trimmedCmd.Contains("Win32_PnPEntity", StringComparison.OrdinalIgnoreCase))
            {
                if (trimmedCmd.Contains("VID_0E8D", StringComparison.OrdinalIgnoreCase))
                {
                    item.Category = "MediaTek";
                    item.CommandAction = "WMIC QUERY: PNP (VID_0E8D MTK)";
                }
                else if (trimmedCmd.Contains("VID_05C6", StringComparison.OrdinalIgnoreCase) || trimmedCmd.Contains("9008", StringComparison.OrdinalIgnoreCase))
                {
                    item.Category = "QualcommEdl";
                    item.CommandAction = "WMIC QUERY: PNP (VID_05C6 QCOM 9008)";
                }
                else if (trimmedCmd.Contains("VID_1782", StringComparison.OrdinalIgnoreCase))
                {
                    item.Category = "UnisocSpd";
                    item.CommandAction = "WMIC QUERY: PNP (VID_1782 SPD)";
                }
                else
                {
                    item.Category = "Cmd";
                    item.CommandAction = "WMIC QUERY: WIN32_PNPENTITY";
                }
                item.TargetOrEndpoint = "Win32_PnPEntity";
            }
            else if (trimmedCmd.Contains("Win32_SerialPort", StringComparison.OrdinalIgnoreCase))
            {
                item.Category = "Cmd";
                item.CommandAction = "WMIC QUERY: SERIAL/COM PORTS";
                item.TargetOrEndpoint = "Win32_SerialPort";
            }
            else
            {
                item.Category = "Cmd";
                item.CommandAction = "WMIC QUERY: " + wmicClass;
                item.TargetOrEndpoint = "WMI";
            }

            item.FormattedSummary = $"[{parentName}] {trimmedCmd}";
            item.TechnicalDetails = $"WMI Query Execution\nQuery: {trimmedCmd}\nCaller: {parentName} (PID {parentPid})";
            return item;
        }

        // ══════════════════════════════════════════════════════════════════════
        // CASE 3: DevCon / PnPUtil / DPInst (Driver & Port Enumeration)
        // ══════════════════════════════════════════════════════════════════════
        if (cleanExe.Equals("devcon.exe", StringComparison.OrdinalIgnoreCase) ||
            cleanExe.Equals("pnputil.exe", StringComparison.OrdinalIgnoreCase) ||
            cleanExe.Equals("dpinst.exe", StringComparison.OrdinalIgnoreCase))
        {
            string util = cleanExe.Replace(".exe", "").ToUpperInvariant();
            item.Protocol = KnownProtocol.HostCommand;
            item.ProtocolName = $"{util}-CLI";
            item.SourceTag = util;

            if (trimmedCmd.Contains("VID_0E8D", StringComparison.OrdinalIgnoreCase))
            {
                item.Category = "MediaTek";
                item.CommandAction = $"{util}: STATUS USB\\VID_0E8D* (MTK)";
            }
            else if (trimmedCmd.Contains("VID_05C6", StringComparison.OrdinalIgnoreCase) || trimmedCmd.Contains("9008", StringComparison.OrdinalIgnoreCase))
            {
                item.Category = "QualcommEdl";
                item.CommandAction = $"{util}: STATUS USB\\VID_05C6* (QCOM)";
            }
            else if (trimmedCmd.Contains("VID_1782", StringComparison.OrdinalIgnoreCase))
            {
                item.Category = "UnisocSpd";
                item.CommandAction = $"{util}: STATUS USB\\VID_1782* (SPD)";
            }
            else
            {
                item.Category = "Cmd";
                var parts = trimmedCmd.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                string sub = parts.Length > 1 ? parts[1].ToUpperInvariant() : "EXEC";
                string arg = parts.Length > 2 ? parts[2].ToUpperInvariant() : "";
                item.CommandAction = $"{util} {sub} {arg}".Trim();
            }

            item.TargetOrEndpoint = util;
            item.FormattedSummary = $"[{parentName}] {trimmedCmd}";
            item.TechnicalDetails = $"Hardware PnP / Driver Utility Execution\nCommand: {trimmedCmd}\nCaller: {parentName} (PID {parentPid})";
            return item;
        }

        // ══════════════════════════════════════════════════════════════════════
        // CASE 4: Fastboot CLI Executions
        // ══════════════════════════════════════════════════════════════════════
        if (cleanExe.Equals("fastboot.exe", StringComparison.OrdinalIgnoreCase))
        {
            item.Category = "AdbProxy";
            item.Protocol = KnownProtocol.Fastboot;
            item.ProtocolName = "FASTBOOT-CLI";
            item.SourceTag = "FASTBOOT";
            item.TargetOrEndpoint = "FASTBOOT";

            string subcmd = ExtractFastbootSubcommand(trimmedCmd);
            item.CommandAction = "FASTBOOT " + subcmd.ToUpperInvariant();
            item.FormattedSummary = $"[{parentName}] fastboot {subcmd}";
            item.TechnicalDetails = $"Android Fastboot Bootloader Command\nArguments: {trimmedCmd}\nCaller: {parentName} (PID {parentPid})";
            return item;
        }

        // ══════════════════════════════════════════════════════════════════════
        // CASE 5: ADB CLI Executions
        // ══════════════════════════════════════════════════════════════════════
        if (cleanExe.Equals("adb.exe", StringComparison.OrdinalIgnoreCase))
        {
            item.Category = "AdbProxy";
            item.Protocol = KnownProtocol.ADB;
            item.ProtocolName = "ADB-CLI";
            item.SourceTag = "ADB-CMD";
            item.TargetOrEndpoint = "ADB";

            string subcmd = ExtractAdbSubcommand(trimmedCmd);
            item.CommandAction = "ADB " + subcmd.ToUpperInvariant();
            item.FormattedSummary = $"[{parentName}] adb {subcmd}";
            item.TechnicalDetails = $"Android Debug Bridge Host Invocation\nCommandLine: {trimmedCmd}\nCaller: {parentName} (PID {parentPid})";
            return item;
        }

        // ══════════════════════════════════════════════════════════════════════
        // CASE 6: PowerShell Executions & Encoded Commands
        // ══════════════════════════════════════════════════════════════════════
        if (cleanExe.Contains("powershell") || cleanExe.Contains("pwsh"))
        {
            item.Category = "Shell";
            item.Protocol = KnownProtocol.HostCommand;
            item.ProtocolName = "POWERSHELL";
            item.SourceTag = "POWERSHELL";
            item.TargetOrEndpoint = "POWERSHELL";

            var parsed = ShellCommandParser.ParseShellExecution(cleanExe, trimmedCmd);
            item.DecodedScript = parsed.DecodedScript;
            item.CommandAction = parsed.Subcommand;
            item.FormattedSummary = $"[{parentName}] {parsed.NormalizedCommand}";
            item.TechnicalDetails = $"PowerShell Execution\nRaw CommandLine: {trimmedCmd}\nDecoded Script: {parsed.DecodedScript ?? "N/A"}\nCaller: {parentName} (PID {parentPid})";
            return item;
        }

        // ══════════════════════════════════════════════════════════════════════
        // CASE 7: CMD.EXE Wrapper Executions (Unwrap cmd.exe /c ...)
        // ══════════════════════════════════════════════════════════════════════
        if (cleanExe.Equals("cmd.exe", StringComparison.OrdinalIgnoreCase))
        {
            int cIdx = trimmedCmd.IndexOf("/c ", StringComparison.OrdinalIgnoreCase);
            if (cIdx < 0) cIdx = trimmedCmd.IndexOf("/k ", StringComparison.OrdinalIgnoreCase);

            if (cIdx >= 0 && cIdx + 3 < trimmedCmd.Length)
            {
                string inner = trimmedCmd[(cIdx + 3)..].Trim(' ', '"', '\'');
                var innerTokens = inner.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                string innerExe = innerTokens.Length > 0 ? Path.GetFileName(innerTokens[0]).ToLowerInvariant() : "cmd";

                // Re-evaluate inner command through analyzer
                var nested = AnalyzeCommand(innerExe, innerExe, inner, parentName, parentPid, pid, engine, timestamp);
                nested.SourceTag = "CMD-EXEC";
                nested.FormattedSummary = $"[{parentName}] cmd.exe /c {inner}";
                return nested;
            }

            item.Category = "Cmd";
            item.Protocol = KnownProtocol.HostCommand;
            item.ProtocolName = "HOST-CMD";
            item.SourceTag = "CMD-HOST";
            item.CommandAction = "CMD: " + trimmedCmd;
            item.TargetOrEndpoint = parentName;
            item.FormattedSummary = $"[{parentName}] {trimmedCmd}";
            item.TechnicalDetails = $"Command Prompt Execution\nCommandLine: {trimmedCmd}\nCaller: {parentName} (PID {parentPid})";
            return item;
        }

        // ══════════════════════════════════════════════════════════════════════
        // CASE 8: Apple iOS Utilities (irecovery, ideviceinfo, iproxy, etc.)
        // ══════════════════════════════════════════════════════════════════════
        if (cleanExe.Contains("iproxy") || cleanExe.StartsWith("idevice") || cleanExe.StartsWith("irecovery") ||
            cleanExe.Contains("futurerestore") || cleanExe.Contains("palera1n") || cleanExe.Contains("checkra1n") ||
            cleanExe.Contains("gaster") || cleanExe.Contains("ipwndfu"))
        {
            item.Category = "AppleIos";
            item.Protocol = cleanExe.Contains("iproxy") ? KnownProtocol.AppleRamdiskSsh :
                            cleanExe.Contains("irecovery") ? KnownProtocol.AppleRecovery : KnownProtocol.AppleLockdown;
            item.ProtocolName = "APPLE-CLI";
            item.SourceTag = cleanExe.Contains("irecovery") ? "APPLE-REC" : (cleanExe.Contains("iproxy") ? "APPLE-SSH" : "APPLE-CLI");
            item.TargetOrEndpoint = Path.GetFileNameWithoutExtension(cleanExe).ToUpperInvariant();
            item.CommandAction = $"APPLE: {Path.GetFileNameWithoutExtension(cleanExe).ToUpperInvariant()}";
            item.FormattedSummary = $"[{parentName}] {cleanExe} {trimmedCmd}";
            item.TechnicalDetails = $"Apple iOS Service Execution\nBinary: {exePath}\nArgs: {trimmedCmd}\nCaller: {parentName} (PID {parentPid})";
            return item;
        }

        // ══════════════════════════════════════════════════════════════════════
        // CASE 9: Chipset Flashing Binaries (MTK, Qualcomm EDL, SPD, Samsung)
        // ══════════════════════════════════════════════════════════════════════
        if (cleanExe.Contains("fh_loader") || cleanExe.Contains("emmcdl") || cleanExe.Contains("qsahara") || cleanExe.Contains("qfil") || cleanExe.Contains("edl"))
        {
            item.Category = "QualcommEdl";
            item.Protocol = KnownProtocol.QualcommFirehose;
            item.ProtocolName = "FIREHOSE-CLI";
            item.SourceTag = "QCOM-EDL";
            item.TargetOrEndpoint = "EDL 9008";
            item.CommandAction = $"{Path.GetFileNameWithoutExtension(cleanExe).ToUpperInvariant()}: {ExtractShortArgs(trimmedCmd)}";
            item.FormattedSummary = $"[{parentName}] {cleanExe} {trimmedCmd}";
            item.TechnicalDetails = $"Qualcomm EDL Flasher Execution\nBinary: {exePath}\nArgs: {trimmedCmd}\nCaller: {parentName} (PID {parentPid})";
            return item;
        }

        if (cleanExe.Contains("sp_flash_tool") || cleanExe.Contains("flashtool") || cleanExe.Contains("brom") || cleanExe.Contains("mtk"))
        {
            item.Category = "MediaTek";
            item.Protocol = KnownProtocol.MtkBrom;
            item.ProtocolName = "MTK-CLI";
            item.SourceTag = "MTK-TOOL";
            item.TargetOrEndpoint = "MTK BROM/DA";
            item.CommandAction = $"{Path.GetFileNameWithoutExtension(cleanExe).ToUpperInvariant()}: {ExtractShortArgs(trimmedCmd)}";
            item.FormattedSummary = $"[{parentName}] {cleanExe} {trimmedCmd}";
            item.TechnicalDetails = $"MediaTek Flash Utility Execution\nBinary: {exePath}\nArgs: {trimmedCmd}\nCaller: {parentName} (PID {parentPid})";
            return item;
        }

        if (cleanExe.Contains("researchdownload") || cleanExe.Contains("upgradedownload") || cleanExe.Contains("fdl") || cleanExe.Contains("spd"))
        {
            item.Category = "UnisocSpd";
            item.Protocol = KnownProtocol.SpreadtrumFdl;
            item.ProtocolName = "SPD-CLI";
            item.SourceTag = "SPD-TOOL";
            item.TargetOrEndpoint = "SPD DIAG";
            item.CommandAction = $"{Path.GetFileNameWithoutExtension(cleanExe).ToUpperInvariant()}: {ExtractShortArgs(trimmedCmd)}";
            item.FormattedSummary = $"[{parentName}] {cleanExe} {trimmedCmd}";
            item.TechnicalDetails = $"Unisoc/Spreadtrum Flash Tool Execution\nBinary: {exePath}\nArgs: {trimmedCmd}\nCaller: {parentName} (PID {parentPid})";
            return item;
        }

        // ══════════════════════════════════════════════════════════════════════
        // CASE 10: General Tool Sub-Process / CLI Execution
        // ══════════════════════════════════════════════════════════════════════
        item.Category = "Process";
        item.Protocol = KnownProtocol.HostCommand;
        item.ProtocolName = "GSM-TOOL";
        item.SourceTag = "TOOL-CMD";
        item.TargetOrEndpoint = parentName;

        string shortSub = ExtractShortArgs(trimmedCmd);
        item.CommandAction = $"{Path.GetFileNameWithoutExtension(cleanExe).ToUpperInvariant()}: {shortSub}".Trim(':', ' ');
        item.FormattedSummary = $"[{parentName}] {cleanExe} {trimmedCmd}";
        item.TechnicalDetails = $"GSM Tool Sub-Process Command\nBinary: {exePath}\nCommandLine: {trimmedCmd}\nCaller: {parentName} (PID {parentPid})";

        return item;
    }
}
