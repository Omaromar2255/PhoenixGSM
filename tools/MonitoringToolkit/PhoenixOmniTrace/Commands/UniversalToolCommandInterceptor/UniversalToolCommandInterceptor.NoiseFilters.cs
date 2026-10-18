using System;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace PhoenixGSM.OmniTrace.Commands;

public sealed partial class UniversalToolCommandInterceptor
{
    #region Helper Parsers
    private static string ExtractDevicePattern(string cmdLine)
    {
        var match = Regex.Match(cmdLine, @"(?:--device=|device=)?(USB\\[A-Za-z0-9_&]+)", RegexOptions.IgnoreCase);
        if (match.Success) return match.Groups[1].Value;

        var vidMatch = Regex.Match(cmdLine, @"VID_[A-Za-z0-9]+(?:&PID_[A-Za-z0-9]+)?", RegexOptions.IgnoreCase);
        if (vidMatch.Success) return vidMatch.Value;

        return "USB Device";
    }

    private static string ExtractWmicClass(string cmdLine)
    {
        var parts = cmdLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        int pathIdx = Array.FindIndex(parts, p => p.Equals("path", StringComparison.OrdinalIgnoreCase));
        if (pathIdx >= 0 && pathIdx + 1 < parts.Length)
        {
            return parts[pathIdx + 1].ToUpperInvariant();
        }
        return parts.Length > 1 ? parts[1].ToUpperInvariant() : "QUERY";
    }

    private static string ExtractFastbootSubcommand(string cmdLine)
    {
        var tokens = cmdLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        int fbIdx = Array.FindIndex(tokens, t => t.EndsWith("fastboot.exe", StringComparison.OrdinalIgnoreCase) || t.Equals("fastboot", StringComparison.OrdinalIgnoreCase));
        if (fbIdx >= 0 && fbIdx + 1 < tokens.Length)
        {
            return string.Join(" ", tokens.Skip(fbIdx + 1));
        }
        return tokens.Length > 1 ? string.Join(" ", tokens.Skip(1)) : "FASTBOOT";
    }

    private static string ExtractAdbSubcommand(string cmdLine)
    {
        var tokens = cmdLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        int adbIdx = Array.FindIndex(tokens, t => t.EndsWith("adb.exe", StringComparison.OrdinalIgnoreCase) || t.Equals("adb", StringComparison.OrdinalIgnoreCase));
        if (adbIdx >= 0 && adbIdx + 1 < tokens.Length)
        {
            return string.Join(" ", tokens.Skip(adbIdx + 1));
        }
        return tokens.Length > 1 ? string.Join(" ", tokens.Skip(1)) : "ADB";
    }

    private static string ExtractShortArgs(string cmdLine)
    {
        var tokens = cmdLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (tokens.Length <= 1) return string.Empty;
        var args = tokens.Skip(1);
        return string.Join(" ", args);
    }

    private static bool IsPotentiallyRelevantUtility(string exeName)
    {
        string lower = exeName.ToLowerInvariant();
        return lower.Contains("filter-") ||
               lower.Contains("devcon") ||
               lower.Contains("pnputil") ||
               lower.Contains("dpinst") ||
               lower.Contains("wmic") ||
               lower.Contains("fastboot") ||
               lower.Contains("adb") ||
               lower.Contains("cmd.exe") ||
               lower.Contains("powershell") ||
               lower.Contains("pwsh") ||
               lower.Contains("curl") ||
               lower.Contains("certutil") ||
               lower.Contains("bitsadmin") ||
               lower.Contains("sc.exe") ||
               lower.Contains("net.exe") ||
               lower.Contains("reg.exe") ||
               lower.Contains("tar.exe") ||
               lower.Contains("7z.exe") ||
               lower.Contains("flashtool") ||
               lower.Contains("fh_loader") ||
               lower.Contains("emmcdl") ||
               lower.Contains("researchdownload") ||
               lower.Contains("upgradedownload") ||
               lower.Contains("irecovery") ||
               lower.Contains("idevice") ||
               lower.Contains("iproxy");
    }

    private static bool HasHardwareOrGsmKeywords(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return false;
        string t = text.ToLowerInvariant();
        return t.Contains("vid_") || t.Contains("pid_") || t.Contains("usb\\") ||
               t.Contains("9008") || t.Contains("brom") || t.Contains("preloader") ||
               t.Contains("scatter") || t.Contains("edl") || t.Contains("sahara") ||
               t.Contains("firehose") || t.Contains("fdl") || t.Contains("da") ||
               t.Contains("flash") || t.Contains("erase") || t.Contains("install --device") ||
               t.Contains("class ports") || t.Contains("serialcomm") || t.Contains("getvar");
    }

    public static bool HasNoiseKeywords(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return false;
        return text.Contains("MicrosoftEdgeUpdate", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("EdgeUpdate", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("GoogleUpdate", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("chrome.exe", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("msedge.exe", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("svchost.exe", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("services.exe", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("conhost.exe", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("git.exe", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsStrictlyExcludedProcess(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return false;
        string clean = Path.GetFileName(name).ToLowerInvariant();
        if (clean.EndsWith(".exe")) clean = clean[..^4];

        return clean is "microsoftedgeupdate" or "googleupdate" or "edgeupdate" or
                        "svchost" or "services" or "chrome" or "git" or "conhost" or
                        "searchhost" or "runtimebroker" or "taskhostw" or "wmiprvse" or "explorer";
    }

    public static string NormalizeWmicQuery(string cmd)
    {
        if (string.IsNullOrWhiteSpace(cmd)) return string.Empty;
        string s = cmd.Replace("\"", "").Replace("'", "").ToLowerInvariant().Trim();
        s = Regex.Replace(s, @"/output:[^\s]+", "").Trim();
        s = Regex.Replace(s, @"\s+", " ").Trim();
        return s;
    }

    public static bool IsBareWmicCommand(string cmd)
    {
        if (string.IsNullOrWhiteSpace(cmd)) return true;
        string clean = cmd.Trim('"', ' ', '\'').ToLowerInvariant();
        return clean == "wmic" || clean == "wmic.exe" ||
               clean.EndsWith(@"\wbem\wmic.exe") || clean.EndsWith(@"\wbem\wmic") ||
               clean.EndsWith("/output:stdout") || clean.EndsWith("/output:stderr");
    }

    private static bool IsBenignNoiseProcess(string cleanExe, string cmdLine)
    {
        string l = cleanExe.ToLowerInvariant();
        if (l == "microsoftedgeupdate.exe" ||
            l == "edgeupdate.exe" ||
            l == "googleupdate.exe" ||
            l == "svchost.exe" ||
            l == "taskhostw.exe" ||
            l == "searchhost.exe" ||
            l == "startmenuexperiencehost.exe" ||
            l == "shellexperiencehost.exe" ||
            l == "runtimebroker.exe" ||
            l == "sihost.exe" ||
            l == "ctfmon.exe" ||
            l == "fontdrvhost.exe" ||
            l == "backgroundtaskhost.exe" ||
            l == "wmiprvse.exe" ||
            l == "systemsettings.exe" ||
            l == "applicationframehost.exe" ||
            l == "smartscreen.exe" ||
            l == "securityhealthservice.exe" ||
            l == "chrome.exe" ||
            l == "msedge.exe" ||
            l == "firefox.exe" ||
            l == "services.exe" ||
            l == "explorer.exe" ||
            l == "git.exe" ||
            l == "conhost.exe" ||
            l == "attrib.exe")
        {
            return true;
        }

        if (cmdLine.Contains("--type=renderer", StringComparison.OrdinalIgnoreCase) ||
            cmdLine.Contains("--type=gpu-process", StringComparison.OrdinalIgnoreCase) ||
            cmdLine.Contains("--type=utility", StringComparison.OrdinalIgnoreCase) ||
            cmdLine.Contains("--type=crashpad", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return false;
    }
    #endregion
}
