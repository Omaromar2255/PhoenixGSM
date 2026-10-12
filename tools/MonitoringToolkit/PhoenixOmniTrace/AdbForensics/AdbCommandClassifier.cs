using System;
using System.Text.RegularExpressions;

namespace PhoenixGSM.OmniTrace.AdbForensics;

[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public class AdbCommandClassifier
{
    // Critical risk patterns
    private static readonly Regex CriticalPattern = new Regex(
        @"(?:rm\s+-rf|push\s+.*?(?:su|busybox)|push\s+.*?/system/|content\s+query\s+.*?(?:contacts|sms)|shell\s+dd|pm\s+grant\s+.*?(?:READ_SMS|CAMERA|RECORD_AUDIO|ACCESS_FINE_LOCATION)|dpm\s+set-device-owner|input\s+(?:text|keyevent|tap))",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // High risk patterns
    private static readonly Regex HighPattern = new Regex(
        @"(?:adb\s+install|adb\s+push\s+.*?\.apk|adb\s+forward|adb\s+reverse|settings\s+put|appops\s+set|service\s+call|am\s+broadcast\s+.*?SECRET_CODE)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // Medium risk patterns
    private static readonly Regex MediumPattern = new Regex(
        @"(?:dumpsys|getprop|logcat|pm\s+list|shell\s+ps)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // Low risk patterns
    private static readonly Regex LowPattern = new Regex(
        @"(?:version|devices|get-state)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // Safe risk patterns
    private static readonly Regex SafePattern = new Regex(
        @"(?:help)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public AdbCommandRisk ClassifyCommand(string command)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(command))
            {
                return new AdbCommandRisk(command ?? "", AdbRiskLevel.Safe, AdbCommandCategory.Unknown, "Empty command.");
            }

            // تصنيف حسب الخطورة - Classify by Severity
            if (CriticalPattern.IsMatch(command))
            {
                return new AdbCommandRisk(command, AdbRiskLevel.Critical, DetermineCategory(command), "Critical security command that alters system configuration, accesses private data, or injects input.");
            }
            if (HighPattern.IsMatch(command))
            {
                return new AdbCommandRisk(command, AdbRiskLevel.High, DetermineCategory(command), "High risk command modifying settings, port forwarding, or app installation.");
            }
            if (MediumPattern.IsMatch(command))
            {
                return new AdbCommandRisk(command, AdbRiskLevel.Medium, DetermineCategory(command), "Information gathering command (system dump, properties, logs).");
            }
            if (LowPattern.IsMatch(command))
            {
                return new AdbCommandRisk(command, AdbRiskLevel.Low, DetermineCategory(command), "Basic device query command.");
            }
            if (SafePattern.IsMatch(command))
            {
                return new AdbCommandRisk(command, AdbRiskLevel.Safe, AdbCommandCategory.DeviceQuery, "Safe documentation command.");
            }

            // الافتراضي - Default
            return new AdbCommandRisk(command, AdbRiskLevel.Low, AdbCommandCategory.ShellExecution, "Unrecognized command, assuming low risk.");
        }
        catch (Exception ex)
        {
            // Fail-open
            Console.WriteLine($"[AdbCommandClassifier] Error: {ex.Message}");
            return new AdbCommandRisk(command ?? "", AdbRiskLevel.Unknown, AdbCommandCategory.Unknown, "Error during classification.");
        }
    }

    private AdbCommandCategory DetermineCategory(string cmd)
    {
        cmd = cmd.ToLowerInvariant();
        if (cmd.Contains("pm ") || cmd.Contains("install ") || cmd.Contains("appops ")) return AdbCommandCategory.PackageManagement;
        if (cmd.Contains("push ") || cmd.Contains("pull ")) return AdbCommandCategory.FileTransfer;
        if (cmd.Contains("settings ")) return AdbCommandCategory.SystemSettings;
        if (cmd.Contains("forward ") || cmd.Contains("reverse ")) return AdbCommandCategory.NetworkConfig;
        if (cmd.Contains("grant ")) return AdbCommandCategory.PermissionGrant;
        if (cmd.Contains("logcat ") || cmd.Contains("dumpsys ")) return AdbCommandCategory.DebugControl;
        if (cmd.Contains("getprop ") || cmd.Contains("devices ")) return AdbCommandCategory.DeviceQuery;
        if (cmd.Contains("su") || cmd.Contains("chmod ") || cmd.Contains("chown ")) return AdbCommandCategory.SecuritySensitive;

        return AdbCommandCategory.ShellExecution;
    }
}
