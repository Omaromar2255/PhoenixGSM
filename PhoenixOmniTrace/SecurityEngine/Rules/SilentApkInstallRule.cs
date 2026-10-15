using System;
using System.Text.RegularExpressions;
using PhoenixGSM.OmniTrace;

namespace PhoenixGSM.OmniTrace.SecurityEngine.Rules;

[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public class SilentApkInstallRule : IDetectionRule
{
    public string RuleId => "R-SAI-01";
    public string RuleName => "Silent APK Installation Detection";
    public ThreatCategory Category => ThreatCategory.SilentApkInstall;
    public ThreatSeverity DefaultSeverity => ThreatSeverity.Critical;

    // Pattern to detect silent installs (pm install, adb install, etc.)
    private static readonly Regex InstallPattern = new Regex(
        @"(?:pm\s+install|adb\s+install|push\s+.*\.apk)", 
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public ThreatAlert? Evaluate(dynamic commandEvent)
    {
        try
        {
            // التحقق من البروتوكول - Check Protocol
            // Assuming Protocol is ADB or similar
            string commandStr = commandEvent.Command?.ToString() ?? string.Empty;
            string protocolStr = commandEvent.Protocol?.ToString() ?? string.Empty;
            
            if (string.IsNullOrWhiteSpace(commandStr)) return null;

            if (protocolStr.Contains("ADB", StringComparison.OrdinalIgnoreCase) && 
                InstallPattern.IsMatch(commandStr))
            {
                var alert = new ThreatAlert
                {
                    Severity = DefaultSeverity,
                    Category = Category,
                    Title = "Silent APK Install Detected",
                    Description = $"Detected a potential silent application installation attempt: {commandStr}",
                    CommandId = commandEvent.CommandId?.ToString(),
                    ProcessName = commandEvent.Attribution?.ImageName,
                    DeviceId = commandEvent.DeviceIdentity?.ToString(),
                    ConfidenceScore = 85
                };
                
                alert.RawEvidence.Add($"Command: {commandStr}");
                alert.Metadata["Protocol"] = protocolStr;
                return alert;
            }
        }
        catch (Exception ex)
        {
            // Fail-open: لا تقم بإيقاف النظام - Do not crash the system
            Console.WriteLine($"[SilentApkInstallRule] Error evaluating command: {ex.Message}");
        }
        return null;
    }
}
