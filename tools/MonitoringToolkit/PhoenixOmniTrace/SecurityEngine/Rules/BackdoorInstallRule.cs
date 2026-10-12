using System;
using System.Text.RegularExpressions;

namespace PhoenixGSM.OmniTrace.SecurityEngine.Rules;

[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public class BackdoorInstallRule : IDetectionRule
{
    public string RuleId => "R-BDI-01";
    public string RuleName => "Backdoor Installation Detection";
    public ThreatCategory Category => ThreatCategory.BackdoorInstall;
    public ThreatSeverity DefaultSeverity => ThreatSeverity.Critical;

    private static readonly Regex BackdoorPattern = new Regex(
        @"(?:push\s+.*?/system/(?:app|priv-app)|pm\s+grant\s+.*?(?:READ_SMS|CAMERA|RECORD_AUDIO)|dpm\s+set-device-owner)", 
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public ThreatAlert? Evaluate(dynamic commandEvent)
    {
        try
        {
            string commandStr = commandEvent.Command?.ToString() ?? string.Empty;
            
            if (string.IsNullOrWhiteSpace(commandStr)) return null;

            if (BackdoorPattern.IsMatch(commandStr))
            {
                var alert = new ThreatAlert
                {
                    Severity = DefaultSeverity,
                    Category = Category,
                    Title = "Backdoor Installation Detected",
                    Description = $"System app modification, dangerous permission grant, or device-owner change detected: {commandStr}",
                    CommandId = commandEvent.CommandId?.ToString(),
                    ProcessName = commandEvent.Attribution?.ImageName,
                    DeviceId = commandEvent.DeviceIdentity?.ToString(),
                    ConfidenceScore = 90
                };
                
                alert.RawEvidence.Add($"Suspicious Command: {commandStr}");
                return alert;
            }
        }
        catch (Exception ex)
        {
            // Fail-open
            Console.WriteLine($"[BackdoorInstallRule] Error: {ex.Message}");
        }
        return null;
    }
}
