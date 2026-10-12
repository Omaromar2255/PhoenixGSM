using System;
using System.Text.RegularExpressions;

namespace PhoenixGSM.OmniTrace.SecurityEngine.Rules;

[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public class AntiForensicRule : IDetectionRule
{
    public string RuleId => "R-AFR-01";
    public string RuleName => "Anti-Forensic Activity Detection";
    public ThreatCategory Category => ThreatCategory.AntiForensic;
    public ThreatSeverity DefaultSeverity => ThreatSeverity.High;

    private static readonly Regex AntiForensicPattern = new Regex(
        @"(?:logcat\s+-c|rm\s+-rf\s+/data/local/tmp|history\s+-c|settings\s+put\s+global\s+adb_enabled\s+0)", 
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public ThreatAlert? Evaluate(dynamic commandEvent)
    {
        try
        {
            string commandStr = commandEvent.Command?.ToString() ?? string.Empty;
            
            if (string.IsNullOrWhiteSpace(commandStr)) return null;

            if (AntiForensicPattern.IsMatch(commandStr))
            {
                return new ThreatAlert
                {
                    Severity = DefaultSeverity,
                    Category = Category,
                    Title = "Anti-Forensic Behavior",
                    Description = $"Detected log clearing, trace deletion, or disabling debug mode: {commandStr}",
                    CommandId = commandEvent.CommandId?.ToString(),
                    ProcessName = commandEvent.Attribution?.ImageName,
                    DeviceId = commandEvent.DeviceIdentity?.ToString(),
                    ConfidenceScore = 85,
                    RawEvidence = new System.Collections.Generic.List<string> { commandStr }
                };
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[AntiForensicRule] Error: {ex.Message}");
        }
        return null;
    }
}
