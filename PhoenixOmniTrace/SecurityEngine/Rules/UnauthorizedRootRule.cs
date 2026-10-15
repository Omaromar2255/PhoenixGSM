using System;
using System.Text.RegularExpressions;

namespace PhoenixGSM.OmniTrace.SecurityEngine.Rules;

[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public class UnauthorizedRootRule : IDetectionRule
{
    public string RuleId => "R-ROOT-01";
    public string RuleName => "Unauthorized Root Access";
    public ThreatCategory Category => ThreatCategory.UnauthorizedRoot;
    public ThreatSeverity DefaultSeverity => ThreatSeverity.Critical;

    private static readonly Regex RootPattern = new Regex(
        @"(?:push\s+.*?(?:su|busybox)|chmod\s+(?:4755|6755)|chown\s+root|mount\s+-o\s+remount(?:,\w+)*\s+rw\s+/system)", 
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public ThreatAlert? Evaluate(dynamic commandEvent)
    {
        try
        {
            string commandStr = commandEvent.Command?.ToString() ?? string.Empty;
            
            if (string.IsNullOrWhiteSpace(commandStr)) return null;

            if (RootPattern.IsMatch(commandStr))
            {
                return new ThreatAlert
                {
                    Severity = DefaultSeverity,
                    Category = Category,
                    Title = "Unauthorized Root Activity",
                    Description = $"Attempted root escalation or system partition modification: {commandStr}",
                    CommandId = commandEvent.CommandId?.ToString(),
                    ProcessName = commandEvent.Attribution?.ImageName,
                    DeviceId = commandEvent.DeviceIdentity?.ToString(),
                    ConfidenceScore = 90,
                    RawEvidence = new System.Collections.Generic.List<string> { commandStr }
                };
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[UnauthorizedRootRule] Error: {ex.Message}");
        }
        return null;
    }
}
