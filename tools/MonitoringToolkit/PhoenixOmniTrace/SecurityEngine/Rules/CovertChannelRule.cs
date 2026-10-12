using System;
using System.Text.RegularExpressions;

namespace PhoenixGSM.OmniTrace.SecurityEngine.Rules;

[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public class CovertChannelRule : IDetectionRule
{
    public string RuleId => "R-COV-01";
    public string RuleName => "Covert Channel Detection";
    public ThreatCategory Category => ThreatCategory.CovertChannel;
    public ThreatSeverity DefaultSeverity => ThreatSeverity.High;

    private static readonly Regex CovertPattern = new Regex(
        @"(?:adb\s+(?:forward|reverse)\s+tcp:\d+\s+tcp:\d+|nc\s+-e\s+/system/bin/sh|ping\s+-s\s+\d{4,})", 
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public ThreatAlert? Evaluate(dynamic commandEvent)
    {
        try
        {
            string commandStr = commandEvent.Command?.ToString() ?? string.Empty;
            
            if (string.IsNullOrWhiteSpace(commandStr)) return null;

            if (CovertPattern.IsMatch(commandStr))
            {
                return new ThreatAlert
                {
                    Severity = DefaultSeverity,
                    Category = Category,
                    Title = "Covert Channel Activity",
                    Description = $"Port forwarding, bind shells, or suspicious network tunneling: {commandStr}",
                    CommandId = commandEvent.CommandId?.ToString(),
                    ProcessName = commandEvent.Attribution?.ImageName,
                    DeviceId = commandEvent.DeviceIdentity?.ToString(),
                    ConfidenceScore = 80,
                    RawEvidence = new System.Collections.Generic.List<string> { commandStr }
                };
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[CovertChannelRule] Error: {ex.Message}");
        }
        return null;
    }
}
