using System;
using System.Text.RegularExpressions;

namespace PhoenixGSM.OmniTrace.SecurityEngine.Rules;

[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public class DataExfiltrationRule : IDetectionRule
{
    public string RuleId => "R-DEX-01";
    public string RuleName => "Data Exfiltration Detection";
    public ThreatCategory Category => ThreatCategory.DataExfiltration;
    public ThreatSeverity DefaultSeverity => ThreatSeverity.Critical;

    // Patterns for data stealing
    private static readonly Regex ExfiltrationPattern = new Regex(
        @"(?:content\s+query\s+--uri\s+content://(?:contacts|sms|call_log)|pull\s+(?:/sdcard|/data/data/)|dumpsys\s+(?:telephony|sms|contacts)|cat\s+/data/data/)", 
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public ThreatAlert? Evaluate(dynamic commandEvent)
    {
        try
        {
            string commandStr = commandEvent.Command?.ToString() ?? string.Empty;
            string protocolStr = commandEvent.Protocol?.ToString() ?? string.Empty;
            
            if (string.IsNullOrWhiteSpace(commandStr)) return null;

            if (ExfiltrationPattern.IsMatch(commandStr))
            {
                var alert = new ThreatAlert
                {
                    Severity = DefaultSeverity,
                    Category = Category,
                    Title = "Data Exfiltration Attempt Detected",
                    Description = $"Detected an attempt to read or extract sensitive data: {commandStr}",
                    CommandId = commandEvent.CommandId?.ToString(),
                    ProcessName = commandEvent.Attribution?.ImageName,
                    DeviceId = commandEvent.DeviceIdentity?.ToString(),
                    ConfidenceScore = 95
                };
                
                alert.RawEvidence.Add($"Command Match: {commandStr}");
                return alert;
            }
        }
        catch (Exception ex)
        {
            // Fail-open
            Console.WriteLine($"[DataExfiltrationRule] Error: {ex.Message}");
        }
        return null;
    }
}
