using System;
using System.Text.RegularExpressions;

namespace PhoenixGSM.OmniTrace.SecurityEngine.Rules;

[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public class ImeiTamperingRule : IDetectionRule
{
    public string RuleId => "R-IMEI-01";
    public string RuleName => "IMEI Tampering Detection";
    public ThreatCategory Category => ThreatCategory.ImeiTampering;
    public ThreatSeverity DefaultSeverity => ThreatSeverity.High;

    private static readonly Regex ImeiPattern = new Regex(
        @"(?:AT\+EGMR=\d,\d,|AT\+CGSN=\d|DIAG_NV_WRITE_F.*?(?:IMEI|MEID))", 
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public ThreatAlert? Evaluate(dynamic commandEvent)
    {
        try
        {
            string commandStr = commandEvent.Command?.ToString() ?? string.Empty;
            
            if (string.IsNullOrWhiteSpace(commandStr)) return null;

            if (ImeiPattern.IsMatch(commandStr))
            {
                return new ThreatAlert
                {
                    Severity = DefaultSeverity,
                    Category = Category,
                    Title = "IMEI Tampering Detected",
                    Description = $"Attempted IMEI or NV rewrite detected: {commandStr}",
                    CommandId = commandEvent.CommandId?.ToString(),
                    ProcessName = commandEvent.Attribution?.ImageName,
                    DeviceId = commandEvent.DeviceIdentity?.ToString(),
                    ConfidenceScore = 95,
                    RawEvidence = new System.Collections.Generic.List<string> { commandStr }
                };
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ImeiTamperingRule] Error: {ex.Message}");
        }
        return null;
    }
}
