using System;
using System.Collections.Generic;

namespace PhoenixGSM.OmniTrace.Reporting
{
    public record ThreatSummary(string Severity, string Description, DateTime Timestamp);
    public record TimelineSummary(string EventName, string Details, DateTime Timestamp);
    
    public record ForensicReportDocument(
        string ToolName, 
        string ToolVersion, 
        ToolTrustEvaluation Trust, 
        List<ThreatSummary> Threats, 
        List<TimelineSummary> Timeline,
        DateTime GeneratedAt);

    public class ForensicReportBuilder
    {
        // بناء التقرير الجنائي - Build forensic report
        public ForensicReportDocument BuildReport(
            string toolName, 
            string toolVersion, 
            ToolTrustEvaluation trust, 
            IEnumerable<ThreatSummary> threats, 
            IEnumerable<TimelineSummary> timeline)
        {
            try
            {
                var threatsList = new List<ThreatSummary>(threats);
                var timelineList = new List<TimelineSummary>(timeline);

                return new ForensicReportDocument(
                    ToolName: toolName,
                    ToolVersion: toolVersion,
                    Trust: trust,
                    Threats: threatsList,
                    Timeline: timelineList,
                    GeneratedAt: DateTime.UtcNow
                );
            }
            catch (Exception ex)
            {
                // منع التوقف المفاجئ - Prevent crash
                Console.WriteLine($"[ForensicReportBuilder] Error: {ex.Message}");
                return new ForensicReportDocument(toolName, toolVersion, new ToolTrustEvaluation(0, RiskVerdict.MaliciousHostile), [], [], DateTime.UtcNow);
            }
        }
    }
}
