using System;
using System.Text;

namespace PhoenixGSM.OmniTrace.Reporting
{
    public class HtmlReportExporter
    {
        // تصدير التقرير إلى HTML - Export report to HTML
        public string ExportToHtml(ForensicReportDocument report)
        {
            try
            {
                var sb = new StringBuilder();
                sb.AppendLine("<!DOCTYPE html>");
                sb.AppendLine("<html lang='en'><head>");
                sb.AppendLine("<meta charset='UTF-8'>");
                sb.AppendLine("<title>Forensic Report - " + report.ToolName + "</title>");
                sb.AppendLine("<style>");
                sb.AppendLine("body { background-color: #121212; color: #e0e0e0; font-family: Arial, sans-serif; }");
                sb.AppendLine(".container { width: 80%; margin: auto; padding: 20px; }");
                sb.AppendLine(".critical { color: #ff4c4c; font-weight: bold; }");
                sb.AppendLine(".high { color: #ff9800; font-weight: bold; }");
                sb.AppendLine(".medium { color: #ffeb3b; font-weight: bold; }");
                sb.AppendLine(".trusted { color: #4caf50; font-weight: bold; }");
                sb.AppendLine("table { width: 100%; border-collapse: collapse; margin-top: 15px; }");
                sb.AppendLine("th, td { border: 1px solid #333; padding: 8px; text-align: left; }");
                sb.AppendLine("th { background-color: #1f1f1f; }");
                sb.AppendLine("</style>");
                sb.AppendLine("</head><body>");
                sb.AppendLine("<div class='container'>");
                sb.AppendLine($"<h1>OmniTrace Forensic Report / تقرير الفحص الجنائي</h1>");
                sb.AppendLine($"<p>Tool / الأداة: {report.ToolName} v{report.ToolVersion}</p>");
                sb.AppendLine($"<p>Generated At / وقت الإنشاء: {report.GeneratedAt:O}</p>");
                
                string scoreClass = report.Trust.Verdict == RiskVerdict.Trusted ? "trusted" : 
                                    (report.Trust.Verdict == RiskVerdict.Suspicious ? "high" : "critical");

                sb.AppendLine($"<h2>Trust Score: <span class='{scoreClass}'>{report.Trust.Score}/100 ({report.Trust.Verdict})</span></h2>");

                sb.AppendLine("<h3>Threats / التهديدات المكتشفة</h3>");
                sb.AppendLine("<table><tr><th>Severity</th><th>Description</th><th>Timestamp</th></tr>");
                foreach (var threat in report.Threats)
                {
                    string sevClass = threat.Severity.ToLower();
                    sb.AppendLine($"<tr><td class='{sevClass}'>{threat.Severity}</td><td>{threat.Description}</td><td>{threat.Timestamp:O}</td></tr>");
                }
                sb.AppendLine("</table>");

                sb.AppendLine("<h3>Timeline / التسلسل الزمني</h3>");
                sb.AppendLine("<table><tr><th>Event</th><th>Details</th><th>Timestamp</th></tr>");
                foreach (var evt in report.Timeline)
                {
                    sb.AppendLine($"<tr><td>{evt.EventName}</td><td>{evt.Details}</td><td>{evt.Timestamp:O}</td></tr>");
                }
                sb.AppendLine("</table>");

                sb.AppendLine("</div></body></html>");

                return sb.ToString();
            }
            catch (Exception ex)
            {
                // منع التوقف المفاجئ - Prevent crash
                Console.WriteLine($"[HtmlReportExporter] Error: {ex.Message}");
                return $"<html><body><h1>Error generating report: {ex.Message}</h1></body></html>";
            }
        }
    }
}
