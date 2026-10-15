using System;

namespace PhoenixGSM.OmniTrace.LiveVisibility;

public enum HighlightColor
{
    Green,      // Normal/Safe
    Yellow,     // Suspicious
    Orange,     // High risk
    Red         // Critical danger
}

public class LiveHighlightStyle
{
    public HighlightColor Color { get; set; }
    public bool RequiresUrgentNotification { get; set; }
    public string NotificationMessage { get; set; } = string.Empty;
}

public class SeverityHighlighter
{
    /// <summary>
    /// يصنف العناصر المباشرة إلى تمييزات مرئية / Classifies live items into visual highlights
    /// </summary>
    public LiveHighlightStyle DetermineStyle(string category, string riskLevel)
    {
        var style = new LiveHighlightStyle { Color = HighlightColor.Green, RequiresUrgentNotification = false };

        try
        {
            string risk = riskLevel?.ToUpperInvariant() ?? "LOW";
            string cat = category?.ToUpperInvariant() ?? "UNKNOWN";

            if (risk == "CRITICAL")
            {
                style.Color = HighlightColor.Red;
                style.RequiresUrgentNotification = true;
                style.NotificationMessage = "تنبيه حرج! / CRITICAL ALERT!";
            }
            else if (risk == "HIGH" || cat.Contains("EXPLOIT") || cat.Contains("MALWARE"))
            {
                style.Color = HighlightColor.Orange;
                style.RequiresUrgentNotification = true;
                style.NotificationMessage = "خطر عالي / HIGH RISK!";
            }
            else if (risk == "MEDIUM" || cat.Contains("ANOMALY"))
            {
                style.Color = HighlightColor.Yellow;
                style.RequiresUrgentNotification = false;
            }
            else
            {
                style.Color = HighlightColor.Green;
            }
        }
        catch (Exception ex)
        {
            // Fail-open: لا تعطل النظام / Do not crash system
            Console.WriteLine($"[SeverityHighlighter Error] {ex.Message}");
        }

        return style;
    }
}
