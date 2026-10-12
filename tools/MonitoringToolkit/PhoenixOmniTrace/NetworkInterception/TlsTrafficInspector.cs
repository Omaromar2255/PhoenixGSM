using System;
using System.Collections.Generic;
using System.Linq;

namespace PhoenixGSM.OmniTrace.NetworkInterception;

public class NetworkInspectionResult
{
    public bool IsSuspicious { get; set; }
    public List<string> Flags { get; set; } = new();
}

public class TlsTrafficInspector : IDisposable
{
    /// <summary>
    /// فحص طلب الشبكة / Inspect HTTP request
    /// </summary>
    public NetworkInspectionResult InspectHttpRequest(string method, string url, IDictionary<string, string> headers, byte[]? body)
    {
        var result = new NetworkInspectionResult();
        try
        {
            // 1. Check for standard User-Agent / التحقق من وجود وكيل مستخدم قياسي
            bool hasValidUa = headers.Any(h => h.Key.Equals("User-Agent", StringComparison.OrdinalIgnoreCase) && 
                                               (h.Value.Contains("Mozilla") || h.Value.Contains("Chrome")));
            if (!hasValidUa)
            {
                result.IsSuspicious = true;
                result.Flags.Add("Missing or abnormal User-Agent");
            }

            // 2. Large POST bodies / بيانات كبيرة مرسلة
            if (method.Equals("POST", StringComparison.OrdinalIgnoreCase) && body != null && body.Length > 1024 * 1024)
            {
                result.IsSuspicious = true;
                result.Flags.Add("Large POST body detected");
            }

            // 3. Suspicious ports in URL / منافذ مشبوهة
            if (Uri.TryCreate(url, UriKind.Absolute, out var uri))
            {
                int port = uri.Port;
                if (port != 80 && port != 443 && port != 8080)
                {
                    result.IsSuspicious = true;
                    result.Flags.Add($"Suspicious port used: {port}");
                }
            }
        }
        catch (Exception ex)
        {
            // Fail-open
            Console.WriteLine($"[TlsTrafficInspector] InspectHttpRequest Error: {ex.Message}");
        }
        return result;
    }

    public void Dispose()
    {
        // تنظيف / Cleanup
    }
}
