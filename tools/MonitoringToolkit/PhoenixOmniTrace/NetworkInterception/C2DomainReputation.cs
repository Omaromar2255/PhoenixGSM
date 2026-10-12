using System;
using System.Collections.Generic;

namespace PhoenixGSM.OmniTrace.NetworkInterception;

public class C2DomainReputation : IDisposable
{
    private readonly HashSet<string> _maliciousDomains;
    private readonly HashSet<string> _maliciousIps;

    public C2DomainReputation()
    {
        // Database in-memory / قاعدة بيانات في الذاكرة
        _maliciousDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "c2.telemetry-hack.net",
            "evil-gsm-tool.com",
            "bad-dyn-dns.org"
        };

        _maliciousIps = new HashSet<string>
        {
            "185.11.22.33",
            "193.168.0.100"
        };
    }

    /// <summary>
    /// التحقق مما إذا كانت الوجهة مشبوهة / Check if destination is suspicious
    /// </summary>
    public bool IsSuspiciousDestination(string hostOrIp, out string threatCategory)
    {
        threatCategory = string.Empty;
        try
        {
            if (_maliciousDomains.Contains(hostOrIp))
            {
                threatCategory = "Malicious_Domain";
                return true;
            }

            if (_maliciousIps.Contains(hostOrIp))
            {
                threatCategory = "Malicious_IP";
                return true;
            }
        }
        catch (Exception ex)
        {
            // Fail-open
            Console.WriteLine($"[C2DomainReputation] IsSuspiciousDestination Error: {ex.Message}");
        }
        
        return false;
    }

    public void Dispose()
    {
        // تنظيف / Cleanup
        _maliciousDomains.Clear();
        _maliciousIps.Clear();
    }
}
