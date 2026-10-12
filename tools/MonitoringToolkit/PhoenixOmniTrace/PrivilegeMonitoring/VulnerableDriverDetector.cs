using System;
using System.Collections.Concurrent;

namespace PhoenixGSM.OmniTrace.PrivilegeMonitoring;

/// <summary>
/// Detects BYOVD (Bring Your Own Vulnerable Driver) attacks
/// يكتشف هجمات BYOVD (إحضار تعريف ضعيف خاص بك)
/// </summary>
public class VulnerableDriverDetector : IDisposable
{
    private readonly ConcurrentDictionary<string, string> _vulnerableDrivers = new(StringComparer.OrdinalIgnoreCase);

    public VulnerableDriverDetector()
    {
        // قائمة التعريفات الضعيفة المعروفة
        // Known vulnerable drivers list
        _vulnerableDrivers["dbutil_2_3.sys"] = "CVE-2021-21551";
        _vulnerableDrivers["gdrv.sys"] = "CVE-2018-19320";
        _vulnerableDrivers["RTCore64.sys"] = "CVE-2019-16098";
        _vulnerableDrivers["capcom.sys"] = "Capcom Anti-Cheat ByDesign Bypass";
        _vulnerableDrivers["kprocesshacker.sys"] = "Process Hacker Capability Abuse";
    }

    public bool IsKnownVulnerableDriver(string driverName, string sha256Hash, out string cveReference)
    {
        cveReference = string.Empty;
        try
        {
            if (_vulnerableDrivers.TryGetValue(driverName, out var cve) && cve != null)
            {
                cveReference = cve;
                return true;
            }
            
            // Should also check hash in real-world scenario
            // يجب أيضًا التحقق من التجزئة في سيناريو العالم الحقيقي
        }
        catch (Exception ex)
        {
            // Fail open
            Console.WriteLine($"[ByovdMon] Error checking driver: {ex.Message}");
        }

        return false;
    }

    public void Dispose()
    {
        _vulnerableDrivers.Clear();
    }
}
