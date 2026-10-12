using System;

namespace PhoenixGSM.OmniTrace.PrivilegeMonitoring;

/// <summary>
/// Detects known UAC (User Account Control) bypass techniques
/// يكتشف تقنيات تجاوز التحكم بحساب المستخدم المعروفة
/// </summary>
public class UacBypassDetector : IDisposable
{
    public bool InspectProcessElevation(string imagePath, string parentImage, string commandLine, out string bypassType)
    {
        bypassType = string.Empty;
        
        try
        {
            string lowerImage = imagePath.ToLowerInvariant();
            string lowerParent = parentImage.ToLowerInvariant();

            // فحص البرامج الموثوقة التي تستخدم لتجاوز UAC
            // Check trusted binaries used for UAC bypass
            if (lowerImage.EndsWith("fodhelper.exe") || 
                lowerImage.EndsWith("eventvwr.exe") || 
                lowerImage.EndsWith("slui.exe") || 
                lowerImage.EndsWith("sdclt.exe"))
            {
                if (!lowerParent.EndsWith("explorer.exe") && !lowerParent.EndsWith("svchost.exe"))
                {
                    bypassType = $"Registry hijacking via {System.IO.Path.GetFileName(imagePath)}";
                    return true;
                }
            }

            // فحص المسارات الوهمية الموثوقة
            // Check mock trusted directories
            if (lowerImage.Contains("windows \\system32")) // Notice the space
            {
                bypassType = "Mock trusted directory (space after Windows)";
                return true;
            }
        }
        catch (Exception ex)
        {
            // Fail open
            // فشل مفتوح
            Console.WriteLine($"[UacMon] Error inspecting elevation: {ex.Message}");
        }
        
        return false;
    }

    public void Dispose()
    {
        // Cleanup
    }
}
