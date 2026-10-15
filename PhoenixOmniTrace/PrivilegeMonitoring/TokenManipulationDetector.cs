using System;
using System.Linq;

namespace PhoenixGSM.OmniTrace.PrivilegeMonitoring;

/// <summary>
/// Detects Windows Access Token abuse
/// يكتشف إساءة استخدام رموز وصول Windows
/// </summary>
public class TokenManipulationDetector : IDisposable
{
    private readonly string[] _dangerousPrivileges = 
    {
        "SeDebugPrivilege",
        "SeTcbPrivilege",
        "SeBackupPrivilege",
        "SeRestorePrivilege",
        "SeTakeOwnershipPrivilege",
        "SeLoadDriverPrivilege"
    };

    public bool InspectTokenPrivileges(int pid, string[] enabledPrivileges, out string alertMessage)
    {
        alertMessage = string.Empty;
        try
        {
            var matched = enabledPrivileges.Where(p => _dangerousPrivileges.Contains(p, StringComparer.OrdinalIgnoreCase)).ToList();
            
            if (matched.Any())
            {
                alertMessage = $"Process {pid} enabled dangerous privileges: {string.Join(", ", matched)}";
                return true;
            }
        }
        catch (Exception ex)
        {
            // Fail-open
            // فشل مفتوح
            Console.WriteLine($"[TokenMon] Error inspecting privileges: {ex.Message}");
        }

        return false;
    }

    public void Dispose()
    {
        // Cleanup
    }
}
