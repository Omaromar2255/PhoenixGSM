using System;

namespace PhoenixGSM.OmniTrace.InjectionDetection;

/// <summary>
/// Detects remote thread creation and cross-process memory manipulation.
/// يكتشف إنشاء الخيوط عن بُعد والتلاعب بذاكرة العمليات المتقاطعة.
/// </summary>
public class RemoteThreadInjectionDetector : IDisposable
{
    private const uint PAGE_EXECUTE_READWRITE = 0x40;

    /// <summary>
    /// Inspects thread creation for malicious cross-process activity.
    /// يفحص إنشاء الخيوط بحثاً عن نشاط خبيث بين العمليات.
    /// </summary>
    public bool InspectThreadCreation(int targetPid, int creatorPid, IntPtr startAddress, out string threatDescription)
    {
        threatDescription = string.Empty;

        try
        {
            // CreateRemoteThread or NtCreateThreadEx into a different process
            // إنشاء خيط في عملية مختلفة
            if (targetPid != creatorPid)
            {
                threatDescription = $"Remote Thread Injection detected: Process (PID: {creatorPid}) created a thread in Target (PID: {targetPid}) at address 0x{startAddress:X}.";
                return true;
            }

            return false;
        }
        catch (Exception ex)
        {
            // Fail-open pattern
            // نمط تجاوز الفشل
            Console.WriteLine($"[RemoteThreadInjectionDetector Error]: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Inspects memory allocation for RWX permissions in remote processes.
    /// يفحص تخصيص الذاكرة لصلاحيات RWX في العمليات البعيدة.
    /// </summary>
    public bool InspectMemoryAllocation(int targetPid, int allocatorPid, uint protectionFlags, out string threatDescription)
    {
        threatDescription = string.Empty;
        
        try
        {
            if (targetPid != allocatorPid && protectionFlags == PAGE_EXECUTE_READWRITE)
            {
                threatDescription = $"Suspicious Cross-Process Allocation: Process {allocatorPid} allocated PAGE_EXECUTE_READWRITE memory in Process {targetPid}.";
                return true;
            }
            return false;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[RemoteThreadInjectionDetector Error]: {ex.Message}");
            return false;
        }
    }

    public void Dispose()
    {
        // Cleanup (if any managed/unmanaged resources were held)
        // تنظيف الموارد
    }
}
