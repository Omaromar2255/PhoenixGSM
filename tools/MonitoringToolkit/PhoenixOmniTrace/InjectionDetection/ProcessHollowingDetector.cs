using System;
using System.Collections.Concurrent;

namespace PhoenixGSM.OmniTrace.InjectionDetection;

/// <summary>
/// Detects indicators of Process Hollowing / RunPE.
/// يكتشف مؤشرات تفريغ العمليات / RunPE.
/// </summary>
public class ProcessHollowingDetector : IDisposable
{
    private const uint CREATE_SUSPENDED = 0x00000004;

    private class ProcessState
    {
        public int ParentPid { get; set; }
        public string ImageName { get; set; } = string.Empty;
        public bool IsSuspended { get; set; }
        public bool MemoryManipulated { get; set; }
    }

    // سجل للعمليات المعلقة (Log for suspended processes)
    private readonly ConcurrentDictionary<int, ProcessState> _suspendedProcesses = new();

    /// <summary>
    /// Analyze process creation for hollowing indicators.
    /// تحليل إنشاء العملية لمؤشرات التفريغ.
    /// </summary>
    public bool AnalyzeProcessCreationSequence(int pid, int parentPid, string imageName, bool isSuspended, out string alertDescription)
    {
        alertDescription = string.Empty;
        
        try
        {
            if (isSuspended)
            {
                // Process created with CREATE_SUSPENDED
                // تم إنشاء العملية بحالة معلقة
                _suspendedProcesses[pid] = new ProcessState
                {
                    ParentPid = parentPid,
                    ImageName = imageName,
                    IsSuspended = true,
                    MemoryManipulated = false
                };

                // We don't alert immediately on suspension alone, as legit processes might do it.
                // لا ننذر فوراً بناءً على التعليق فقط، لأن العمليات الشرعية قد تفعل ذلك.
            }

            // In a real scenario, we would check for image/memory discrepancies here
            // في السيناريو الحقيقي، سنتحقق من تباين الصورة/الذاكرة هنا
            bool imageMismatch = CheckImageMemoryDiscrepancy(pid);
            if (imageMismatch)
            {
                alertDescription = $"Process Hollowing Indicator: Discrepancy between image on disk and memory base for {imageName} (PID: {pid}).";
                return true;
            }

            return false;
        }
        catch (Exception ex)
        {
            // Fail-open: Do not crash the monitoring system
            // منع الانهيار: لا توقف نظام المراقبة
            Console.WriteLine($"[ProcessHollowingDetector Error]: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Simulates sequence: NtUnmapViewOfSection/VirtualAllocEx -> WriteProcessMemory -> ResumeThread
    /// يحاكي التسلسل: NtUnmapViewOfSection/VirtualAllocEx -> WriteProcessMemory -> ResumeThread
    /// </summary>
    public bool AnalyzeApiCall(int pid, string apiCall, out string alertDescription)
    {
        alertDescription = string.Empty;
        try
        {
            if (_suspendedProcesses.TryGetValue(pid, out var state))
            {
                if (apiCall is "NtUnmapViewOfSection" or "VirtualAllocEx" or "WriteProcessMemory")
                {
                    state.MemoryManipulated = true;
                }
                else if (apiCall == "ResumeThread" && state.MemoryManipulated)
                {
                    alertDescription = $"Process Hollowing Detected: Process {state.ImageName} (PID: {pid}) resumed after memory manipulation.";
                    _suspendedProcesses.TryRemove(pid, out _);
                    return true;
                }
            }
            return false;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ProcessHollowingDetector Error]: {ex.Message}");
            return false;
        }
    }

    private bool CheckImageMemoryDiscrepancy(int pid)
    {
        // Placeholder for memory discrepancy check
        // عنصر نائب للتحقق من تباين الذاكرة
        return false; 
    }

    public void Dispose()
    {
        // Cleanup resources
        // تنظيف الموارد
        _suspendedProcesses.Clear();
    }
}
