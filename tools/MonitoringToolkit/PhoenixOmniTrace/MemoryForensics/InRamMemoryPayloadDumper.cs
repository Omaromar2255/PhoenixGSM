using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace PhoenixGSM.OmniTrace.MemoryForensics;

/// <summary>
/// Represents a payload extracted from an in-memory executable region.
/// يمثل حمولة تم استخراجها من منطقة تنفيذية في الذاكرة.
/// </summary>
public record ExtractedRamPayload(
    int ProcessId,
    long BaseAddress,
    long RegionSize,
    string SavedFilePath,
    string SignatureType
);

/// <summary>
/// Dumps in-RAM memory regions that have executable permissions to detect reflective loading.
/// يستخرج مناطق الذاكرة التي تحتوي على صلاحيات تنفيذية لاكتشاف التحميل الانعكاسي.
/// </summary>
public class InRamMemoryPayloadDumper : IDisposable
{
    private const int PROCESS_QUERY_INFORMATION = 0x0400;
    private const int PROCESS_VM_READ = 0x0010;
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_EXECUTE_WRITECOPY = 0x80;
    private const uint MEM_COMMIT = 0x1000;

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORY_BASIC_INFORMATION64
    {
        public ulong BaseAddress;
        public ulong AllocationBase;
        public uint AllocationProtect;
        public uint __alignment1;
        public ulong RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
        public uint __alignment2;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION64 lpBuffer, uint dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, IntPtr nSize, out IntPtr lpNumberOfBytesRead);

    public event Action<ExtractedRamPayload>? OnRamPayloadExtracted;

    /// <summary>
    /// Scans a target process for executable memory pages and dumps them.
    /// يفحص عملية مستهدفة للبحث عن صفحات ذاكرة تنفيذية ويقوم باستخراجها.
    /// </summary>
    public List<ExtractedRamPayload> DumpExecutableMemoryRegions(int targetPid, string vaultDirectory)
    {
        var payloads = new List<ExtractedRamPayload>();
        IntPtr hProcess = IntPtr.Zero;

        try
        {
            if (!Directory.Exists(vaultDirectory))
                Directory.CreateDirectory(vaultDirectory);

            hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, targetPid);
            if (hProcess == IntPtr.Zero)
                return payloads;

            ulong address = 0;
            long maxAddress = unchecked((long)0x7FFFFFFFFFFFL); // Typical user-mode max address

            while (address < (ulong)maxAddress)
            {
                var memInfo = new MEMORY_BASIC_INFORMATION64();
                int result = VirtualQueryEx(hProcess, (IntPtr)address, out memInfo, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION64)));
                
                if (result == 0)
                    break;

                // Check if committed and executable / تحقق مما إذا كانت مخصصة وتنفيذية
                bool isCommitted = memInfo.State == MEM_COMMIT;
                bool isExecutable = memInfo.Protect == PAGE_EXECUTE_READ || 
                                    memInfo.Protect == PAGE_EXECUTE_READWRITE || 
                                    memInfo.Protect == PAGE_EXECUTE_WRITECOPY;

                if (isCommitted && isExecutable && memInfo.RegionSize > 0)
                {
                    DumpRegion(hProcess, targetPid, memInfo, vaultDirectory, payloads);
                }

                address = memInfo.BaseAddress + memInfo.RegionSize;
            }
        }
        catch (Exception ex)
        {
            // Fail-open: swallow exceptions to prevent crashing the trace service
            // تجاوز الأخطاء لمنع تعطل خدمة التتبع
            Console.WriteLine($"[Dumper] Failed to dump PID {targetPid}: {ex.Message}");
        }
        finally
        {
            if (hProcess != IntPtr.Zero)
                CloseHandle(hProcess);
        }

        return payloads;
    }

    private void DumpRegion(IntPtr hProcess, int pid, MEMORY_BASIC_INFORMATION64 memInfo, string vaultDir, List<ExtractedRamPayload> payloads)
    {
        try
        {
            byte[] buffer = new byte[memInfo.RegionSize];
            if (ReadProcessMemory(hProcess, (IntPtr)memInfo.BaseAddress, buffer, (IntPtr)memInfo.RegionSize, out _))
            {
                string sig = DetectSignature(buffer);
                if (sig != "Unknown")
                {
                    string filePath = Path.Combine(vaultDir, $"dump_pid{pid}_0x{memInfo.BaseAddress:X}.bin");
                    File.WriteAllBytes(filePath, buffer);

                    var payload = new ExtractedRamPayload(pid, (long)memInfo.BaseAddress, (long)memInfo.RegionSize, filePath, sig);
                    payloads.Add(payload);
                    OnRamPayloadExtracted?.Invoke(payload);
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Dumper] ReadProcessMemory failed at {memInfo.BaseAddress:X}: {ex.Message}");
        }
    }

    private string DetectSignature(byte[] data)
    {
        if (data.Length >= 2 && data[0] == 0x4D && data[1] == 0x5A) // MZ
            return "PE_Executable";
        if (data.Length >= 4 && data[0] == 0x7F && data[1] == 0x45 && data[2] == 0x4C && data[3] == 0x46) // ELF
            return "ELF_Executable";
        
        // Simple heuristic for common shellcode NOP sleds or interrupts
        // طريقة بسيطة لاكتشاف شفرة القشرة
        if (data.Length > 16 && data[0] == 0x90 && data[1] == 0x90 && data[2] == 0x90)
            return "Possible_Shellcode";

        return "Unknown";
    }

    public void Dispose()
    {
        // Cleanup resources if any long-lived handles were kept
        // تنظيف الموارد إذا كانت هناك أي مقابض طويلة الأمد
        OnRamPayloadExtracted = null;
    }
}
