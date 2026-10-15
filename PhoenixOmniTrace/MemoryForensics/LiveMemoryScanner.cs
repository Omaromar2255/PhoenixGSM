using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace PhoenixGSM.OmniTrace.MemoryForensics
{
    public record MemoryFinding(IntPtr Address, string Description);

    public class LiveMemoryScanner : IDisposable
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        private const int PROCESS_QUERY_INFORMATION = 0x0400;
        private const int PROCESS_VM_READ = 0x0010;
        private const uint MEM_COMMIT = 0x1000;
        private const uint PAGE_EXECUTE_READ = 0x20;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;

        // فحص الذاكرة الحية للعملية - Scan live memory of a process
        public List<MemoryFinding> ScanProcessMemory(int pid)
        {
            var findings = new List<MemoryFinding>();
            try
            {
                IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
                if (hProcess == IntPtr.Zero)
                {
                    return findings;
                }

                IntPtr address = IntPtr.Zero;
                while (true)
                {
                    int result = VirtualQueryEx(hProcess, address, out MEMORY_BASIC_INFORMATION memInfo, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));
                    if (result == 0) break;

                    if (memInfo.State == MEM_COMMIT && (memInfo.Protect == PAGE_EXECUTE_READ || memInfo.Protect == PAGE_EXECUTE_READWRITE))
                    {
                        byte[] buffer = new byte[(long)memInfo.RegionSize];
                        if (ReadProcessMemory(hProcess, memInfo.BaseAddress, buffer, buffer.Length, out int bytesRead))
                        {
                            // Example detection logic - C2 URLs or shellcode
                            // فحص بسيط للذاكرة - Simple memory check
                            if (ContainsMaliciousPattern(buffer, bytesRead))
                            {
                                findings.Add(new MemoryFinding(memInfo.BaseAddress, "Suspicious executable memory pattern detected. / تم اكتشاف نمط مشبوه في الذاكرة القابلة للتنفيذ."));
                            }
                        }
                    }

                    // Move to next region
                    long nextAddress = (long)memInfo.BaseAddress + (long)memInfo.RegionSize;
                    address = (IntPtr)nextAddress;
                }
            }
            catch (Exception ex)
            {
                // منع التوقف المفاجئ - Prevent crash
                Console.WriteLine($"[LiveMemoryScanner] Error: {ex.Message}");
            }
            return findings;
        }

        private bool ContainsMaliciousPattern(byte[] buffer, int length)
        {
            // Placeholder for pattern matching
            return false;
        }

        public void Dispose()
        {
            // تحرير الموارد - Free resources
        }
    }
}
