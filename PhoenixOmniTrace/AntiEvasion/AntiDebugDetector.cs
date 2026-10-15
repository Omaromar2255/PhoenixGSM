using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace PhoenixGSM.OmniTrace.AntiEvasion
{
    public class AntiDebugDetector : IDisposable
    {
        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern bool IsDebuggerPresent();

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);

        // اكتشاف محاولات التهرب ومكافحة التحليل - Detect evasion and anti-analysis attempts
        public bool DetectEvasionAttempt(string apiNameOrBehavior, out string evasionType)
        {
            evasionType = string.Empty;
            try
            {
                // Check IsDebuggerPresent API
                if (apiNameOrBehavior.Contains("IsDebuggerPresent", StringComparison.OrdinalIgnoreCase))
                {
                    if (IsDebuggerPresent())
                    {
                        evasionType = "Debugger Present Detection API";
                        return true;
                    }
                }

                // Check RDTSC timing
                if (apiNameOrBehavior.Contains("RDTSC", StringComparison.OrdinalIgnoreCase))
                {
                    evasionType = "Timing Evasion (RDTSC)";
                    return true;
                }

                // Window titles check (e.g., Process Hacker, Wireshark)
                if (apiNameOrBehavior.Contains("Wireshark", StringComparison.OrdinalIgnoreCase) || 
                    apiNameOrBehavior.Contains("ProcessHacker", StringComparison.OrdinalIgnoreCase))
                {
                    evasionType = "Analysis Tool Window Search";
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                // منع التوقف المفاجئ - Prevent crash
                Console.WriteLine($"[AntiDebugDetector] Error: {ex.Message}");
                return false;
            }
        }

        public void Dispose()
        {
            // تحرير الموارد - Free resources
        }
    }
}
