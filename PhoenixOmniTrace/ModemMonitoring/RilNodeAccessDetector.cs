using System;

namespace PhoenixGSM.OmniTrace.ModemMonitoring
{
    public class RilNodeAccessDetector : IDisposable
    {
        /// <summary>
        /// يراقب أوامر الشل بحثاً عن تفاعلات مباشرة مع عقد الراديو والمودم
        /// Inspects shell commands for direct interaction with Radio/Modem nodes
        /// </summary>
        public ModemCommandEvent? InspectShellCommand(string shellCmd)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(shellCmd))
                    return null;

                var lowerCmd = shellCmd.ToLowerInvariant();
                
                // فحص العقد الخاصة بالمودم (Modem/Radio Nodes)
                bool accessesModemNodes = lowerCmd.Contains("/dev/smd") || 
                                          lowerCmd.Contains("/dev/qmi") || 
                                          lowerCmd.Contains("/dev/radio") || 
                                          lowerCmd.Contains("/dev/mhi") ||
                                          lowerCmd.Contains("/dev/ttyusb"); // Sometimes used for AT

                // فحص التدخل المباشر في مكتبات وخدمات الراديو
                bool accessesRilDeamon = lowerCmd.Contains("libril.so") || 
                                         lowerCmd.Contains("ril-daemon") ||
                                         lowerCmd.Contains("setprop rild.");

                if (accessesModemNodes || accessesRilDeamon)
                {
                    int riskLevel = accessesModemNodes ? 7 : 6;
                    string desc = accessesModemNodes ? 
                        "تفاعل مباشر مع عقد المودم - Direct Modem Node Access (/dev/smd, /dev/qmi, etc.)" : 
                        "تفاعل مع خدمات الراديو - RIL Daemon/Library Interaction";

                    return new ModemCommandEvent(
                        ModemRoute.AdbRilInternal,
                        shellCmd,
                        ModemRiskCategory.RadioControl,
                        riskLevel,
                        desc,
                        "ADB_SHELL_RIL",
                        DateTime.UtcNow,
                        null
                    );
                }

                return null;
            }
            catch (Exception)
            {
                // Fail-open: تجاهل الأمر في حال حدوث خطأ للحفاظ على استقرار النظام
                return null;
            }
        }

        public void Dispose()
        {
            // تنظيف الموارد - Cleanup
            GC.SuppressFinalize(this);
        }
    }
}
