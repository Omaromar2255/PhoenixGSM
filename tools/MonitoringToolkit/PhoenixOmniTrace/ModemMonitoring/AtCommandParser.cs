using System;

namespace PhoenixGSM.OmniTrace.ModemMonitoring
{
    public class AtCommandParser : IDisposable
    {
        /// <summary>
        /// يحلل أوامر AT ويصنف مستوى الخطورة - Parses AT commands and categorizes risk levels
        /// </summary>
        public ModemCommandEvent ParseAtCommand(string line, ModemRoute route = ModemRoute.UsbCdcAcm, string port = "")
        {
            try
            {
                if (string.IsNullOrWhiteSpace(line))
                {
                    return CreateEvent(route, line, ModemRiskCategory.InfoQuery, 0, "أمر فارغ - Empty Command", port);
                }

                var upperLine = line.Trim().ToUpperInvariant();
                ModemRiskCategory category = ModemRiskCategory.InfoQuery;
                int riskLevel = 0;
                string desc = "استعلام أو أمر قياسي - Standard Query/Command";

                // 1. فحص أوامر تغيير IMEI أو فك قفل الشبكة (Network Lock / IMEI Rewrite)
                if (upperLine.StartsWith("AT+EGMR") || upperLine.StartsWith("AT^CARDLOCK") || upperLine.StartsWith("AT+SIMLOCK") || upperLine.Contains("AT+MODEM_UNLOCK"))
                {
                    category = ModemRiskCategory.SimLockTampering;
                    riskLevel = 9;
                    desc = "تعديل حماية الشبكة أو تغيير IMEI - Network Lock / IMEI modification";
                }
                // 2. فحص أوامر قفل بطاقة SIM (SIM PIN/PUK)
                else if (upperLine.StartsWith("AT+CPIN") || upperLine.StartsWith("AT+CLCK") || upperLine.StartsWith("AT+CPWD"))
                {
                    category = ModemRiskCategory.SimLockTampering;
                    riskLevel = 6;
                    desc = "إدارة رموز الحماية أو قفل SIM - SIM Lock/PIN Management";
                }
                // 3. فحص أوامر الراديو والشبكة (Radio Power/Network Selection)
                else if (upperLine.StartsWith("AT+CFUN") || upperLine.StartsWith("AT+COPS"))
                {
                    category = ModemRiskCategory.RadioControl;
                    riskLevel = 4;
                    desc = "التحكم في طاقة الراديو أو اختيار الشبكة - Radio Power / Network Selection";
                }
                // 4. فحص أوامر المكالمات والرسائل (Calls / SMS)
                else if (upperLine.StartsWith("ATD") || upperLine.StartsWith("ATA") || upperLine.StartsWith("AT+CMGS"))
                {
                    category = ModemRiskCategory.SmsCallOperations;
                    riskLevel = 3;
                    desc = "عمليات مكالمات أو رسائل - Call/SMS Operations";
                }
                // 5. أوامر غير قياسية / غير معروفة (Proprietary / Unknown)
                else if (upperLine.StartsWith("AT$") || upperLine.StartsWith("AT%"))
                {
                    category = ModemRiskCategory.VendorSpecificHighRisk;
                    riskLevel = 7;
                    desc = "أمر خاص بالشركة المصنعة - Proprietary Vendor Command";
                }

                return CreateEvent(route, line, category, riskLevel, desc, port);
            }
            catch (Exception ex)
            {
                // Fail-open: لا تعطل النظام في حال حدوث خطأ - Do not crash the system on error
                return CreateEvent(route, line, ModemRiskCategory.InfoQuery, 0, $"خطأ في التحليل - Parse error: {ex.Message}", port);
            }
        }

        private ModemCommandEvent CreateEvent(ModemRoute route, string cmd, ModemRiskCategory cat, int risk, string desc, string port)
        {
            return new ModemCommandEvent(route, cmd, cat, risk, desc, port, DateTime.UtcNow, null);
        }

        public void Dispose()
        {
            // تنظيف الموارد إن وجدت - Cleanup resources if any
            GC.SuppressFinalize(this);
        }
    }
}
