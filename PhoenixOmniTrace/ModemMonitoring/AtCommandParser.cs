using System;

namespace PhoenixGSM.OmniTrace.ModemMonitoring
{
    public class AtCommandParser : IDisposable
    {
        /// <summary>
        /// يحلل أوامر AT ويصنف مستوى الخطورة - Parses AT commands and categorizes risk levels
        /// </summary>
        public ModemCommandEvent? ParseAtCommand(string line, ModemRoute route = ModemRoute.UsbCdcAcm, string port = "")
        {
            try
            {
                if (string.IsNullOrWhiteSpace(line))
                {
                    return null;
                }

                string trimmed = line.Trim();

                // Reject getprop fragments, hex streams, parcel results, and non-modem artifacts
                if (trimmed.Contains("]: [") || trimmed == "]" || trimmed.Contains("0x0000") ||
                    trimmed.Contains("Enforcing", StringComparison.OrdinalIgnoreCase) ||
                    trimmed.Contains("Permissive", StringComparison.OrdinalIgnoreCase) ||
                    trimmed.Contains("0x4948", StringComparison.OrdinalIgnoreCase) ||
                    trimmed.Contains("0x4f4c", StringComparison.OrdinalIgnoreCase) ||
                    trimmed.Contains("0x494d", StringComparison.OrdinalIgnoreCase) ||
                    trimmed.Contains("Product Name", StringComparison.OrdinalIgnoreCase) ||
                    trimmed.Contains("Product Model", StringComparison.OrdinalIgnoreCase) ||
                    trimmed.Contains("Build  Number", StringComparison.OrdinalIgnoreCase) ||
                    trimmed.Contains("Serial Number", StringComparison.OrdinalIgnoreCase) ||
                    trimmed.Contains("restarting in USB mode", StringComparison.OrdinalIgnoreCase) ||
                    trimmed.Contains("#OK", StringComparison.OrdinalIgnoreCase) ||
                    trimmed.StartsWith("AuthKey", StringComparison.OrdinalIgnoreCase) ||
                    trimmed.StartsWith("Token AuthKey", StringComparison.OrdinalIgnoreCase))
                {
                    return null;
                }

                // Reject long hex strings (>= 32 hex chars)
                if (trimmed.Length >= 32 && trimmed.All(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                {
                    return null;
                }

                var upperLine = trimmed.ToUpperInvariant();

                // Strict validation: must start with standard AT command or modem response prefix
                bool isStandardAt = upperLine.StartsWith("AT+") || upperLine.StartsWith("AT*") || upperLine.StartsWith("AT#") ||
                                    upperLine.StartsWith("AT$") || upperLine.StartsWith("AT%") || upperLine.StartsWith("AT^") ||
                                    upperLine.StartsWith("ATE") || upperLine.StartsWith("ATI") || upperLine.StartsWith("ATD") ||
                                    upperLine.StartsWith("ATA") || upperLine.StartsWith("ATH") || upperLine.StartsWith("ATO") ||
                                    upperLine.StartsWith("ATZ") || upperLine.StartsWith("AT&") || upperLine.StartsWith("ATQ") ||
                                    upperLine.StartsWith("ATV") || upperLine.StartsWith("ATX") || upperLine == "AT" ||
                                    upperLine == "A/" || upperLine.StartsWith("^") ||
                                    upperLine.StartsWith("+") || upperLine == "OK" || upperLine.StartsWith("ERROR") ||
                                    upperLine.StartsWith("+CME ERROR:") || upperLine.StartsWith("+CMS ERROR:") || upperLine.StartsWith("+DEVCONINFO:") ||
                                    upperLine.StartsWith("ANY-") || upperLine.StartsWith("SM-") || upperLine.StartsWith("MODEL:") || upperLine.StartsWith("IMEI:") ||
                                    (trimmed.Length >= 14 && trimmed.Length <= 16 && trimmed.All(char.IsDigit));

                if (!isStandardAt)
                {
                    return null;
                }

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

                return CreateEvent(route, trimmed, category, riskLevel, desc, port);
            }
            catch (Exception)
            {
                // Fail-open: لا تعطل النظام في حال حدوث خطأ - Do not crash the system on error
                return null;
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
