using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace PhoenixGSM.OmniTrace.Reporting
{
    public record EvidenceItem(string Id, string Description, byte[] Data);

    public class EvidenceChainOfCustody
    {
        // إنشاء سجل تتبع الأدلة - Generate evidence tracking manifest
        public string GenerateCustodyManifest(string caseId, string examinerName, IEnumerable<EvidenceItem> items)
        {
            try
            {
                var sb = new StringBuilder();
                sb.AppendLine($"--- EVIDENCE CHAIN OF CUSTODY / سجل تتبع الأدلة ---");
                sb.AppendLine($"Case ID / رقم القضية: {caseId}");
                sb.AppendLine($"Examiner / المحقق: {examinerName}");
                sb.AppendLine($"Date / التاريخ: {DateTime.UtcNow:O}");
                sb.AppendLine("-------------------------------------------------");

                using var sha256 = SHA256.Create();

                foreach (var item in items)
                {
                    byte[] hashBytes = sha256.ComputeHash(item.Data);
                    string hashString = Convert.ToHexString(hashBytes);
                    
                    sb.AppendLine($"Item ID: {item.Id}");
                    sb.AppendLine($"Description: {item.Description}");
                    sb.AppendLine($"SHA-256: {hashString}");
                    sb.AppendLine($"Timestamp: {DateTime.UtcNow:O}");
                    sb.AppendLine("---");
                }

                return sb.ToString();
            }
            catch (Exception ex)
            {
                // منع التوقف المفاجئ - Prevent crash
                Console.WriteLine($"[EvidenceChainOfCustody] Error: {ex.Message}");
                return $"Error generating manifest: {ex.Message}";
            }
        }
    }
}
