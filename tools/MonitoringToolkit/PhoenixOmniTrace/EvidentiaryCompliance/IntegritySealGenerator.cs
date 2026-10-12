using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace PhoenixGSM.OmniTrace.EvidentiaryCompliance;

public class IntegritySealGenerator
{
    /// <summary>
    /// ينشئ أختام سلامة رقمية وبيانات تدقيق متوافقة مع ISO / Generates ISO-compliant digital integrity seals
    /// </summary>
    public string GenerateIntegritySealManifest(string sessionId, string examiner, IDictionary<string, string> artifactHashes)
    {
        var manifestBuilder = new StringBuilder();

        try
        {
            string timestamp = DateTime.UtcNow.ToString("O"); // UTC Timestamp (RFC 3339)
            
            manifestBuilder.AppendLine("=== PHOENIX OMNITRACE EVIDENCE SEAL MANIFEST ===");
            manifestBuilder.AppendLine($"Session ID: {sessionId}");
            manifestBuilder.AppendLine($"Examiner: {examiner}");
            manifestBuilder.AppendLine($"Seal Timestamp (UTC): {timestamp}");
            manifestBuilder.AppendLine("================================================");

            manifestBuilder.AppendLine("Artifacts Hashes (SHA-256):");
            
            // حساب التجزئة الشاملة / Calculate overall manifest hash
            using var sha256 = SHA256.Create();
            var concatHashes = new StringBuilder();

            if (artifactHashes != null)
            {
                foreach (var kvp in artifactHashes)
                {
                    manifestBuilder.AppendLine($"- {kvp.Key}: {kvp.Value}");
                    concatHashes.Append(kvp.Value);
                }
            }

            byte[] overallHashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(concatHashes.ToString() + timestamp));
            string overallSeal = BitConverter.ToString(overallHashBytes).Replace("-", "").ToLowerInvariant();

            manifestBuilder.AppendLine("================================================");
            manifestBuilder.AppendLine($"Integrity Seal (SHA-256): {overallSeal}");
            manifestBuilder.AppendLine("=== END OF MANIFEST ===");
        }
        catch (Exception ex)
        {
            // Fail-open: إنشاء بيان خطأ آمن / Create safe error manifest
            manifestBuilder.AppendLine($"[Seal Error] فشل إنشاء الختم / Failed to generate seal: {ex.Message}");
        }

        return manifestBuilder.ToString();
    }
}
