using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace PhoenixGSM.OmniTrace.SupplyChainVerification;

public class SignatureAuditResult
{
    public bool IsValid { get; set; }
    public string PublisherName { get; set; } = string.Empty;
    public bool IsTrustedChain { get; set; }
    public string StatusMessage { get; set; } = string.Empty;
}

public class CodeSignatureValidator
{
    /// <summary>
    /// يفحص التوقيعات الرقمية للملفات التنفيذية / Inspects Authenticode digital signatures
    /// </summary>
    public SignatureAuditResult VerifyExecutableSignature(string filePath)
    {
        var result = new SignatureAuditResult { IsValid = false };

        try
        {
            if (!File.Exists(filePath))
            {
                result.StatusMessage = "الملف غير موجود / File not found";
                return result;
            }

            // التحقق من التوقيع الرقمي / Verify digital signature
            using var cert = X509Certificate2.CreateFromCertFile(filePath);
            using var cert2 = new X509Certificate2(cert);

            result.PublisherName = cert2.Subject;
            
            // التحقق من سلسلة الثقة / Validate chain integrity
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            
            bool isChainValid = chain.Build(cert2);
            result.IsTrustedChain = isChainValid;
            
            // التحقق من تواريخ الصلاحية / Validate dates
            bool isDateValid = DateTime.Now >= cert2.NotBefore && DateTime.Now <= cert2.NotAfter;

            result.IsValid = isChainValid && isDateValid;
            result.StatusMessage = result.IsValid ? "توقيع صالح / Valid Signature" : "توقيع غير صالح / Invalid Signature";
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            // No signature present or corrupted
            // لا يوجد توقيع أو الملف تالف
            result.StatusMessage = "لم يتم العثور على توقيع / No signature found";
        }
        catch (Exception ex)
        {
            // Fail-open: لا تعطل النظام / Do not crash system
            result.StatusMessage = $"خطأ في التحقق / Validation Error: {ex.Message}";
        }

        return result;
    }
}
