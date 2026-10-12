using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;

namespace PhoenixGSM.OmniTrace.SupplyChainVerification;

public class CrackAuditResult
{
    public bool IsTampered { get; set; }
    public List<string> IndicatorsFound { get; set; } = new();
}

public class CrackIndicatorDetector
{
    private readonly string[] _suspiciousDlls = { "hasp_windows.dll", "sentinel.dll", "vusb.sys" };
    private readonly string[] _packerMarkers = { "Themida", "VMProtect", "Enigma" }; // Simplified strings

    /// <summary>
    /// يكتشف مؤشرات الأدوات المقرصنة / Detects indicators of cracked / tampered GSM tools
    /// </summary>
    public CrackAuditResult InspectExecutable(string filePath)
    {
        var result = new CrackAuditResult { IsTampered = false };

        try
        {
            if (!File.Exists(filePath)) return result;

            string directory = Path.GetDirectoryName(filePath) ?? string.Empty;
            
            // 1. التحقق من ملفات محاكاة الدونجل / Check for dongle emulator DLLs
            if (!string.IsNullOrEmpty(directory))
            {
                var filesInDir = Directory.GetFiles(directory).Select(Path.GetFileName).ToList();
                foreach (var dll in _suspiciousDlls)
                {
                    if (filesInDir.Any(f => f != null && f.Equals(dll, StringComparison.OrdinalIgnoreCase)))
                    {
                        result.IsTampered = true;
                        result.IndicatorsFound.Add($"مكتبة محاكاة مكتشفة / Emulator DLL found: {dll}");
                    }
                }
            }

            // 2. التحقق من العلامات داخل الملف / Check for packer markers
            // قراءة جزئية سريعة لتجنب قراءة ملفات ضخمة في الذاكرة / Simulating check to avoid massive memory read
            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = new StreamReader(stream);
            
            // Quick partial scan of first 4KB for packer strings
            char[] buffer = new char[4096];
            int bytesRead = reader.ReadBlock(buffer, 0, buffer.Length);
            string header = new string(buffer, 0, bytesRead);

            foreach (var marker in _packerMarkers)
            {
                if (header.Contains(marker, StringComparison.OrdinalIgnoreCase))
                {
                    result.IsTampered = true;
                    result.IndicatorsFound.Add($"مؤشر تعبئة مكتشف / Packer marker found: {marker}");
                }
            }
        }
        catch (Exception ex)
        {
            // Fail-open: لا تعطل النظام / Do not crash system
            Console.WriteLine($"[CrackDetector Error] {ex.Message}");
        }

        return result;
    }
}
