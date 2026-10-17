using System;
using System.Collections.Generic;
using System.Text;

namespace PhoenixGSM.OmniTrace.BinaryAnalysis;

public class ElfInspectionResult
{
    public bool IsValidElf { get; set; }
    public string Architecture { get; set; } = "Unknown";
    public bool HasDangerousSymbols { get; set; }
    public string[] DangerousSymbolsFound { get; set; } = Array.Empty<string>();
    public bool IsPackedRilBridge { get; set; }
    public string ForensicClassification { get; set; } = string.Empty;
    public string[] BuildSignaturesFound { get; set; } = Array.Empty<string>();
}

/// <summary>
/// Standalone C# parser for ELF binary headers and forensic fingerprinting.
/// محلل C# مستقل لترويسات ملفات ELF وفحص البصمات الجنائية.
/// </summary>
public class ElfBinaryInspector : IDisposable
{
    private static ReadOnlySpan<byte> ElfMagic => new byte[] { 0x7F, 0x45, 0x4C, 0x46 }; // 0x7F 'E' 'L' 'F'
    
    private readonly string[] _dangerousSymbols = { "system", "popen", "execve", "ptrace", "mprotect" };

    private readonly string[] _forensicSignatures =
    {
        "Android r21e",
        "/system/bin/linker64",
        "/dev/shm",
        "/proc/self/exe",
        "PROT_EXEC",
        "PROT_EXE",
        "liblog.so",
        "KEY-Tool"
    };

    /// <summary>
    /// Inspects raw ELF data for structure, dangerous imported symbols, and forensic signatures.
    /// يفحص بيانات ELF الخام للبحث عن الرموز وبصمات الضغط الجنائي.
    /// </summary>
    public ElfInspectionResult InspectElf(ReadOnlySpan<byte> elfData)
    {
        var result = new ElfInspectionResult();

        try
        {
            // 1. Magic check
            // 1. فحص التوقيع السحري
            if (elfData.Length < 4 || !elfData.Slice(0, 4).SequenceEqual(ElfMagic))
            {
                return result; // Not an ELF
            }

            result.IsValidElf = true;

            // 2. Architecture identification (e_machine field at offset 18)
            // 2. تحديد المعمارية (حقل e_machine عند الإزاحة 18)
            if (elfData.Length >= 20)
            {
                ushort machineType = BitConverter.ToUInt16(elfData.Slice(18, 2).ToArray(), 0);
                result.Architecture = machineType switch
                {
                    0x03 => "x86",
                    0x28 => "ARM",
                    0x3E => "x64",
                    0xB7 => "AArch64",
                    _ => $"Unknown (0x{machineType:X2})"
                };
            }

            // 3. Scan for dangerous symbols
            // 3. البحث عن الرموز الخطيرة
            result.DangerousSymbolsFound = ScanForSymbols(elfData);
            result.HasDangerousSymbols = result.DangerousSymbolsFound.Length > 0;

            // 4. Forensic Fingerprint Scan (AT binary, self-unpacking bridge)
            // 4. مسح البصمات الجنائية لملف AT وجسر RIL المعبأ
            var foundSignatures = new List<string>();
            string asciiContent = Encoding.Latin1.GetString(elfData.ToArray());

            foreach (var sig in _forensicSignatures)
            {
                if (asciiContent.Contains(sig, StringComparison.OrdinalIgnoreCase))
                {
                    foundSignatures.Add(sig);
                }
            }
            result.BuildSignaturesFound = foundSignatures.ToArray();

            bool hasSelfUnpackIndicators = asciiContent.Contains("/proc/self/exe", StringComparison.OrdinalIgnoreCase) ||
                                           asciiContent.Contains("/dev/shm", StringComparison.OrdinalIgnoreCase) ||
                                           asciiContent.Contains("PROT_EXE", StringComparison.OrdinalIgnoreCase);

            if (hasSelfUnpackIndicators)
            {
                result.IsPackedRilBridge = true;
                result.ForensicClassification = "Packed ARM64 ELF RIL/AT Bridge (Self-Unpacking in RAM via /dev/shm & /proc/self/exe)";
            }
            else if (foundSignatures.Count > 0)
            {
                result.ForensicClassification = $"Native ELF Bridge ({string.Join(", ", foundSignatures)})";
            }

            return result;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ElfBinaryInspector Error]: {ex.Message}");
            return result;
        }
    }

    public ElfInspectionResult InspectElf(byte[] elfData)
    {
        if (elfData == null || elfData.Length == 0)
        {
            return new ElfInspectionResult();
        }
        return InspectElf(new ReadOnlySpan<byte>(elfData));
    }

    private string[] ScanForSymbols(ReadOnlySpan<byte> data)
    {
        var foundSymbols = new List<string>();
        string content = Encoding.Latin1.GetString(data.ToArray());

        foreach (var symbol in _dangerousSymbols)
        {
            if (content.Contains(symbol, StringComparison.OrdinalIgnoreCase))
            {
                foundSymbols.Add(symbol);
            }
        }
        return foundSymbols.ToArray();
    }

    public void Dispose()
    {
    }
}
