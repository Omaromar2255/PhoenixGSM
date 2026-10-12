using System;
using System.Collections.Generic;

namespace PhoenixGSM.OmniTrace.PayloadAnalysis;

public static class KnownThreatSignatures
{
    /// <summary>
    /// جلب التوقيعات الافتراضية / Get default forensic signatures
    /// </summary>
    public static IReadOnlyList<YaraRuleDefinition> GetDefaultSignatures()
    {
        var rules = new List<YaraRuleDefinition>();

        try
        {
            // 1. Android Spyware (Pegasus, FinSpy, etc.)
            rules.Add(new YaraRuleDefinition
            {
                Name = "Android_Spyware_Indicators",
                Category = "Spyware",
                Severity = "Critical",
                StringPatterns = new List<string> { "com.network.android", "finspy", "pegasus", "record_mic_hidden" }
            });

            // 2. GSM Tool Backdoors
            rules.Add(new YaraRuleDefinition
            {
                Name = "GSM_Tool_Backdoor",
                Category = "Backdoor",
                Severity = "High",
                StringPatterns = new List<string> { "/api/v1/telemetry/upload", "cmd.exe /c", "/bin/sh -i" },
                RegexPatterns = new List<string> { @"adb\s+shell\s+cat\s+/data/misc/adb/adb_keys" }
            });

            // 3. Dangerous ELF stubs
            rules.Add(new YaraRuleDefinition
            {
                Name = "ELF_Dangerous_Stubs",
                Category = "Exploit",
                Severity = "High",
                StringPatterns = new List<string> { "setuid(0)", "chown root:root" },
                ByteSequences = new List<byte[]>
                {
                    new byte[] { 0x7F, 0x45, 0x4C, 0x46, 0x01, 0x01, 0x01, 0x00 } // ELF header
                }
            });

            // 4. Exploits
            rules.Add(new YaraRuleDefinition
            {
                Name = "Known_Exploits",
                Category = "Exploit",
                Severity = "Critical",
                StringPatterns = new List<string> { "dirtycow", "checkm8", "MTK_DA_BYPASS" }
            });
        }
        catch (Exception ex)
        {
            // Fail-open
            Console.WriteLine($"[KnownThreatSignatures] Error initializing signatures: {ex.Message}");
        }

        return rules.AsReadOnly();
    }
}
