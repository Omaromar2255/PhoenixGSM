using System;
using System.Collections.Generic;

namespace PhoenixGSM.OmniTrace.ForensicTimeline;

public class MitreTechniqueInfo
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
}

/// <summary>
/// Maps observed behaviors to MITRE ATT&CK framework techniques
/// تعيين السلوكيات الملاحظة إلى تقنيات إطار MITRE ATT&CK
/// </summary>
public class MitreAttMapper : IDisposable
{
    private readonly Dictionary<string, MitreTechniqueInfo> _ruleToTechniqueMap;

    public MitreAttMapper()
    {
        // تهيئة خريطة التقنيات
        // Initialize technique map
        _ruleToTechniqueMap = new Dictionary<string, MitreTechniqueInfo>(StringComparer.OrdinalIgnoreCase)
        {
            { "ADB_Shell_Command", new MitreTechniqueInfo { Id = "T1059", Name = "Command and Scripting Interpreter", Description = "Abuse of interpreters to execute commands, scripts, or binaries." } },
            { "Registry_Run_Key", new MitreTechniqueInfo { Id = "T1547", Name = "Boot or Logon Autostart Execution", Description = "Add registry keys to persist across reboots." } },
            { "Process_Hollowing", new MitreTechniqueInfo { Id = "T1055", Name = "Process Injection", Description = "Injecting code into processes." } },
            { "Data_Exfil", new MitreTechniqueInfo { Id = "T1020", Name = "Automated Exfiltration", Description = "Automated theft of data like contacts or SMS." } },
            { "Account_Manupilation", new MitreTechniqueInfo { Id = "T1098", Name = "Account Manipulation", Description = "Device owner manipulation or su root." } },
            { "C2_Traffic", new MitreTechniqueInfo { Id = "T1071", Name = "Application Layer Protocol", Description = "Communication over HTTP/DNS for C2." } },
            { "High_Entropy_Payload", new MitreTechniqueInfo { Id = "T1027", Name = "Obfuscated Files or Information", Description = "Packed or obfuscated payloads." } },
            { "Sandbox_Evasion", new MitreTechniqueInfo { Id = "T1497", Name = "Virtualization/Sandbox Evasion", Description = "Detecting analysis environments." } }
        };
    }

    public MitreTechniqueInfo? MapThreatCategory(string categoryOrRule)
    {
        try
        {
            if (_ruleToTechniqueMap.TryGetValue(categoryOrRule, out var technique))
            {
                return technique;
            }
            
            // Check substrings
            // فحص السلاسل الفرعية
            foreach (var kvp in _ruleToTechniqueMap)
            {
                if (categoryOrRule.Contains(kvp.Key, StringComparison.OrdinalIgnoreCase))
                {
                    return kvp.Value;
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[MitreMapper] Error mapping category: {ex.Message}");
        }
        
        return null;
    }

    public void Dispose()
    {
        _ruleToTechniqueMap.Clear();
    }
}
