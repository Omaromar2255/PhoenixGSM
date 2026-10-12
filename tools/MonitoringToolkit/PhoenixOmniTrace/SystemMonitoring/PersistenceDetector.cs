using System;
using System.Collections.Generic;

namespace PhoenixGSM.OmniTrace.SystemMonitoring;

public class PersistenceFinding
{
    public string Technique { get; set; } = string.Empty;
    public string Details { get; set; } = string.Empty;
}

public class PersistenceDetector : IDisposable
{
    /// <summary>
    /// تقييم الثبات / Evaluate persistence techniques
    /// </summary>
    public List<PersistenceFinding> Evaluate(RegistryDiff regDiff, FileSystemDiff fsDiff)
    {
        var findings = new List<PersistenceFinding>();
        try
        {
            // 1. Startup Run key addition
            foreach (var key in regDiff.AddedRunKeys)
            {
                findings.Add(new PersistenceFinding
                {
                    Technique = "Startup_Run_Key",
                    Details = $"New startup item added: {key}"
                });
            }

            // 2. Modified Filters
            if (regDiff.FiltersModified)
            {
                findings.Add(new PersistenceFinding
                {
                    Technique = "Driver_Filter_Modification",
                    Details = "USB Upper/Lower filters were modified."
                });
            }

            // 3. Driver installation (FileSystem)
            foreach (var file in fsDiff.AddedFiles)
            {
                if (file.EndsWith(".sys", StringComparison.OrdinalIgnoreCase) && 
                    file.Contains(@"System32\drivers", StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(new PersistenceFinding
                    {
                        Technique = "Driver_Installation",
                        Details = $"New driver installed: {file}"
                    });
                }
            }
        }
        catch (Exception ex)
        {
            // Fail-open
            Console.WriteLine($"[PersistenceDetector] Evaluate Error: {ex.Message}");
        }
        return findings;
    }

    public void Dispose()
    {
        // Cleanup
    }
}
