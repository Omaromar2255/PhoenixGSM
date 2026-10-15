using System;
using System.Collections.Generic;
using System.Runtime.Versioning;
using Microsoft.Win32;

namespace PhoenixGSM.OmniTrace.SystemMonitoring;

public class RegistrySnapshot
{
    public Dictionary<string, string> RunKeys { get; set; } = new();
    public Dictionary<string, string> Services { get; set; } = new();
    public Dictionary<string, string> IfeoKeys { get; set; } = new();
    public string UpperFilters { get; set; } = string.Empty;
    public string LowerFilters { get; set; } = string.Empty;
}

public class RegistryDiff
{
    public List<string> AddedRunKeys { get; set; } = new();
    public List<string> ModifiedServices { get; set; } = new();
    public bool FiltersModified { get; set; }
}

[SupportedOSPlatform("windows")]
public class RegistrySnapshotDiff : IDisposable
{
    /// <summary>
    /// أخذ لقطة للريجستري / Take registry snapshot
    /// </summary>
    public RegistrySnapshot TakeSnapshot()
    {
        var snapshot = new RegistrySnapshot();
        try
        {
            // Run keys
            using var runKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run");
            if (runKey != null)
            {
                foreach (var name in runKey.GetValueNames())
                {
                    snapshot.RunKeys[name] = runKey.GetValue(name)?.ToString() ?? "";
                }
            }

            // Drivers filters (USB)
            using var usbKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Class\{36fc9e60-c465-11cf-8056-444553540000}");
            if (usbKey != null)
            {
                snapshot.UpperFilters = string.Join(",", (string[])usbKey.GetValue("UpperFilters", Array.Empty<string>()));
                snapshot.LowerFilters = string.Join(",", (string[])usbKey.GetValue("LowerFilters", Array.Empty<string>()));
            }
        }
        catch (Exception ex)
        {
            // Fail-open
            Console.WriteLine($"[RegistrySnapshotDiff] TakeSnapshot Error: {ex.Message}");
        }
        return snapshot;
    }

    /// <summary>
    /// مقارنة لقطتين / Compare snapshots
    /// </summary>
    public RegistryDiff CompareSnapshots(RegistrySnapshot before, RegistrySnapshot after)
    {
        var diff = new RegistryDiff();
        try
        {
            foreach (var kvp in after.RunKeys)
            {
                if (!before.RunKeys.ContainsKey(kvp.Key) || before.RunKeys[kvp.Key] != kvp.Value)
                {
                    diff.AddedRunKeys.Add(kvp.Key);
                }
            }

            if (before.UpperFilters != after.UpperFilters || before.LowerFilters != after.LowerFilters)
            {
                diff.FiltersModified = true;
            }
        }
        catch (Exception ex)
        {
            // Fail-open
            Console.WriteLine($"[RegistrySnapshotDiff] CompareSnapshots Error: {ex.Message}");
        }
        return diff;
    }

    public void Dispose()
    {
        // Cleanup
    }
}
