using System;
using System.Collections.Generic;
using System.Linq;

namespace PhoenixGSM.OmniTrace.DeviceStateDiff;

public class DarkChannelReport
{
    public bool HasDarkChannelActivity { get; set; }
    public List<string> UnexplainedChanges { get; set; } = new();
    public string ReportSummary { get; set; } = string.Empty;
}

public class DarkChannelDetector : IDisposable
{
    // تحليل الفروقات واكتشاف قنوات غير مسجلة (العمليات غير المراقبة)
    public DarkChannelReport AnalyzeDiscrepancies(DeviceStateSnapshot before, DeviceStateSnapshot after, IEnumerable<string> capturedCommandSummaries)
    {
        var report = new DarkChannelReport();
        var captured = capturedCommandSummaries.ToList();

        try
        {
            // 1. Packages
            var newPackages = after.InstalledPackages.Except(before.InstalledPackages).ToList();
            foreach (var pkg in newPackages)
            {
                if (!IsChangeExplained(captured, "install", pkg))
                {
                    report.UnexplainedChanges.Add($"Package installed via Dark Channel: {pkg}");
                    report.HasDarkChannelActivity = true;
                }
            }

            var removedPackages = before.InstalledPackages.Except(after.InstalledPackages).ToList();
            foreach (var pkg in removedPackages)
            {
                if (!IsChangeExplained(captured, "uninstall", pkg))
                {
                    report.UnexplainedChanges.Add($"Package uninstalled via Dark Channel: {pkg}");
                    report.HasDarkChannelActivity = true;
                }
            }

            // 2. Settings Secure
            foreach (var kvp in after.SettingsSecure)
            {
                if (!before.SettingsSecure.TryGetValue(kvp.Key, out var beforeVal) || beforeVal != kvp.Value)
                {
                    if (!IsChangeExplained(captured, "settings", kvp.Key))
                    {
                        report.UnexplainedChanges.Add($"Secure setting changed via Dark Channel: {kvp.Key} -> {kvp.Value}");
                        report.HasDarkChannelActivity = true;
                    }
                }
            }

            // 3. Bootloader Status
            if (before.BootloaderStatus != after.BootloaderStatus)
            {
                if (!IsChangeExplained(captured, "oem", "unlock"))
                {
                    report.UnexplainedChanges.Add($"Bootloader status changed via Dark Channel: {after.BootloaderStatus}");
                    report.HasDarkChannelActivity = true;
                }
            }

            // 4. Knox Status
            if (before.KnoxWarrantyVoid != after.KnoxWarrantyVoid)
            {
                report.UnexplainedChanges.Add($"Knox Warranty Void triggered unexpectedly: {after.KnoxWarrantyVoid}");
                report.HasDarkChannelActivity = true;
            }

            report.ReportSummary = report.HasDarkChannelActivity 
                ? $"🔴 Dark Channel Detected! {report.UnexplainedChanges.Count} unexplained changes found." 
                : "🟢 Clean. All state changes correlate to captured commands.";
                
            return report;
        }
        catch (Exception ex)
        {
            // Fail-open: لا توقف النظام
            Console.WriteLine($"[Error] AnalyzeDiscrepancies failed: {ex.Message}");
            return new DarkChannelReport { ReportSummary = "Error during analysis" };
        }
    }

    private bool IsChangeExplained(List<string> capturedSummaries, string keyword1, string keyword2)
    {
        return capturedSummaries.Any(s => 
            s.Contains(keyword1, StringComparison.OrdinalIgnoreCase) && 
            s.Contains(keyword2, StringComparison.OrdinalIgnoreCase));
    }

    public void Dispose()
    {
        // Cleanup if necessary
    }
}
