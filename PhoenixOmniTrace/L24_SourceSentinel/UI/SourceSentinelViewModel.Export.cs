using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Windows;
using PhoenixOmniTrace.L24_SourceSentinel.Core;
using PhoenixOmniTrace.L24_SourceSentinel.Models;

namespace PhoenixOmniTrace.L24_SourceSentinel.UI;

public sealed partial class SourceSentinelViewModel
{
    private void ExecuteClearEvents()
    {
        lock (_lockObj)
        {
            ExecutedDeviceEvents.Clear();
            PurePhoneTestableEvents.Clear();
            DiscoveredRamEvents.Clear();
            RadarAndFileEvents.Clear();
            UnfilteredRawEvents.Clear();
            LiveEvents.Clear();
            LoadedArtifacts.Clear();
            SelectedEvent = null;
            SelectedArtifact = null;
            NotifyCounterProperties();
            UpdateDiscoveredCategoryCounters();
        }
        ForensicNoiseGate.ResetSessionDeduplication();
        StatusMessage = "تم تنظيف كافة التبويبات وإعادة ضبط الجلسة.";
    }

    private void ExecuteExportUnfilteredRawLogs()
    {
        try
        {
            var items = UnfilteredRawEvents.ToList();
            string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            string baseFile = Path.Combine(_orchestrator.LogDirectory, $"L24_Unfiltered_Raw_Complete_{timestamp}");

            WriteCategoryExportFiles(baseFile, "السجل الشامل الخام بدون فلترة (Unfiltered Raw Stream - كافة العمليات والروابط وتسجيل الدخول)", items);
            StatusMessage = $"تم تصدير السجل الشامل الخام ({items.Count} عملية) إلى: {baseFile}.txt | ويُحفظ تلقائياً في: {Path.GetFileName(_orchestrator.UnfilteredRawTxtPath)}";
            MessageBox.Show(
                $"تم تصدير السجل الشامل الخام بدون فلترة ({items.Count} عملية) بنجاح:\n\n1. ملف التصدير الفوري:\n{baseFile}.txt\n\n2. ملف التسجيل التلقائي المستمر:\n{_orchestrator.UnfilteredRawTxtPath}",
                "تصدير السجل الشامل الخام (بدون فلترة)",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"تعذر تصدير السجل الخام: {ex.Message}", "خطأ", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void ExecuteExportSelectedDiscoveredCategory()
    {
        try
        {
            var items = FilteredDiscoveredRamEvents.Cast<SourceTelemetryEvent>().ToList();
            string catSlug = _discoveredCategoryFilter == "All" ? "All_Discovered" : _discoveredCategoryFilter;
            string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            string baseFile = Path.Combine(_orchestrator.LogDirectory, $"L24_Discovered_{catSlug}_{timestamp}");

            WriteCategoryExportFiles(baseFile, $"الأوامر المكتشفة في الذاكرة — الفئة: {catSlug}", items);
            StatusMessage = $"تم تصدير الفئة ({catSlug}) بنجاح ({items.Count} أمر) إلى: {baseFile}.txt";
            MessageBox.Show($"تم تصدير أوامر الفئة [{catSlug}] بنجاح ({items.Count} أمر):\n{baseFile}.txt\n{baseFile}.json",
                "تصدير الفئة المحددة", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"تعذر التصدير: {ex.Message}", "خطأ", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void ExecuteExportAllDiscoveredCategoriesSeparately()
    {
        try
        {
            string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            string exportFolder = Path.Combine(_orchestrator.LogDirectory, $"Export_By_Category_{timestamp}");
            Directory.CreateDirectory(exportFolder);

            int exportedFilesCount = 0;

            var executedList = ExecutedDeviceEvents.ToList();
            if (executedList.Count > 0)
            {
                WriteCategoryExportFiles(Path.Combine(exportFolder, "01_Executed_On_Device"), "الأوامر الفعلية المنفذة للجهاز", executedList);
                exportedFilesCount++;
            }

            var pureList = PurePhoneTestableEvents.ToList();
            if (pureList.Count > 0)
            {
                WriteCategoryExportFiles(Path.Combine(exportFolder, "02_Pure_Phone_Testable"), "أوامر الهاتف الصافية للتجربة", pureList);
                exportedFilesCount++;
            }

            var rawList = UnfilteredRawEvents.ToList();
            if (rawList.Count > 0)
            {
                WriteCategoryExportFiles(Path.Combine(exportFolder, "03_Unfiltered_Raw_Everything"), "السجل الشامل الخام بدون فلترة", rawList);
                exportedFilesCount++;
            }

            foreach (L24CommandGroup group in Enum.GetValues<L24CommandGroup>())
            {
                var groupItems = DiscoveredRamEvents.Where(e => e.CommandGroup == group).ToList();
                if (groupItems.Count == 0) continue;

                string slug = L24CommandClassifier.GetGroupShortSlug(group);
                string title = L24CommandClassifier.GetGroupArabicTitle(group);
                WriteCategoryExportFiles(Path.Combine(exportFolder, $"Discovered_{slug}"), title, groupItems);
                exportedFilesCount++;
            }

            StatusMessage = $"تم تصدير {exportedFilesCount} ملفات منفصلة في المجلد: {exportFolder}";
            MessageBox.Show($"تم تصدير كل نوع في ملفات منفصلة بنجاح ({exportedFilesCount} ملفات) داخل المجلد:\n{exportFolder}",
                "تصدير كافة الفئات بشكل منفصل", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"تعذر تصدير الفئات: {ex.Message}", "خطأ", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void ExecuteExportPurePhoneCommands()
    {
        try
        {
            var items = PurePhoneTestableEvents.ToList();
            string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            string baseFile = Path.Combine(_orchestrator.LogDirectory, $"L24_PurePhone_Testable_{timestamp}");

            WriteCategoryExportFiles(baseFile, "أوامر الهاتف الصافية القابلة للتجربة المباشرة", items);
            StatusMessage = $"تم تصدير أوامر الهاتف للتجربة ({items.Count} أمر) إلى: {baseFile}.txt";
            MessageBox.Show($"تم تصدير أوامر الهاتف الصافية للتجربة بنجاح:\n{baseFile}.txt\n{baseFile}.json",
                "تصدير أوامر الهاتف للتجربة", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"تعذر تصدير أوامر الهاتف: {ex.Message}", "خطأ", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private static void WriteCategoryExportFiles(string basePathWithoutExt, string headerTitle, List<SourceTelemetryEvent> items)
    {
        string txtPath = basePathWithoutExt + ".txt";
        string jsonPath = basePathWithoutExt + ".json";

        var sb = new StringBuilder();
        sb.AppendLine($"=== {headerTitle} ===");
        sb.AppendLine($"تاريخ التصدير: {DateTime.Now:yyyy-MM-dd HH:mm:ss} | إجمالي السجلات: {items.Count}");
        sb.AppendLine(new string('=', 80));
        sb.AppendLine();

        sb.AppendLine("--- [أولاً: القائمة الصافية السريعة] ---");
        foreach (var ev in items)
        {
            sb.AppendLine(ev.PureCommandText);
        }
        sb.AppendLine();
        sb.AppendLine(new string('=', 80));
        sb.AppendLine("--- [ثانياً: التفاصيل الجنائية الكاملة لكل حدث] ---");
        sb.AppendLine();

        foreach (var ev in items)
        {
            sb.AppendLine($"[{ev.TimeFormatted}] [PID:{ev.ProcessId}] [{ev.CommandGroupBadge}] ({ev.CommandCategory})");
            sb.AppendLine($"الأمر الصافي : {ev.PureCommandText}");
            sb.AppendLine($"الوصف       : {ev.DecodedCommandText}");
            sb.AppendLine($"الهدف/البورت : {ev.TargetResource} | المصدر: {ev.CallerModuleOrigin}");
            if (!string.IsNullOrWhiteSpace(ev.SavedFilePath))
                sb.AppendLine($"الملف المحفوظ: {ev.SavedFilePath}");
            sb.AppendLine(new string('-', 60));
        }

        File.WriteAllText(txtPath, sb.ToString(), Encoding.UTF8);

        var options = new JsonSerializerOptions
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            WriteIndented = true
        };
        var cleanDtos = items.Select(e => new
        {
            e.FormattedTimestamp,
            e.ProcessId,
            Scope = e.Scope.ToString(),
            Group = e.CommandGroup.ToString(),
            e.CommandCategory,
            e.PureCommandText,
            e.DecodedCommandText,
            e.TargetResource,
            e.SavedFilePath,
            e.CallerModuleOrigin,
            e.HookedApiName,
            e.PayloadSize
        });
        File.WriteAllText(jsonPath, JsonSerializer.Serialize(cleanDtos, options), Encoding.UTF8);
    }

    private void ExecuteExportLogs()
    {
        _orchestrator.FlushAndExportSessionSnapshot();
        ExecuteExportAllDiscoveredCategoriesSeparately();
    }

    private void ExecuteOpenLogsFolder()
    {
        try
        {
            if (Directory.Exists(_orchestrator.LogDirectory))
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = _orchestrator.LogDirectory,
                    UseShellExecute = true
                });
            }
        }
        catch { }
    }

    private void ExecuteOpenCapturedFilesFolder()
    {
        try
        {
            string dir = _orchestrator.CapturedFilesDirectory;
            Directory.CreateDirectory(dir);
            Process.Start(new ProcessStartInfo
            {
                FileName = dir,
                UseShellExecute = true
            });
        }
        catch { }
    }
}
