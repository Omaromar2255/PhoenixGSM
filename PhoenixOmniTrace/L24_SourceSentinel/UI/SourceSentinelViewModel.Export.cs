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

    public void ExecuteExportExecutedCommandsSeparately()
    {
        var items = ExecutedDeviceEvents.ToList();
        var result = L24ReusableExportEngine.ExportSeparatedByProtocol(
            _orchestrator.LogDirectory,
            "الأوامر الفعلية المنفذة للجهاز",
            items,
            isExecutedCommands: true);

        if (result.Success)
        {
            StatusMessage = $"تم تصدير {result.TotalCommandsCount} أمر منفذ عبر {result.ExportedProtocolsCount} فئات بنجاح إلى: {result.ExportDirectory}";
            var dlgRes = MessageBox.Show(
                $"تم تصدير الأوامر الفعلية المنفذة للجهاز بنجاح:\n\n" +
                $"• إجمالي الأوامر المنفذة: {result.TotalCommandsCount}\n" +
                $"• عدد الفئات المنفصلة: {result.ExportedProtocolsCount}\n" +
                $"• المجلد:\n{result.ExportDirectory}\n\n" +
                $"تتضمن الحزمة سكريبتات تشغيل تلقائي (Batch / Python) وقوائم نقية بدون شوائب وملفات JSON مهيكلة.\n\n" +
                $"هل تريد فتح مجلد التصدير الآن؟",
                "تصدير الأوامر المنفذة للهاتف (منظمة وقابلة لإعادة الاستخدام)",
                MessageBoxButton.YesNo,
                MessageBoxImage.Information);

            if (dlgRes == MessageBoxResult.Yes)
                OpenDirectoryInExplorer(result.ExportDirectory);
        }
        else
        {
            MessageBox.Show(result.ErrorMessage, "تنبيه التصدير", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    public void ExecuteExportCurrentExecutedCategory()
    {
        if (_executedCategoryFilter == "All")
        {
            ExecuteExportExecutedCommandsSeparately();
            return;
        }

        var visibleItems = FilteredExecutedEvents.Cast<SourceTelemetryEvent>().ToList();
        if (visibleItems.Count == 0)
        {
            MessageBox.Show("لا توجد أوامر مسجلة في الفئة المحددة حالياً.", "تنبيه", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (Enum.TryParse<L24CommandGroup>(_executedCategoryFilter, out var grp))
        {
            var result = L24ReusableExportEngine.ExportSingleCategory(
                _orchestrator.LogDirectory,
                "الأوامر المنفذة",
                grp,
                visibleItems,
                isExecutedCommands: true);

            if (result.Success)
            {
                StatusMessage = $"تم تصدير فئة [{L24CommandClassifier.GetGroupArabicTitle(grp)}] ({result.TotalCommandsCount} أمر) إلى: {result.ExportDirectory}";
                var dlgRes = MessageBox.Show(
                    $"تم تصدير أوامر فئة [{L24CommandClassifier.GetGroupArabicTitle(grp)}] بنجاح ({result.TotalCommandsCount} أمر).\n\nالمجلد:\n{result.ExportDirectory}\n\nهل تريد فتح المجلد؟",
                    "تصدير الفئة المنفذة المحددة",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Information);

                if (dlgRes == MessageBoxResult.Yes)
                    OpenDirectoryInExplorer(result.ExportDirectory);
            }
            else
            {
                MessageBox.Show(result.ErrorMessage, "خطأ", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    public void ExecuteCopyExecutedCommandsToClipboard()
    {
        try
        {
            var visibleItems = FilteredExecutedEvents.Cast<SourceTelemetryEvent>().ToList();
            if (visibleItems.Count == 0)
            {
                StatusMessage = "لا توجد أوامر معروضة لنسخها.";
                return;
            }

            string text = L24ReusableExportEngine.FormatCleanCommandsForClipboard(visibleItems);
            if (!string.IsNullOrWhiteSpace(text))
            {
                Clipboard.SetDataObject(text, true);
                StatusMessage = $"تم نسخ {visibleItems.Count} أمر منفذ نقي للحافظة جاهزة للاستخدام الفوري بنجاح.";
            }
        }
        catch (Exception ex)
        {
            StatusMessage = $"تعذر النسخ للحافظة: {ex.Message}";
        }
    }

    public void ExecuteExportPureTestCommandsSeparately()
    {
        var items = PurePhoneTestableEvents.ToList();
        var result = L24ReusableExportEngine.ExportSeparatedByProtocol(
            _orchestrator.LogDirectory,
            "أوامر الهاتف الصافية للتجربة والاختبار المباشر",
            items,
            isExecutedCommands: false);

        if (result.Success)
        {
            StatusMessage = $"تم تصدير {result.TotalCommandsCount} أمر تجربة عبر {result.ExportedProtocolsCount} فئات بنجاح إلى: {result.ExportDirectory}";
            var dlgRes = MessageBox.Show(
                $"تم تصدير أوامر الهاتف الصافية للتجربة بنجاح:\n\n" +
                $"• إجمالي أوامر التجربة: {result.TotalCommandsCount}\n" +
                $"• عدد الفئات المنفصلة: {result.ExportedProtocolsCount}\n" +
                $"• المجلد:\n{result.ExportDirectory}\n\n" +
                $"تتضمن الحزمة سكريبتات تشغيل تلقائي (Batch / Python) وقوائم نقية بدون شوائب وملفات JSON مهيكلة.\n\n" +
                $"هل تريد فتح مجلد التصدير الآن؟",
                "تصدير أوامر الهاتف للتجربة (منظمة وقابلة لإعادة الاستخدام)",
                MessageBoxButton.YesNo,
                MessageBoxImage.Information);

            if (dlgRes == MessageBoxResult.Yes)
                OpenDirectoryInExplorer(result.ExportDirectory);
        }
        else
        {
            MessageBox.Show(result.ErrorMessage, "تنبيه التصدير", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    public void ExecuteExportCurrentPureTestCategory()
    {
        if (_pureCategoryFilter == "All")
        {
            ExecuteExportPureTestCommandsSeparately();
            return;
        }

        var visibleItems = FilteredPurePhoneEvents.Cast<SourceTelemetryEvent>().ToList();
        if (visibleItems.Count == 0)
        {
            MessageBox.Show("لا توجد أوامر تجربة في الفئة المحددة حالياً.", "تنبيه", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (Enum.TryParse<L24CommandGroup>(_pureCategoryFilter, out var grp))
        {
            var result = L24ReusableExportEngine.ExportSingleCategory(
                _orchestrator.LogDirectory,
                "أوامر التجربة",
                grp,
                visibleItems,
                isExecutedCommands: false);

            if (result.Success)
            {
                StatusMessage = $"تم تصدير أوامر تجربة فئة [{L24CommandClassifier.GetGroupArabicTitle(grp)}] ({result.TotalCommandsCount} أمر) إلى: {result.ExportDirectory}";
                var dlgRes = MessageBox.Show(
                    $"تم تصدير أوامر تجربة فئة [{L24CommandClassifier.GetGroupArabicTitle(grp)}] بنجاح ({result.TotalCommandsCount} أمر).\n\nالمجلد:\n{result.ExportDirectory}\n\nهل تريد فتح المجلد؟",
                    "تصدير فئة أوامر التجربة المحددة",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Information);

                if (dlgRes == MessageBoxResult.Yes)
                    OpenDirectoryInExplorer(result.ExportDirectory);
            }
            else
            {
                MessageBox.Show(result.ErrorMessage, "خطأ", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    public void ExecuteCopyPureTestCommandsToClipboard()
    {
        try
        {
            var visibleItems = FilteredPurePhoneEvents.Cast<SourceTelemetryEvent>().ToList();
            if (visibleItems.Count == 0)
            {
                StatusMessage = "لا توجد أوامر تجربة معروضة لنسخها.";
                return;
            }

            string text = L24ReusableExportEngine.FormatCleanCommandsForClipboard(visibleItems);
            if (!string.IsNullOrWhiteSpace(text))
            {
                Clipboard.SetDataObject(text, true);
                StatusMessage = $"تم نسخ {visibleItems.Count} أمر تجربة صافٍ للحافظة جاهزة للتجربة المباشرة بنجاح.";
            }
        }
        catch (Exception ex)
        {
            StatusMessage = $"تعذر النسخ للحافظة: {ex.Message}";
        }
    }

    private void ExecuteExportPurePhoneCommands()
    {
        ExecuteExportPureTestCommandsSeparately();
    }

    private static void OpenDirectoryInExplorer(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = path,
                    UseShellExecute = true
                });
            }
        }
        catch { }
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
