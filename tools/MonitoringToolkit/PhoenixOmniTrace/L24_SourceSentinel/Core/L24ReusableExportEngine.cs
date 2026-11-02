using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using PhoenixOmniTrace.L24_SourceSentinel.Models;

namespace PhoenixOmniTrace.L24_SourceSentinel.Core;

/// <summary>
/// محرك التصدير المنظم للأوامر المنفذة وأوامر الاختبار
/// يولد سكريبتات تنفيذية (Batch/Bash/Python) وقوائم نقية وملفات مهيكلة مقسمة كل نوع بشكل مستقل
/// </summary>
public static partial class L24ReusableExportEngine
{
    public sealed class ExportResult
    {
        public bool Success { get; set; }
        public string ExportDirectory { get; set; } = string.Empty;
        public int TotalCommandsCount { get; set; }
        public int ExportedProtocolsCount { get; set; }
        public List<string> CreatedFiles { get; } = [];
        public Dictionary<string, int> ProtocolCounts { get; } = [];
        public string ErrorMessage { get; set; } = string.Empty;
    }

    /// <summary>
    /// تصدير الأوامر مقسمة كل بروتوكول وفئة في مجلد وملفات مستقلة مع سكريبتات إعادة تشغيل
    /// </summary>
    public static ExportResult ExportSeparatedByProtocol(
        string baseDirectory,
        string sessionName,
        IEnumerable<SourceTelemetryEvent> events,
        bool isExecutedCommands)
    {
        var result = new ExportResult();
        try
        {
            var rawList = events.Where(e => !string.IsNullOrWhiteSpace(e.PureCommandText)).ToList();
            if (rawList.Count == 0)
            {
                result.Success = false;
                result.ErrorMessage = "لا توجد أوامر مسجلة للتصدير في هذه الفئة.";
                return result;
            }

            string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            string prefix = isExecutedCommands ? "L24_Export_Executed" : "L24_Export_PureTest";
            string targetDir = Path.Combine(baseDirectory, $"{prefix}_{timestamp}");
            Directory.CreateDirectory(targetDir);
            result.ExportDirectory = targetDir;
            result.TotalCommandsCount = rawList.Count;

            // تجميع الأوامر حسب الفئة / البروتوكول
            var grouped = rawList.GroupBy(e => e.CommandGroup).OrderBy(g => (int)g.Key).ToList();

            foreach (var group in grouped)
            {
                var groupItems = group.ToList();
                if (groupItems.Count == 0) continue;

                string folderName = GetProtocolFolderName(group.Key);
                string groupDir = Path.Combine(targetDir, folderName);
                Directory.CreateDirectory(groupDir);

                ExportProtocolArtifacts(groupDir, group.Key, groupItems, isExecutedCommands, result);
                result.ExportedProtocolsCount++;
                result.ProtocolCounts[group.Key.ToString()] = groupItems.Count;
            }

            // توليد الملفات الشاملة في الجذر
            WriteRootIndexAndInstructions(targetDir, sessionName, rawList, isExecutedCommands, result);
            WriteConsolidatedCleanCommands(targetDir, rawList, result);

            result.Success = true;
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.ErrorMessage = ex.Message;
        }

        return result;
    }

    /// <summary>
    /// تصدير فئة واحدة محددة بتنسيقات قابلة لإعادة الاستخدام
    /// </summary>
    public static ExportResult ExportSingleCategory(
        string baseDirectory,
        string sessionName,
        L24CommandGroup group,
        IEnumerable<SourceTelemetryEvent> events,
        bool isExecutedCommands)
    {
        var result = new ExportResult();
        try
        {
            var rawList = events.Where(e => !string.IsNullOrWhiteSpace(e.PureCommandText)).ToList();
            if (rawList.Count == 0)
            {
                result.Success = false;
                result.ErrorMessage = "لا توجد أوامر مسجلة في الفئة المحددة للتصدير.";
                return result;
            }

            string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            string slug = L24CommandClassifier.GetGroupShortSlug(group);
            string prefix = isExecutedCommands ? "L24_Executed" : "L24_PureTest";
            string targetDir = Path.Combine(baseDirectory, $"{prefix}_{slug}_{timestamp}");
            Directory.CreateDirectory(targetDir);
            result.ExportDirectory = targetDir;
            result.TotalCommandsCount = rawList.Count;

            ExportProtocolArtifacts(targetDir, group, rawList, isExecutedCommands, result);
            WriteRootIndexAndInstructions(targetDir, $"{sessionName} - {L24CommandClassifier.GetGroupArabicTitle(group)}", rawList, isExecutedCommands, result);

            result.ExportedProtocolsCount = 1;
            result.ProtocolCounts[group.ToString()] = rawList.Count;
            result.Success = true;
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.ErrorMessage = ex.Message;
        }

        return result;
    }

    /// <summary>
    /// توليد نص نقي للأوامر جاهز للنسخ للحافظة
    /// </summary>
    public static string FormatCleanCommandsForClipboard(IEnumerable<SourceTelemetryEvent> events, bool deduplicate = false)
    {
        var query = events
            .Select(e => e.PureCommandText?.Trim())
            .Where(s => !string.IsNullOrWhiteSpace(s))!;

        if (deduplicate)
            query = query.Distinct(StringComparer.OrdinalIgnoreCase);

        return string.Join(Environment.NewLine, query);
    }

    private static string GetProtocolFolderName(L24CommandGroup group) => group switch
    {
        L24CommandGroup.ModemAt => "01_Modem_AT_Commands",
        L24CommandGroup.AdbFastboot => "02_ADB_and_Fastboot",
        L24CommandGroup.Qualcomm => "03_Qualcomm_EDL_Firehose",
        L24CommandGroup.MediaTek => "04_MediaTek_BROM_DA",
        L24CommandGroup.AppleIos => "05_Apple_iOS_DFU",
        L24CommandGroup.CryptoAuth => "06_Crypto_Keys_Auth",
        L24CommandGroup.FileTransfer => "07_File_Transfers_BootLoaders",
        L24CommandGroup.ArchiveUnpack => "08_Archive_Unpack",
        L24CommandGroup.ServerCloudLogin => "09_Server_URLs_Auth",
        _ => "10_Other_Phone_Commands"
    };

    private static void ExportProtocolArtifacts(
        string targetDir,
        L24CommandGroup group,
        List<SourceTelemetryEvent> items,
        bool isExecuted,
        ExportResult result)
    {
        // 1. ملف الأوامر النقية سطر بسطر (بدون أي علامات أو بيانات وصفية)
        string cleanTxtPath = Path.Combine(targetDir, "commands_clean.txt");
        var cleanLines = items.Select(e => e.PureCommandText.Trim()).Where(s => !string.IsNullOrEmpty(s));
        File.WriteAllLines(cleanTxtPath, cleanLines, Encoding.UTF8);
        result.CreatedFiles.Add(cleanTxtPath);

        // 2. ملف الأوامر الفريدة بدون تكرار
        string uniqueTxtPath = Path.Combine(targetDir, "commands_unique.txt");
        var uniqueLines = cleanLines.Distinct(StringComparer.OrdinalIgnoreCase);
        File.WriteAllLines(uniqueTxtPath, uniqueLines, Encoding.UTF8);
        result.CreatedFiles.Add(uniqueTxtPath);

        // 3. ملف JSON مهيكل متكامل
        string jsonPath = Path.Combine(targetDir, "commands_structured.json");
        var options = new JsonSerializerOptions
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            WriteIndented = true
        };
        var structuredList = items.Select((e, idx) => new
        {
            SequenceIndex = idx + 1,
            e.FormattedTimestamp,
            e.ProcessId,
            Scope = e.Scope.ToString(),
            Group = e.CommandGroup.ToString(),
            GroupTitle = e.CommandGroupBadge,
            e.CommandCategory,
            e.PureCommandText,
            e.DecodedCommandText,
            e.TargetResource,
            e.CallerModuleOrigin,
            e.HookedApiName,
            e.RawPayloadHex,
            e.PayloadSize,
            e.SavedFilePath
        });
        File.WriteAllText(jsonPath, JsonSerializer.Serialize(structuredList, options), Encoding.UTF8);
        result.CreatedFiles.Add(jsonPath);

        // 4. تقرير تحليلي مفصل
        string detailsTxtPath = Path.Combine(targetDir, "forensic_details.txt");
        WriteForensicReport(detailsTxtPath, group, items, isExecuted);
        result.CreatedFiles.Add(detailsTxtPath);

        // 5. سكريبتات إعادة التشغيل المتخصصة حسب نوع البروتوكول
        switch (group)
        {
            case L24CommandGroup.AdbFastboot:
                GenerateAdbReplayScripts(targetDir, items, result);
                break;

            case L24CommandGroup.ModemAt:
                GenerateAtReplayScript(targetDir, items, result);
                break;

            case L24CommandGroup.Qualcomm:
                GenerateQualcommArtifacts(targetDir, items, result);
                break;

            case L24CommandGroup.AppleIos:
                GenerateAppleReplayScripts(targetDir, items, result);
                break;

            case L24CommandGroup.MediaTek:
                GenerateMediaTekArtifacts(targetDir, items, result);
                break;
        }
    }
}
