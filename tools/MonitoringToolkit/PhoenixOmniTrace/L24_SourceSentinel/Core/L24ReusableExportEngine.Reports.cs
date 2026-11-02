using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using PhoenixOmniTrace.L24_SourceSentinel.Models;

namespace PhoenixOmniTrace.L24_SourceSentinel.Core;

public static partial class L24ReusableExportEngine
{
    private static void WriteForensicReport(string filePath, L24CommandGroup group, List<SourceTelemetryEvent> items, bool isExecuted)
    {
        var sb = new StringBuilder();
        string typeLabel = isExecuted ? "الأوامر الفعلية المنفذة للجهاز" : "أوامر الهاتف الصافية للتجربة المباشرة";
        sb.AppendLine("================================================================================");
        sb.AppendLine(" PhoenixGSM Layer 24 - Forensic Trace Report");
        sb.AppendLine($" الفئة: {L24CommandClassifier.GetGroupArabicTitle(group)}");
        sb.AppendLine($" النوع: {typeLabel} | إجمالي السجلات: {items.Count}");
        sb.AppendLine($" تاريخ التوليد: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine("================================================================================");
        sb.AppendLine();

        for (int i = 0; i < items.Count; i++)
        {
            var ev = items[i];
            sb.AppendLine($"[#{i + 1:D4}] [{ev.TimeFormatted}] [PID: {ev.ProcessId}] [Stage: {ev.StageBadge}]");
            sb.AppendLine($"  الأمر الصافي   : {ev.PureCommandText}");
            sb.AppendLine($"  التصنيف والوصف: {ev.CommandCategory} - {ev.DecodedCommandText}");
            sb.AppendLine($"  المصدر / الدالة : {ev.CallerModuleOrigin} -> {ev.HookedApiName}");
            sb.AppendLine($"  الهدف / المنفذ : {ev.TargetResource}");
            if (!string.IsNullOrWhiteSpace(ev.RawPayloadHex))
                sb.AppendLine($"  البيانات الخام  : {ev.RawPayloadHex}");
            if (!string.IsNullOrWhiteSpace(ev.SavedFilePath))
                sb.AppendLine($"  الملف المحفوظ : {ev.SavedFilePath}");
            sb.AppendLine(new string('-', 75));
        }

        File.WriteAllText(filePath, sb.ToString(), Encoding.UTF8);
    }

    private static void WriteRootIndexAndInstructions(
        string targetDir,
        string sessionName,
        List<SourceTelemetryEvent> allItems,
        bool isExecuted,
        ExportResult result)
    {
        string readmePath = Path.Combine(targetDir, "00_README_INSTRUCTIONS.txt");
        var sb = new StringBuilder();
        sb.AppendLine("================================================================================");
        sb.AppendLine("         PhoenixGSM - Layer 24 (Source Sentinel) Export Package         ");
        sb.AppendLine("================================================================================");
        sb.AppendLine($"اسم الجلسة      : {sessionName}");
        sb.AppendLine($"نوع التصدير     : {(isExecuted ? "الأوامر الفعلية المنفذة للجهاز (Executed Commands)" : "أوامر الهاتف الصافية للتجربة والاختبار (Pure Testable Commands)")}");
        sb.AppendLine($"تاريخ ووقت التصدير: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"إجمالي الأوامر   : {allItems.Count}");
        sb.AppendLine($"عدد الفئات المصدرة: {result.ExportedProtocolsCount}");
        sb.AppendLine("--------------------------------------------------------------------------------");
        sb.AppendLine();
        sb.AppendLine("دليل المجلدات والملفات المنظمة القابلة لإعادة الاستخدام:");
        sb.AppendLine();

        foreach (var kvp in result.ProtocolCounts)
        {
            if (Enum.TryParse<L24CommandGroup>(kvp.Key, out var grp))
            {
                string folder = GetProtocolFolderName(grp);
                string arabic = L24CommandClassifier.GetGroupArabicTitle(grp);
                sb.AppendLine($"📁 [{folder}] -> {arabic} ({kvp.Value} أمر)");
            }
        }

        sb.AppendLine();
        sb.AppendLine("================================================================================");
        sb.AppendLine("كيفية إعادة استخدام الأوامر المصدرة فوراً:");
        sb.AppendLine("================================================================================");
        sb.AppendLine("1. أوامر ADB و Fastboot:");
        sb.AppendLine("   - شغل ملف [01_Run_ADB_Commands.bat] لتنفيذ الأوامر تلقائياً على الهاتف المتصل.");
        sb.AppendLine("   - أو افتح [commands_clean.txt] وانسخ أي أمر لتنفيذه في موجه الأوامر (CMD).");
        sb.AppendLine();
        sb.AppendLine("2. أوامر المودم (AT Commands):");
        sb.AppendLine("   - شغل سكريبت [01_Replay_AT_Serial.py] عبر بايثون: python 01_Replay_AT_Serial.py COM_PORT");
        sb.AppendLine("   - سيقوم السكريبت بإرسال أوامر الـ AT بالترتيب، وقراءة رد الهاتف، وتسجيل النتائج.");
        sb.AppendLine("   - أو استخدم [commands_clean.txt] في أي أداة طرفية (PuTTY, RealTerm, Hercules).");
        sb.AppendLine();
        sb.AppendLine("3. أوامر كوالكوم (Qualcomm EDL / Firehose):");
        sb.AppendLine("   - ستجد حزم الـ XML منظمة وجاهزة في [01_Firehose_Payloads.xml].");
        sb.AppendLine("   - وسكريبت إرسال الحزم إلى منفذ 9008 في [02_Replay_Qualcomm_Port.py].");
        sb.AppendLine();
        sb.AppendLine("4. التكامل البرمجي:");
        sb.AppendLine("   - ملف [commands_structured.json] في كل مجلد يحتوي على هيكل JSON دقيق وسهل الاستيراد.");
        sb.AppendLine("   - ملف [ALL_CLEAN_COMMANDS.txt] بالجذر يضم كافة الأوامر مجمعة بالترتيب الزمني الصافي.");
        sb.AppendLine("================================================================================");

        File.WriteAllText(readmePath, sb.ToString(), Encoding.UTF8);
        result.CreatedFiles.Add(readmePath);
    }

    private static void WriteConsolidatedCleanCommands(
        string targetDir,
        List<SourceTelemetryEvent> allItems,
        ExportResult result)
    {
        // 1. جميع الأوامر الصافية بالترتيب الزمني
        string allCleanPath = Path.Combine(targetDir, "ALL_CLEAN_COMMANDS.txt");
        var allLines = allItems.Select(e => e.PureCommandText.Trim()).Where(s => !string.IsNullOrEmpty(s));
        File.WriteAllLines(allCleanPath, allLines, Encoding.UTF8);
        result.CreatedFiles.Add(allCleanPath);

        // 2. جميع الأوامر الصافية بدون تكرار
        string allUniquePath = Path.Combine(targetDir, "ALL_CLEAN_UNIQUE_COMMANDS.txt");
        File.WriteAllLines(allUniquePath, allLines.Distinct(StringComparer.OrdinalIgnoreCase), Encoding.UTF8);
        result.CreatedFiles.Add(allUniquePath);

        // 3. ملف JSON شامل لكافة الأحداث
        string allJsonPath = Path.Combine(targetDir, "ALL_COMMANDS_COMPLETE.json");
        var options = new JsonSerializerOptions
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            WriteIndented = true
        };
        var structuredList = allItems.Select((e, idx) => new
        {
            GlobalIndex = idx + 1,
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
            e.PayloadSize
        });
        File.WriteAllText(allJsonPath, JsonSerializer.Serialize(structuredList, options), Encoding.UTF8);
        result.CreatedFiles.Add(allJsonPath);
    }
}
