using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Text;
using PhoenixOmniTrace.L24_SourceSentinel.Models;

namespace PhoenixOmniTrace.L24_SourceSentinel.Core;

public sealed class DllFunctionTableAuditor
{
    private readonly ConcurrentDictionary<string, bool> _auditedFiles = new(StringComparer.OrdinalIgnoreCase);
    public event Action<SourceTelemetryEvent>? OnDllCapabilitiesExtracted;

    // قائمة استثناء مكتبات الواجهة والنظام القياسية لتنظيف JSON من الضوضاء
    private static readonly HashSet<string> ExcludedNoiseModules = new(StringComparer.OrdinalIgnoreCase)
    {
        // Qt Framework
        "Qt5Core.dll", "Qt5Gui.dll", "Qt5Widgets.dll", "Qt5Network.dll", "Qt5Svg.dll", "Qt5WinExtras.dll",
        // MSVC Runtimes
        "MSVCR100.dll", "MSVCP100.dll", "MSVCR120.dll", "MSVCP120.dll",
        "vcruntime140.dll", "vcruntime140_1.dll", "msvcp140.dll", "ucrtbase.dll", "msvcrt.dll",
        // MinGW / GCC Runtimes
        "libstdc++-6.dll", "libgcc_s_dw2-1.dll", "libgcc_s_seh-1.dll", "libwinpthread-1.dll",
        // Windows Security / AMSI
        "MpOav.dll", "amsi.dll", "wldp.dll"
    };

    public void AuditLoadedModule(int pid, string processName, string dllPath)
    {
        if (string.IsNullOrWhiteSpace(dllPath) || !File.Exists(dllPath)) return;

        // استبعاد مكتبات الضوضاء فوراً قبل أي قراءة للملف
        string moduleFileName = Path.GetFileName(dllPath);
        if (ExcludedNoiseModules.Contains(moduleFileName)) return;

        // فحص المكتبات غير القياسية فقط (أو مكتبات الاتصال بالهاتف)
        if (dllPath.StartsWith(@"C:\Windows\", StringComparison.OrdinalIgnoreCase)) return;
        if (dllPath.Contains("libcef.dll", StringComparison.OrdinalIgnoreCase) ||
            dllPath.Contains("gdiplus", StringComparison.OrdinalIgnoreCase)) return;

        if (!_auditedFiles.TryAdd(dllPath, true)) return;

        try
        {
            var interestingExports = ExtractExportedFunctionNames(dllPath);
            if (interestingExports.Count > 0)
            {
                string preview = string.Join(" | ", interestingExports.GetRange(0, Math.Min(12, interestingExports.Count)));
                string fileName = Path.GetFileName(dllPath);

                OnDllCapabilitiesExtracted?.Invoke(new SourceTelemetryEvent
                {
                    ProcessId = pid,
                    ThreadId = 0,
                    Stage = SentinelStage.PortConfiguration,
                    HookedApiName = "PE_ExportTableAuditor",
                    CallerModuleOrigin = fileName,
                    TargetResource = dllPath,
                    CommandCategory = "Module Command Functions",
                    DecodedCommandText = $"الدوال المتاحة للتنفيذ داخل [{fileName}] (إجمالي {interestingExports.Count} دالة): {preview}",
                    RawPayloadHex = Convert.ToHexString(Encoding.UTF8.GetBytes(preview)),
                    PayloadSize = interestingExports.Count
                });
            }
        }
        catch { /* تجاهل الملفات المحمية أو غير القياسية */ }
    }

    private static List<string> ExtractExportedFunctionNames(string filePath)
    {
        var results = new List<string>();
        byte[] data = File.ReadAllBytes(filePath);
        if (data.Length < 512) return results;

        // استخراج أسماء الدوال البرمجية الواضحة الخاصة بالمودم، المنافذ، USB، و ADB من جدول الرموز
        string content = Encoding.ASCII.GetString(data);
        string[] keywords = { "QLIB_", "QPHONEMS_", "Adb", "Serial", "Port", "Usb", "Write", "Read", "Send", "Diag", "Nv", "Efs", "Flash", "Sparse", "Brom", "Edl" };

        foreach (var kw in keywords)
        {
            int idx = 0;
            while ((idx = content.IndexOf(kw, idx, StringComparison.OrdinalIgnoreCase)) != -1 && results.Count < 40)
            {
                int start = idx;
                while (start > 0 && IsIdentifierChar(content[start - 1])) start--;

                int end = idx;
                while (end < content.Length && IsIdentifierChar(content[end])) end++;

                int len = end - start;
                if (len >= 5 && len <= 64)
                {
                    string fn = content.Substring(start, len);
                    if (!results.Contains(fn))
                        results.Add(fn);
                }
                idx = end + 1;
            }
        }
        return results;
    }

    private static bool IsIdentifierChar(char c) =>
        (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '@';
}
