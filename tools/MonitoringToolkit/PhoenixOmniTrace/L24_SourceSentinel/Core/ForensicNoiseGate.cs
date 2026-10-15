using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using PhoenixOmniTrace.L24_SourceSentinel.Models;

namespace PhoenixOmniTrace.L24_SourceSentinel.Core
{
    /// <summary>
    /// بوابة التصفية الجنائية الموحدة ومنع التكرار وتنظيم المخرجات لجميع الطبقات.
    /// </summary>
    public static class ForensicNoiseGate
    {
        // 1. القائمة السوداء الشاملة لمكتبات النظام والواجهة والتشفير العام التي تسبب ضوضاء في PE_ExportTableAuditor
        public static readonly HashSet<string> ExcludedNoiseModules = new(StringComparer.OrdinalIgnoreCase)
        {
            // Qt Framework & Plugins
            "Qt5Core.dll", "Qt5Gui.dll", "Qt5Widgets.dll", "Qt5Network.dll", "Qt5Svg.dll",
            "Qt5WinExtras.dll", "Qt5Sql.dll", "Qt5Xml.dll", "Qt5PrintSupport.dll",
            "qwindows.dll", "qico.dll", "qjpeg.dll", "qgif.dll", "qsvg.dll", "qminimal.dll", "qoffscreen.dll",
            // MSVC / MinGW / GCC Runtimes
            "MSVCR100.dll", "MSVCP100.dll", "MSVCR120.dll", "MSVCP120.dll", "vcruntime140.dll",
            "vcruntime140_1.dll", "msvcp140.dll", "ucrtbase.dll", "msvcrt.dll",
            "libstdc++-6.dll", "libgcc_s_dw2-1.dll", "libgcc_s_seh-1.dll", "libwinpthread-1.dll",
            // OpenSSL / System / Defender / Bonjour
            "libssl-1_1.dll", "libcrypto-1_1.dll", "libssl-3.dll", "libcrypto-3.dll",
            "libeay32.dll", "ssleay32.dll", "MpOav.dll", "amsi.dll", "wldp.dll",
            "mdnsNSP.dll", "comctl32.dll", "directxdatabasehelper.dll", "dataexchange.dll",
            "SETUPAPI.dll", "ntdll.dll", "kernel32.dll", "KernelBase.dll", "user32.dll", "gdi32.dll",
            "advapi32.dll", "ws2_32.dll", "shell32.dll", "ole32.dll", "oleaut32.dll", "crypt32.dll"
        };

        // 2. العمليات الفرعية الصامتة التي لا تمثل أوامر هاتف فعلية
        private static readonly HashSet<string> IgnoredEmptyChildProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "conhost.exe", "attrib.exe"
        };

        // 3. الأفعال الحقيقية فقط المسموح بها مع Heredoc (<<)
        private static readonly Regex ValidHeredocShellRegex = new(
            @"^\s*(?:cat|sh|su|bash|echo|dd|sqlite3|tee|base64)\s+.*<<\s*[a-zA-Z_][a-zA-Z0-9_]{1,16}\b",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        // 4. أوامر بروتوكول ADB السلكية الحقيقية (حساسة لحالة الأحرف لمنع التباس ترويسة HTTP "Host: ")
        private static readonly Regex ValidAdbWireProtocolRegex = new(
            @"^(?:host:(?:version|kill|devices(?:-l)?|track-devices(?:-l)?|transport(?:-usb|-local|-any|-id)?|serial:|tport:|features|host-features|pair|connect|disconnect|start-server|reconnect-offline|attach|detach)|shell:(?:[^\r\n]{2,})|sync:|framebuffer:|remount:|reboot:|reverse:|tcp:|localabstract:|localfilesystem:|dev:|jdwp:)",
            RegexOptions.Compiled);

        // 5. مطابقة صارمة لملفات الفيرموير واللودر ذات الامتداد الصريح فقط (تمنع "TAR file" و "7z M23..." و "tar ??is")
        private static readonly Regex ValidFirmwareArtifactRegex = new(
            @"^(?:[a-zA-Z]:\\|\\\\|\.?\/)?[a-zA-Z0-9_\-\.\/\\]{2,140}\.(?:tar|tar\.md5|7z|zip|bin|mbn|elf|img|pit|ops|ofp|pac|qcn|xqcn|nv|efs|sec|auth|da|xml|scatter\.txt)$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        // 6. كشف نصوص المساعدة الساكنة (adb --help) المخزنة في الرام
        private static readonly Regex StaticHelpLineRegex = new(
            @"\s{2,}-\s+(?:run remote shell|list all forward|remove all forward|reboots the device|push files that are newer)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        // سجل البصمات الدلالية لمنع تكرار نفس الحدث عند إعادة مسح الرام أو تغير الـ PID
        private static readonly ConcurrentDictionary<string, SourceTelemetryEvent> SeenEventFingerprints = new();

        public static void ResetSessionDeduplication() => SeenEventFingerprints.Clear();

        public static bool ShouldExcludeModuleFromExportAudit(string dllPath)
        {
            if (string.IsNullOrWhiteSpace(dllPath)) return true;
            string fileName = Path.GetFileName(dllPath.Trim());
            
            // استبعاد فحص جدول التصدير لملف الـ .exe نفسه لأنه يلتقط سلاسل مشفرة عشوائية كأنها دوال
            if (fileName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                return true;

            return ExcludedNoiseModules.Contains(fileName);
        }

        public static bool IsCleanAsciiString(string s)
        {
            if (string.IsNullOrWhiteSpace(s) || s.Length < 4) return false;
            if (s.Contains('?')) return false; // رفض فوري لأي بايت تالف تم تعويضه بـ '?' (0x3F)

            foreach (char c in s)
            {
                if (c == '\r' || c == '\n' || c == '\t') continue;
                if (c < 0x20 || c > 0x7E) return false;
            }
            return true;
        }

        /// <summary>
        /// البوابة المركزية لفحص وتنقية وتصحيح أي حدث قبل إضافته للواجهة أو ملف الـ JSON.
        /// </summary>
        public static bool TryFilterAndNormalizeEvent(SourceTelemetryEvent? evt)
        {
            if (evt == null) return false;

            string api = evt.HookedApiName ?? string.Empty;
            string cat = evt.CommandCategory ?? string.Empty;
            string target = evt.TargetResource ?? string.Empty;
            string decoded = evt.DecodedCommandText ?? string.Empty;

            // 1. فلترة PE_ExportTableAuditor
            if (api.Equals("PE_ExportTableAuditor", StringComparison.OrdinalIgnoreCase))
            {
                if (ShouldExcludeModuleFromExportAudit(target) || ShouldExcludeModuleFromExportAudit(evt.CallerModuleOrigin))
                    return false;
            }

            // 2. فلترة العمليات الفرعية الصامتة (conhost.exe / attrib.exe / WMIC بدون معاملات)
            if (cat.Equals("Child Process Execution", StringComparison.OrdinalIgnoreCase))
            {
                string procName = Path.GetFileName(target.Split(' ')[0].Trim());
                if (IgnoredEmptyChildProcesses.Contains(procName))
                    return false;

                if (procName.Equals("WMIC.exe", StringComparison.OrdinalIgnoreCase) &&
                    target.Trim().Equals("WMIC.exe", StringComparison.OrdinalIgnoreCase))
                    return false;
            }

            // 3. فلترة وتصحيح مخرجات الرام (LiveRAM_UniversalInterceptor)
            if (api.Equals("LiveRAM_UniversalInterceptor", StringComparison.OrdinalIgnoreCase))
            {
                string rawPayloadStr = ExtractRawAscii(evt.RawPayloadHex, target, decoded);

                if (!IsCleanAsciiString(rawPayloadStr))
                    return false;

                // رفض نصوص adb --help و curl help و LZ4 الثابتة
                if (StaticHelpLineRegex.IsMatch(rawPayloadStr) ||
                    rawPayloadStr.StartsWith("sync: only push files", StringComparison.OrdinalIgnoreCase) ||
                    rawPayloadStr.StartsWith("LZ4 ", StringComparison.OrdinalIgnoreCase) ||
                    rawPayloadStr.Equals("TAR file", StringComparison.OrdinalIgnoreCase) ||
                    rawPayloadStr.Equals("shell:\n shell", StringComparison.OrdinalIgnoreCase) ||
                    rawPayloadStr.Contains("terminated with a semicolon", StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                // تصحيح ترويسات HTTP "Host: domain.com" التي التُقطت خطأً كأوامر ADB
                if (rawPayloadStr.StartsWith("Host:", StringComparison.Ordinal) &&
                    (rawPayloadStr.Contains("\r\n") || rawPayloadStr.Contains("Content-Type") || rawPayloadStr.Contains("User-Agent")))
                {
                    string hostLine = rawPayloadStr.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)[0].Trim();
                    evt.CommandCategory = "Network / C2 Server Endpoint";
                    evt.TargetResource = hostLine;
                    evt.DecodedCommandText = $"خادم اتصال شبكي مكتشف في ذاكرة الأداة: {hostLine}";
                }
                // فلترة علامة << (Heredoc)
                else if (cat.Contains("Heredoc", StringComparison.OrdinalIgnoreCase) || rawPayloadStr.Contains("<<"))
                {
                    if (!ValidHeredocShellRegex.IsMatch(rawPayloadStr))
                        return false;
                }
                // فلترة ملفات البوت واللودر (منع 7z M23... الخاصة بـ SVG ومنع tar ??is...)
                else if (cat.Contains("Boot Loader", StringComparison.OrdinalIgnoreCase) ||
                         cat.Contains("Firmware File", StringComparison.OrdinalIgnoreCase))
                {
                    if (!ValidFirmwareArtifactRegex.IsMatch(rawPayloadStr))
                        return false;
                }
                // فلترة أوامر الشل/ADB المباشرة
                else if (cat.Contains("ADB / Interactive Shell", StringComparison.OrdinalIgnoreCase))
                {
                    if (rawPayloadStr.Equals("chown user file", StringComparison.OrdinalIgnoreCase) ||
                        rawPayloadStr.Equals("getProperties", StringComparison.OrdinalIgnoreCase) ||
                        rawPayloadStr.StartsWith("Host:", StringComparison.Ordinal))
                    {
                        return false;
                    }

                    if ((rawPayloadStr.StartsWith("host:", StringComparison.OrdinalIgnoreCase) ||
                         rawPayloadStr.StartsWith("shell:", StringComparison.OrdinalIgnoreCase) ||
                         rawPayloadStr.StartsWith("sync:", StringComparison.OrdinalIgnoreCase)) &&
                        !ValidAdbWireProtocolRegex.IsMatch(rawPayloadStr))
                    {
                        return false;
                    }
                }
            }

            // 4. منع التكرار الدلالي عبر الجلسة (حتى لو تغير الـ PID أو عنوان الرام)
            string fingerprint = ComputeSemanticFingerprint(evt);
            if (!SeenEventFingerprints.TryAdd(fingerprint, evt))
            {
                return false;
            }

            return true;
        }

        private static string ComputeSemanticFingerprint(SourceTelemetryEvent evt)
        {
            // نثبت الفئة + الهدف + النص المفكوك بدون الـ PID وبدون عنوان الرام المتغير
            string key = $"{evt.HookedApiName}|{evt.CommandCategory}|{evt.TargetResource}|{evt.DecodedCommandText}".Trim();
            byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(key));
            return Convert.ToHexString(hash)[..24];
        }

        private static string ExtractRawAscii(string? hex, string target, string decoded)
        {
            if (!string.IsNullOrWhiteSpace(hex) && hex.Length % 2 == 0)
            {
                try
                {
                    byte[] bytes = Convert.FromHexString(hex);
                    return Encoding.UTF8.GetString(bytes).Trim();
                }
                catch { }
            }

            int idx = decoded.IndexOf(':');
            if (idx >= 0 && idx + 1 < decoded.Length)
                return decoded[(idx + 1)..].Trim();

            return target;
        }
    }
}
