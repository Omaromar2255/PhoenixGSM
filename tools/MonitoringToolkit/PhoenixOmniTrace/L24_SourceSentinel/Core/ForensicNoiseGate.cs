using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using PhoenixOmniTrace.L24_SourceSentinel.Models;

namespace PhoenixOmniTrace.L24_SourceSentinel.Core
{
    public static class ForensicNoiseGate
    {
        public static readonly HashSet<string> ExcludedNoiseModules = new(StringComparer.OrdinalIgnoreCase)
        {
            "Qt5Core.dll", "Qt5Gui.dll", "Qt5Widgets.dll", "Qt5Network.dll", "Qt5Svg.dll",
            "Qt5WinExtras.dll", "Qt5Sql.dll", "Qt5Xml.dll", "Qt5PrintSupport.dll",
            "qwindows.dll", "qico.dll", "qjpeg.dll", "qgif.dll", "qsvg.dll", "qminimal.dll", "qoffscreen.dll",
            "MSVCR100.dll", "MSVCP100.dll", "MSVCR120.dll", "MSVCP120.dll", "vcruntime140.dll",
            "vcruntime140_1.dll", "msvcp140.dll", "ucrtbase.dll", "msvcrt.dll",
            "libstdc++-6.dll", "libgcc_s_dw2-1.dll", "libgcc_s_seh-1.dll", "libwinpthread-1.dll",
            "libssl-1_1.dll", "libcrypto-1_1.dll", "libssl-3.dll", "libcrypto-3.dll",
            "libeay32.dll", "ssleay32.dll", "MpOav.dll", "amsi.dll", "wldp.dll",
            "mdnsNSP.dll", "comctl32.dll", "directxdatabasehelper.dll", "dataexchange.dll",
            "SETUPAPI.dll", "ntdll.dll", "kernel32.dll", "KernelBase.dll", "user32.dll", "gdi32.dll"
        };

        private static readonly HashSet<string> IgnoredChildProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "conhost.exe", "attrib.exe", "git.exe", "chrome.exe", "services.exe", "svchost.exe"
        };

        private static readonly Regex ValidHeredocShellRegex = new(
            @"^\s*(?:cat|sh|su|bash|echo|dd|sqlite3|tee|base64)\s+.*<<\s*[a-zA-Z_][a-zA-Z0-9_]{1,16}\b",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex ValidAdbWireProtocolRegex = new(
            @"^(?:host:(?:version|kill|devices(?:-l)?|track-devices(?:-l)?|transport(?:-usb|-local|-any|-id)?|serial:|tport:|features|host-features|pair|connect|disconnect|start-server|reconnect-offline|attach|detach)|shell:(?:[^\r\n]{2,})|sync:|framebuffer:|remount:|reboot:|reverse:|tcp:|localabstract:|localfilesystem:|dev:|jdwp:)",
            RegexOptions.Compiled);

        private static readonly Regex ValidFirmwareArtifactRegex = new(
            @"^(?:[a-zA-Z]:\\|\\\\|\.?\/)?[a-zA-Z0-9_\-\.\/\\]{2,140}\.(?:tar|tar\.md5|7z|zip|bin|mbn|elf|img|pit|ops|ofp|pac|qcn|xqcn|nv|efs|sec|auth|da|xml|scatter\.txt)$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex StaticHelpLineRegex = new(
            @"\s{2,}-\s+(?:run remote shell|list all forward|remove all forward|reboots the device|push files that are newer)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly ConcurrentDictionary<string, byte> SeenFingerprints = new();

        public static void ResetSession() => SeenFingerprints.Clear();

        public static void ResetSessionDeduplication() => ResetSession();

        public static bool ShouldExcludeModuleFromExportAudit(string? modulePathOrName)
        {
            if (string.IsNullOrWhiteSpace(modulePathOrName)) return true;
            string fileName = Path.GetFileName(modulePathOrName.Trim());
            if (fileName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) return true;
            return ExcludedNoiseModules.Contains(fileName);
        }

        public static bool IsCleanAscii(string s)
        {
            if (string.IsNullOrWhiteSpace(s) || s.Length < 4) return false;
            if (s.Contains('?')) return false;
            foreach (char c in s)
            {
                if (c == '\r' || c == '\n' || c == '\t') continue;
                if (c < 0x20 || c > 0x7E) return false;
            }
            return true;
        }

        public static bool IsCleanAsciiString(string s) => IsCleanAscii(s);

        public static bool TryFilterAndNormalizeEvent(SourceTelemetryEvent? evt)
        {
            if (evt == null) return false;

            string api = evt.HookedApiName ?? string.Empty;
            string cat = evt.CommandCategory ?? string.Empty;
            string target = evt.TargetResource ?? string.Empty;
            string decoded = evt.DecodedCommandText ?? string.Empty;

            // 1. استبعاد مكتبات الواجهة والنظام في Stage 0 (ModuleLoaderSnap) و Stage 3 (PE_ExportTableAuditor)
            if (api.Equals("PE_ExportTableAuditor", StringComparison.OrdinalIgnoreCase))
            {
                if (ShouldExcludeModuleFromExportAudit(target) || ShouldExcludeModuleFromExportAudit(evt.CallerModuleOrigin))
                    return false;
            }
            else if (api.Equals("ModuleLoaderSnap", StringComparison.OrdinalIgnoreCase))
            {
                string modName = Path.GetFileName(target.Trim());
                if (ExcludedNoiseModules.Contains(modName))
                    return false;
            }

            // 2. استبعاد ملفات .tmp الفارغة (PayloadSize == 0) وملفات .squirrel-lock
            if (cat.Equals("Helper File Preparation", StringComparison.OrdinalIgnoreCase))
            {
                if (evt.PayloadSize == 0 && (target.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase) || target.Contains(".squirrel-lock", StringComparison.OrdinalIgnoreCase)))
                    return false;
            }

            // 3. فلترة العمليات الفرعية الصامتة (conhost.exe / git.exe / WMIC.exe بدون معاملات)
            if (cat.Equals("Child Process Execution", StringComparison.OrdinalIgnoreCase))
            {
                string cleanTarget = target.Trim();
                string firstToken = Path.GetFileName(cleanTarget.Split(' ')[0].Trim());

                if (IgnoredChildProcesses.Contains(firstToken) || cleanTarget.Contains("conhost.exe", StringComparison.OrdinalIgnoreCase))
                    return false;

                if (firstToken.Equals("WMIC.exe", StringComparison.OrdinalIgnoreCase) &&
                    cleanTarget.Equals("WMIC.exe", StringComparison.OrdinalIgnoreCase))
                    return false;
            }

            // 4. فلترة وتصحيح مخرجات الرام (LiveRAM_UniversalInterceptor)
            if (api.Equals("LiveRAM_UniversalInterceptor", StringComparison.OrdinalIgnoreCase))
            {
                string rawStr = ExtractRawString(evt.RawPayloadHex, target, decoded);

                if (!IsCleanAscii(rawStr))
                    return false;

                if (StaticHelpLineRegex.IsMatch(rawStr) ||
                    rawStr.StartsWith("sync: only push files", StringComparison.OrdinalIgnoreCase) ||
                    rawStr.StartsWith("LZ4 ", StringComparison.OrdinalIgnoreCase) ||
                    rawStr.Equals("TAR file", StringComparison.OrdinalIgnoreCase) ||
                    rawStr.Equals("shell:\n shell", StringComparison.OrdinalIgnoreCase) ||
                    rawStr.Contains("terminated with a semicolon", StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                // تصحيح ترويسات HTTP "Host: ..." (مثل Host: key-tool-api.herokuapp.com)
                if (rawStr.StartsWith("Host:", StringComparison.Ordinal))
                {
                    string hostLine = rawStr.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)[0].Trim();
                    // تجاهل النسخ المبتورة إذا كانت أقل من 12 حرفاً
                    if (hostLine.Length < 12) return false;

                    evt.CommandCategory = "Network / C2 Server Endpoint";
                    evt.TargetResource = hostLine;
                    evt.DecodedCommandText = $"خادم سحابي خاص بالأداة مكتشف في الذاكرة: {hostLine}";
                }
                else if (cat.Contains("Heredoc", StringComparison.OrdinalIgnoreCase) || rawStr.Contains("<<"))
                {
                    if (!ValidHeredocShellRegex.IsMatch(rawStr))
                        return false;
                }
                else if (cat.Contains("Boot Loader", StringComparison.OrdinalIgnoreCase) ||
                         cat.Contains("Firmware File", StringComparison.OrdinalIgnoreCase))
                {
                    if (!ValidFirmwareArtifactRegex.IsMatch(rawStr))
                        return false;
                }
                else if (cat.Contains("ADB / Interactive Shell", StringComparison.OrdinalIgnoreCase))
                {
                    if (rawStr.Equals("chown user file", StringComparison.OrdinalIgnoreCase) ||
                        rawStr.Equals("getProperties", StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }

                    if ((rawStr.StartsWith("host:", StringComparison.OrdinalIgnoreCase) ||
                         rawStr.StartsWith("shell:", StringComparison.OrdinalIgnoreCase) ||
                         rawStr.StartsWith("sync:", StringComparison.OrdinalIgnoreCase)) &&
                        !ValidAdbWireProtocolRegex.IsMatch(rawStr))
                    {
                        return false;
                    }
                }
                else if (cat.Equals("Modem AT Command", StringComparison.OrdinalIgnoreCase))
                {
                    // استبعاد البادئات المبتورة مثل "AT+ACT" عندما يكون الأمر الكامل "AT+ACTIVATE=0,0,0" موجوداً
                    if (rawStr.Equals("AT+ACT", StringComparison.OrdinalIgnoreCase) ||
                        rawStr.EndsWith(",", StringComparison.Ordinal))
                    {
                        return false;
                    }
                }
            }

            // 5. منع التكرار الدلالي عبر الجلسة بالكامل
            string fp = ComputeFingerprint(evt);
            return SeenFingerprints.TryAdd(fp, 1);
        }

        private static string ComputeFingerprint(SourceTelemetryEvent evt)
        {
            string canonical = $"{evt.CommandCategory}|{evt.TargetResource}|{evt.DecodedCommandText}".Trim();
            byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
            return Convert.ToHexString(hash)[..24];
        }

        private static string ExtractRawString(string? hex, string target, string decoded)
        {
            if (!string.IsNullOrWhiteSpace(hex) && hex.Length % 2 == 0)
            {
                try
                {
                    return Encoding.UTF8.GetString(Convert.FromHexString(hex)).Trim();
                }
                catch { }
            }
            int idx = decoded.IndexOf(':');
            return idx >= 0 && idx + 1 < decoded.Length ? decoded[(idx + 1)..].Trim() : target;
        }
    }
}
