using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using PhoenixOmniTrace.L24_SourceSentinel.Models;

namespace PhoenixOmniTrace.L24_SourceSentinel.Core;

public static class ForensicNoiseGate
{
    public static bool ShowPhoneResponses { get; set; } = true;

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
        "conhost.exe", "attrib.exe", "git.exe", "chrome.exe", "services.exe", "svchost.exe", "searchprotocolhost.exe", "searchindexer.exe"
    };

    private static readonly Regex StaticHelpLineRegex = new(
        @"\s{2,}-\s+(?:run remote shell|list all forward|remove all forward|reboots the device|push files that are newer)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly ConcurrentDictionary<string, DateTime> SeenFingerprints = new();

    public static void ResetSession()
    {
        SeenFingerprints.Clear();
        RamCommandConsolidator.ResetSession();
    }

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
        if (string.IsNullOrWhiteSpace(s)) return false;
        string trimmed = s.Trim();
        if (trimmed.Length < 2 && !trimmed.StartsWith("<<")) return false;
        if (trimmed.Contains("????", StringComparison.Ordinal)) return false;

        int nonPrintable = 0;
        foreach (char c in s)
        {
            if (c == '\r' || c == '\n' || c == '\t') continue;
            if (c < 0x20 || c > 0x7E) nonPrintable++;
        }
        return (double)nonPrintable / s.Length <= 0.08;
    }

    public static bool IsCleanAsciiString(string s) => IsCleanAscii(s);

    public static bool TryFilterAndNormalizeEvent(SourceTelemetryEvent? evt)
    {
        if (evt == null) return false;

        string api = evt.HookedApiName ?? string.Empty;
        string cat = evt.CommandCategory ?? string.Empty;
        string target = evt.TargetResource ?? string.Empty;
        string decoded = evt.DecodedCommandText ?? string.Empty;

        if (!ShowPhoneResponses && evt.IsPhoneResponse)
            return false;

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

        if (cat.Equals("Helper File Preparation", StringComparison.OrdinalIgnoreCase))
        {
            if (evt.PayloadSize == 0 && string.IsNullOrWhiteSpace(evt.SavedFilePath) &&
                (target.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase) || target.Contains(".squirrel-lock", StringComparison.OrdinalIgnoreCase)))
            {
                return false;
            }
        }

        if (cat.Equals("Child Process Execution", StringComparison.OrdinalIgnoreCase))
        {
            string cleanTarget = target.Trim();
            string firstToken = Path.GetFileName(cleanTarget.Split(' ')[0].Trim('"'));

            if (IgnoredChildProcesses.Contains(firstToken) || cleanTarget.Contains("conhost.exe", StringComparison.OrdinalIgnoreCase))
                return false;

            if (firstToken.Equals("WMIC.exe", StringComparison.OrdinalIgnoreCase) &&
                cleanTarget.Equals("WMIC.exe", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        if (api.Equals("LiveRAM_UniversalInterceptor", StringComparison.OrdinalIgnoreCase))
        {
            string rawStr = !string.IsNullOrWhiteSpace(evt.PureCommandText)
                ? evt.PureCommandText
                : ExtractRawString(evt.RawPayloadHex, target, decoded);
            evt.PureCommandText = rawStr;

            bool isJsonObjectOrHttp = rawStr.StartsWith("{", StringComparison.Ordinal) ||
                                      rawStr.StartsWith("http", StringComparison.OrdinalIgnoreCase) ||
                                      rawStr.StartsWith("POST ", StringComparison.OrdinalIgnoreCase) ||
                                      rawStr.StartsWith("GET ", StringComparison.OrdinalIgnoreCase);

            if (!isJsonObjectOrHttp &&
                (rawStr.Contains("\",\"", StringComparison.Ordinal) || rawStr.Contains("\", \"", StringComparison.Ordinal)))
            {
                return false;
            }

            bool isBinaryHexPacket = cat.Contains("Binary Packet", StringComparison.OrdinalIgnoreCase) ||
                                     cat.Contains("BROM Handshake", StringComparison.OrdinalIgnoreCase) ||
                                     cat.Contains("Sahara", StringComparison.OrdinalIgnoreCase) ||
                                     cat.Contains("DIAG Packet", StringComparison.OrdinalIgnoreCase) ||
                                     cat.Contains("Carved", StringComparison.OrdinalIgnoreCase);

            if (!isBinaryHexPacket)
            {
                if (!IsCleanAscii(rawStr))
                    return false;

                if (StaticHelpLineRegex.IsMatch(rawStr) ||
                    rawStr.StartsWith("sync: only push files", StringComparison.OrdinalIgnoreCase) ||
                    rawStr.Equals("TAR file", StringComparison.OrdinalIgnoreCase) ||
                    rawStr.Equals("shell:\n shell", StringComparison.OrdinalIgnoreCase) ||
                    rawStr.Contains("terminated with a semicolon", StringComparison.OrdinalIgnoreCase) ||
                    rawStr.Contains("font-family:", StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }
            }
        }
        else if (string.IsNullOrWhiteSpace(evt.PureCommandText))
        {
            evt.PureCommandText = ExtractRawString(evt.RawPayloadHex, target, decoded);
        }

        if (!RamCommandConsolidator.TryConsolidateOrDeduplicate(evt))
            return false;

        string fp = ComputeFingerprint(evt);
        DateTime now = DateTime.UtcNow;
        bool isLiveBridge = evt.Scope == L24CommandScope.ExecutedOnDevice;

        if (SeenFingerprints.TryGetValue(fp, out var prevTime))
        {
            if (!isLiveBridge)
                return false;
            if ((now - prevTime).TotalSeconds < 0.8)
                return false;
        }

        SeenFingerprints[fp] = now;
        return true;
    }

    private static string ComputeFingerprint(SourceTelemetryEvent evt)
    {
        string canonical = $"{evt.Scope}|{evt.CommandCategory}|{evt.TargetResource}|{evt.PureCommandText}".Trim();
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return Convert.ToHexString(hash)[..24];
    }

    private static string ExtractRawString(string? hex, string target, string decoded)
    {
        if (!string.IsNullOrWhiteSpace(hex) && hex.Length % 2 == 0)
        {
            try
            {
                string s = Encoding.UTF8.GetString(Convert.FromHexString(hex)).Trim();
                if (!string.IsNullOrWhiteSpace(s)) return s;
            }
            catch { }
        }
        int idx = decoded.IndexOf(':');
        if (idx >= 0 && idx + 1 < decoded.Length &&
            !decoded.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
            !decoded.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            return decoded[(idx + 1)..].Trim();
        }
        if (!string.IsNullOrWhiteSpace(decoded))
        {
            return decoded.Trim();
        }
        return target.Trim();
    }
}
