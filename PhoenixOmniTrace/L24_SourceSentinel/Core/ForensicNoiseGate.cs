using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using PhoenixOmniTrace.L24_SourceSentinel.Models;

namespace PhoenixOmniTrace.L24_SourceSentinel.Core;

/// <summary>
/// أرشيف الحفظ التلقائي الفوري لكافة الملفات المكتشفة في الطبقة L24 (من المجلدات المؤقتة، الكيرنل، الرام، أو السلك)
/// </summary>
public static class L24FileArchiver
{
    private static readonly object FileLock = new();
    private static readonly ConcurrentDictionary<string, string> SavedByHash = new(StringComparer.OrdinalIgnoreCase);
    private static readonly ConcurrentDictionary<string, int> FileNameCounter = new(StringComparer.OrdinalIgnoreCase);
    private static readonly HashSet<string> ToolDirectories = new(StringComparer.OrdinalIgnoreCase);
    private static string _sessionFilesDirectory = string.Empty;

    public static string CurrentCapturedFilesDirectory
    {
        get
        {
            if (string.IsNullOrWhiteSpace(_sessionFilesDirectory))
            {
                string baseDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Logs", "L24_SourceSentinel");
                InitializeSessionDirectory(baseDir);
            }
            return _sessionFilesDirectory;
        }
    }

    public static void InitializeSessionDirectory(string baseLogDirectory)
    {
        lock (FileLock)
        {
            string stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            _sessionFilesDirectory = Path.Combine(baseLogDirectory, "CapturedFiles", $"Session_{stamp}");
            Directory.CreateDirectory(_sessionFilesDirectory);
            SavedByHash.Clear();
            FileNameCounter.Clear();
        }
    }

    public static void RegisterToolDirectory(string? dirPath)
    {
        if (string.IsNullOrWhiteSpace(dirPath) || !Directory.Exists(dirPath)) return;
        lock (FileLock)
        {
            ToolDirectories.Add(dirPath);
        }
    }

    public static bool TryArchiveDiscoveredFile(
        string? sourcePathOrName,
        string sourceVector,
        out string savedFilePath,
        out long savedSizeBytes,
        out string sha256Hex)
    {
        savedFilePath = string.Empty;
        savedSizeBytes = 0;
        sha256Hex = string.Empty;

        if (string.IsNullOrWhiteSpace(sourcePathOrName)) return false;

        string cleanCandidate = sourcePathOrName.Trim().Trim('"', '\'');
        string? resolvedPath = ResolveExistingFilePath(cleanCandidate);
        if (string.IsNullOrWhiteSpace(resolvedPath) || !File.Exists(resolvedPath))
            return false;

        string fileName = Path.GetFileName(resolvedPath);
        if (IsSystemNoiseFile(resolvedPath, fileName))
            return false;

        byte[]? fileBytes = TryReadFileBytesShared(resolvedPath);
        if (fileBytes == null || fileBytes.Length == 0)
            return false;

        return TryArchiveRawBuffer(fileBytes, fileName, sourceVector, out savedFilePath, out savedSizeBytes, out sha256Hex);
    }

    public static bool TryArchiveRawBuffer(
        byte[]? data,
        string suggestedFileName,
        string sourceVector,
        out string savedFilePath,
        out long savedSizeBytes,
        out string sha256Hex)
    {
        savedFilePath = string.Empty;
        savedSizeBytes = 0;
        sha256Hex = string.Empty;

        if (data == null || data.Length == 0) return false;

        savedSizeBytes = data.Length;
        sha256Hex = Convert.ToHexString(SHA256.HashData(data));

        if (SavedByHash.TryGetValue(sha256Hex, out var existingSaved) && File.Exists(existingSaved))
        {
            savedFilePath = existingSaved;
            return true;
        }

        string cleanName = SanitizeFileName(suggestedFileName);
        if (string.IsNullOrWhiteSpace(cleanName))
            cleanName = $"L24_Payload_{sha256Hex[..8]}.bin";

        lock (FileLock)
        {
            try
            {
                string dir = CurrentCapturedFilesDirectory;
                Directory.CreateDirectory(dir);

                int seq = FileNameCounter.AddOrUpdate(cleanName, 1, (_, c) => c + 1);
                string finalName = seq <= 1
                    ? cleanName
                    : $"{Path.GetFileNameWithoutExtension(cleanName)}_{seq}{Path.GetExtension(cleanName)}";

                string fullDest = Path.Combine(dir, finalName);
                File.WriteAllBytes(fullDest, data);

                string metaPath = fullDest + ".meta.txt";
                string metaContent =
                    $"Saved At      : {DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}\r\n" +
                    $"Original Name : {suggestedFileName}\r\n" +
                    $"Saved Name    : {finalName}\r\n" +
                    $"Capture Vector: {sourceVector}\r\n" +
                    $"Size (Bytes)  : {data.Length:N0}\r\n" +
                    $"SHA-256       : {sha256Hex}\r\n";
                File.WriteAllText(metaPath, metaContent, Encoding.UTF8);

                SavedByHash[sha256Hex] = fullDest;
                savedFilePath = fullDest;
                return true;
            }
            catch
            {
                return false;
            }
        }
    }

    private static string? ResolveExistingFilePath(string candidate)
    {
        try
        {
            if (candidate.StartsWith(@"\??\", StringComparison.Ordinal))
                candidate = candidate[4..];

            if (Path.IsPathRooted(candidate) && File.Exists(candidate))
                return candidate;

            string fileName = Path.GetFileName(candidate);
            if (string.IsNullOrWhiteSpace(fileName)) return null;

            var searchDirs = new List<string>
            {
                Path.GetTempPath(),
                Environment.CurrentDirectory,
                AppDomain.CurrentDomain.BaseDirectory,
                Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                @"C:\UnlockTool",
                @"C:\Program Files (x86)\KEY-Tool",
                @"C:\Program Files\KEY-Tool"
            };

            lock (FileLock)
            {
                searchDirs.InsertRange(0, ToolDirectories);
            }

            foreach (var dir in searchDirs)
            {
                if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir)) continue;
                if (dir.Contains("CapturedFiles", StringComparison.OrdinalIgnoreCase) ||
                    dir.Contains("CapturedArtifacts", StringComparison.OrdinalIgnoreCase))
                    continue;

                try
                {
                    string direct = Path.Combine(dir, candidate);
                    if (File.Exists(direct)) return direct;

                    string byName = Path.Combine(dir, fileName);
                    if (File.Exists(byName)) return byName;

                    var opts = new EnumerationOptions
                    {
                        IgnoreInaccessible = true,
                        RecurseSubdirectories = true,
                        MaxRecursionDepth = 2,
                        MatchCasing = MatchCasing.CaseInsensitive
                    };
                    foreach (var found in Directory.EnumerateFiles(dir, fileName, opts))
                    {
                        if (!found.Contains("CapturedFiles", StringComparison.OrdinalIgnoreCase))
                            return found;
                    }
                }
                catch { }
            }
        }
        catch { }
        return null;
    }

    private static byte[]? TryReadFileBytesShared(string path)
    {
        for (int attempt = 0; attempt < 4; attempt++)
        {
            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                if (fs.Length <= 0 || fs.Length > 256 * 1024 * 1024) return null;
                byte[] buffer = new byte[fs.Length];
                int readTotal = 0;
                while (readTotal < buffer.Length)
                {
                    int r = fs.Read(buffer, readTotal, buffer.Length - readTotal);
                    if (r <= 0) break;
                    readTotal += r;
                }
                if (readTotal > 0)
                    return readTotal == buffer.Length ? buffer : buffer[..readTotal];
            }
            catch (IOException)
            {
                Thread.Sleep(25);
            }
            catch
            {
                return null;
            }
        }
        return null;
    }

    private static bool IsSystemNoiseFile(string fullPath, string fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName)) return true;
        if (fullPath.Contains("L24_SourceSentinel", StringComparison.OrdinalIgnoreCase) ||
            fullPath.Contains("CapturedFiles", StringComparison.OrdinalIgnoreCase) ||
            fullPath.Contains("CapturedArtifacts", StringComparison.OrdinalIgnoreCase))
            return true;

        if (fullPath.StartsWith(@"C:\Windows\", StringComparison.OrdinalIgnoreCase))
            return true;

        if (fileName.EndsWith(".etl", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".squirrel-lock", StringComparison.OrdinalIgnoreCase) ||
            fileName.Equals("adb.log", StringComparison.OrdinalIgnoreCase))
            return true;

        if (ForensicNoiseGate.ExcludedNoiseModules.Contains(fileName))
            return true;

        return false;
    }

    private static string SanitizeFileName(string name)
    {
        string baseName = Path.GetFileName(name.Trim().Replace('/', '\\'));
        foreach (char invalid in Path.GetInvalidFileNameChars())
        {
            baseName = baseName.Replace(invalid, '_');
        }
        return baseName;
    }
}

/// <summary>
/// محرك منع التكرار الدقيق ودمج التجزئة التدريجية في نفس البافر بالذاكرة دون التهام الروابط أو الأوامر المستقلة
/// </summary>
public static class RamCommandConsolidator
{
    private static readonly object SyncLock = new();
    private static long _outboundExecutedSequence = 1;

    private static readonly List<TrackedRamCommandEntry> _discoveredRamEntries = new();
    private static readonly ConcurrentDictionary<string, long> _phoneResponseLastExecSeq = new(StringComparer.OrdinalIgnoreCase);
    private static readonly ConcurrentDictionary<string, DateTime> _phoneResponseLastTime = new(StringComparer.OrdinalIgnoreCase);

    private sealed class TrackedRamCommandEntry
    {
        public required Guid EventId { get; init; }
        public required L24CommandGroup Group { get; init; }
        public required bool IsPhoneResponse { get; init; }
        public required long MemoryAddress { get; set; }
        public required string NormalizedCommand { get; set; }
        public required SourceTelemetryEvent EventRef { get; init; }
        public DateTime LastUpdatedUtc { get; set; }
    }

    public static void ResetSession()
    {
        lock (SyncLock)
        {
            _discoveredRamEntries.Clear();
            _phoneResponseLastExecSeq.Clear();
            _phoneResponseLastTime.Clear();
            Interlocked.Exchange(ref _outboundExecutedSequence, 1);
        }
    }

    public static void NotifyActualOutboundCommandExecuted()
    {
        Interlocked.Increment(ref _outboundExecutedSequence);
    }

    public static bool TryConsolidateOrDeduplicate(SourceTelemetryEvent evt)
    {
        if (evt == null) return false;

        string pure = NormalizeCommandKey(evt.PureCommandText);
        if (string.IsNullOrWhiteSpace(pure)) return false;

        long currentExecSeq = Interlocked.Read(ref _outboundExecutedSequence);
        DateTime now = DateTime.UtcNow;

        if (evt.Scope == L24CommandScope.ExecutedOnDevice)
        {
            if (!evt.IsPhoneResponse)
            {
                NotifyActualOutboundCommandExecuted();
                return true;
            }
            else
            {
                if (_phoneResponseLastExecSeq.TryGetValue(pure, out long lastSeq) && lastSeq == currentExecSeq)
                {
                    if (_phoneResponseLastTime.TryGetValue(pure, out var lastTime) && (now - lastTime).TotalSeconds < 2.0)
                        return false;
                }

                _phoneResponseLastExecSeq[pure] = currentExecSeq;
                _phoneResponseLastTime[pure] = now;
                return true;
            }
        }

        if (evt.Scope == L24CommandScope.DiscoveredInRam)
        {
            lock (SyncLock)
            {
                if (evt.IsPhoneResponse)
                {
                    if (TryMergeSameBufferFragmentLocked(evt, pure, isResponse: true, now, out bool dropFragment))
                    {
                        if (dropFragment) return false;
                        _phoneResponseLastExecSeq[pure] = currentExecSeq;
                        _phoneResponseLastTime[pure] = now;
                        return true;
                    }

                    if (_phoneResponseLastExecSeq.TryGetValue(pure, out long recordedSeq) && recordedSeq == currentExecSeq)
                    {
                        return false;
                    }

                    _phoneResponseLastExecSeq[pure] = currentExecSeq;
                    _phoneResponseLastTime[pure] = now;
                }

                if (TryMergeSameBufferFragmentLocked(evt, pure, evt.IsPhoneResponse, now, out bool dropDuplicateOrFragment))
                {
                    return !dropDuplicateOrFragment;
                }

                _discoveredRamEntries.Add(new TrackedRamCommandEntry
                {
                    EventId = evt.EventId,
                    Group = evt.CommandGroup,
                    IsPhoneResponse = evt.IsPhoneResponse,
                    MemoryAddress = evt.MemoryAddress,
                    NormalizedCommand = pure,
                    EventRef = evt,
                    LastUpdatedUtc = now
                });

                return true;
            }
        }

        return true;
    }

    private static bool TryMergeSameBufferFragmentLocked(
        SourceTelemetryEvent incoming,
        string incomingPure,
        bool isResponse,
        DateTime now,
        out bool shouldDrop)
    {
        shouldDrop = false;

        for (int i = _discoveredRamEntries.Count - 1; i >= 0; i--)
        {
            var existing = _discoveredRamEntries[i];
            if (existing.IsPhoneResponse != isResponse) continue;

            string existingPure = existing.NormalizedCommand;

            if (string.Equals(existingPure, incomingPure, StringComparison.OrdinalIgnoreCase))
            {
                shouldDrop = true;
                return true;
            }

            bool isSameMemoryNeighborhood = incoming.MemoryAddress > 0 && existing.MemoryAddress > 0 &&
                                            Math.Abs(incoming.MemoryAddress - existing.MemoryAddress) <= 128;
            bool isVeryRecentTyping = (now - existing.LastUpdatedUtc).TotalSeconds <= 1.5;

            if (isSameMemoryNeighborhood && isVeryRecentTyping)
            {
                if (incomingPure.Length < existingPure.Length && incomingPure.Length >= 5 &&
                    existingPure.StartsWith(incomingPure, StringComparison.OrdinalIgnoreCase))
                {
                    shouldDrop = true;
                    return true;
                }

                if (incomingPure.Length > existingPure.Length && existingPure.Length >= 5 &&
                    incomingPure.StartsWith(existingPure, StringComparison.OrdinalIgnoreCase))
                {
                    existing.NormalizedCommand = incomingPure;
                    existing.MemoryAddress = incoming.MemoryAddress;
                    existing.LastUpdatedUtc = now;

                    existing.EventRef.DecodedCommandText = incoming.DecodedCommandText;
                    existing.EventRef.RawPayloadHex = incoming.RawPayloadHex;
                    existing.EventRef.PayloadSize = incoming.PayloadSize;
                    existing.EventRef.PureCommandText = incoming.PureCommandText;
                    if (!string.IsNullOrWhiteSpace(incoming.TargetResource))
                        existing.EventRef.TargetResource = incoming.TargetResource;

                    shouldDrop = true;
                    return true;
                }
            }
        }

        return false;
    }

    public static string NormalizeCommandKey(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return string.Empty;
        string s = raw.Trim();
        var sb = new StringBuilder(s.Length);
        bool prevSpace = false;
        foreach (char c in s)
        {
            if (c is ' ' or '\t' or '\r' or '\n')
            {
                if (!prevSpace)
                {
                    sb.Append(' ');
                    prevSpace = true;
                }
            }
            else
            {
                sb.Append(c);
                prevSpace = false;
            }
        }
        return sb.ToString().Trim();
    }
}

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
                return false;
        }

        if (cat.Equals("Child Process Execution", StringComparison.OrdinalIgnoreCase))
        {
            string cleanTarget = target.Trim();
            string firstToken = Path.GetFileName(cleanTarget.Split(' ')[0].Trim('"'));

            if (IgnoredChildProcesses.Contains(firstToken) || cleanTarget.Contains("conhost.exe", StringComparison.OrdinalIgnoreCase))
                return false;

            if (firstToken.Equals("WMIC.exe", StringComparison.OrdinalIgnoreCase) &&
                cleanTarget.Equals("WMIC.exe", StringComparison.OrdinalIgnoreCase))
                return false;
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
                                     cat.Contains("DIAG Packet", StringComparison.OrdinalIgnoreCase);

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
