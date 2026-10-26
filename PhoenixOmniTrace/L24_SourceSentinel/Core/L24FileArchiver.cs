using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

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
        if (File.Exists(candidate)) return candidate;

        string fileNameOnly = Path.GetFileName(candidate);
        if (string.IsNullOrWhiteSpace(fileNameOnly)) return null;

        lock (FileLock)
        {
            foreach (var tDir in ToolDirectories)
            {
                try
                {
                    string probe = Path.Combine(tDir, fileNameOnly);
                    if (File.Exists(probe)) return probe;

                    if (Directory.Exists(tDir))
                    {
                        var matches = Directory.GetFiles(tDir, fileNameOnly, SearchOption.AllDirectories);
                        if (matches.Length > 0) return matches[0];
                    }
                }
                catch { }
            }
        }

        string[] commonDirs =
        {
            Path.GetTempPath(),
            @"C:\Temp",
            @"C:\UnlockTool\Temp",
            @"C:\Windows\Temp",
            Directory.GetCurrentDirectory()
        };

        foreach (var dir in commonDirs)
        {
            try
            {
                if (!Directory.Exists(dir)) continue;
                string probe = Path.Combine(dir, fileNameOnly);
                if (File.Exists(probe)) return probe;
            }
            catch { }
        }

        return null;
    }

    private static byte[]? TryReadFileBytesShared(string path)
    {
        for (int i = 0; i < 4; i++)
        {
            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                if (fs.Length <= 0 || fs.Length > 500 * 1024 * 1024) return null;
                byte[] data = new byte[fs.Length];
                int totalRead = 0;
                while (totalRead < data.Length)
                {
                    int read = fs.Read(data, totalRead, data.Length - totalRead);
                    if (read == 0) break;
                    totalRead += read;
                }
                return data;
            }
            catch (IOException)
            {
                Thread.Sleep(20);
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

        if (fullPath.StartsWith(@"C:\Windows\", StringComparison.OrdinalIgnoreCase) &&
            !fullPath.StartsWith(@"C:\Windows\Temp\", StringComparison.OrdinalIgnoreCase))
            return true;

        if (fileName.StartsWith("AslLog_", StringComparison.OrdinalIgnoreCase) ||
            fileName.Equals("CXDUMMYFILE.TXT", StringComparison.OrdinalIgnoreCase) ||
            fileName.Equals("TRUSTPOL.TXT", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".etl", StringComparison.OrdinalIgnoreCase) ||
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
