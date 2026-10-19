using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Threading;
using PhoenixGSM.OmniTrace.Decoders;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.Sensors;

/// <summary>
/// LAYER 12B — Content-Addressable Artifact Vault &amp; Storage Manager
/// Waits for file size stability before reading local staged files, and uses atomic writes to persist artifacts.
/// </summary>
public sealed class AdbPushArtifactVault
{
    public const long DefaultMaxFullCaptureBytes = 64 * 1024 * 1024;
    public const int MaxHeaderDumpBytes = 4 * 1024 * 1024;

    private static readonly Regex InvalidCharsRegex = new(@"[^\w\.\-\+]", RegexOptions.Compiled);

    private readonly string _vaultDirectory;
    private readonly long _maxFullCaptureBytes;
    private readonly ConcurrentDictionary<string, PushedArtifactInfo> _artifactsBySha256 = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<PushedArtifactInfo> _allArtifacts = [];
    private readonly object _lock = new();

    private long _totalArtifactsCaptured;
    private long _totalBytesSaved;
    private long _deduplicatedCount;

    public string VaultDirectory => _vaultDirectory;
    public long TotalArtifactsCaptured => Interlocked.Read(ref _totalArtifactsCaptured);
    public long TotalBytesSaved => Interlocked.Read(ref _totalBytesSaved);
    public long DeduplicatedCount => Interlocked.Read(ref _deduplicatedCount);

    public AdbPushArtifactVault(string? customVaultDir = null, long maxFullCaptureBytes = DefaultMaxFullCaptureBytes)
    {
        _maxFullCaptureBytes = maxFullCaptureBytes;
        if (!string.IsNullOrWhiteSpace(customVaultDir))
        {
            _vaultDirectory = customVaultDir;
        }
        else
        {
            string localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            _vaultDirectory = Path.Combine(localApp, "PhoenixGSM", "Artifacts", "PushedFiles");
        }

        try
        {
            if (!Directory.Exists(_vaultDirectory))
            {
                Directory.CreateDirectory(_vaultDirectory);
            }
        }
        catch { }
    }

    public PushedArtifactInfo? TryCaptureLocalFile(
        string localPath,
        string targetDevicePath,
        string processName,
        int pid,
        string deviceSerial = "",
        Dictionary<string, string>? extraAttrs = null)
    {
        if (string.IsNullOrWhiteSpace(localPath)) return null;

        localPath = localPath.Trim(' ', '"', '\'');
        if (!File.Exists(localPath)) return null;

        byte[]? fileBytes = ReadStableFileWithRetry(localPath, maxRetries: 8, delayMs: 40);
        if (fileBytes == null || fileBytes.Length == 0) return null;

        string fileName = Path.GetFileName(localPath);
        if (string.IsNullOrWhiteSpace(fileName))
        {
            fileName = Path.GetFileName(targetDevicePath);
            if (string.IsNullOrWhiteSpace(fileName)) fileName = "pushed_file.bin";
        }

        return StoreArtifact(
            content: fileBytes,
            fileName: fileName,
            targetDevicePath: targetDevicePath,
            processName: processName,
            pid: pid,
            sourceVector: "HostPrePush",
            localSourcePath: localPath,
            deviceSerial: deviceSerial,
            extraAttrs: extraAttrs
        );
    }

    public PushedArtifactInfo StoreArtifact(
        byte[] content,
        string fileName,
        string targetDevicePath,
        string processName,
        int pid,
        string sourceVector,
        string? localSourcePath = null,
        string deviceSerial = "",
        Dictionary<string, string>? extraAttrs = null)
    {
        content ??= [];
        if (string.IsNullOrWhiteSpace(fileName)) fileName = "pushed_artifact.bin";
        string safeFileName = SanitizeFileName(fileName);

        string sha256 = Convert.ToHexString(SHA256.HashData(content));
        string md5 = Convert.ToHexString(MD5.HashData(content));
        var classification = SmartContentClassifier.Classify(content);

        if (_artifactsBySha256.TryGetValue(sha256, out var existing))
        {
            Interlocked.Increment(ref _deduplicatedCount);
            var dedupCopy = new PushedArtifactInfo
            {
                ArtifactId = Guid.NewGuid().ToString("N"),
                FileName = fileName,
                TargetDevicePath = targetDevicePath,
                LocalSourcePath = localSourcePath ?? existing.LocalSourcePath,
                VaultFilePath = existing.VaultFilePath,
                VaultManifestPath = existing.VaultManifestPath,
                FileSizeBytes = content.Length,
                Sha256 = sha256,
                Md5 = md5,
                FileClassification = classification.Classification,
                MagicDescription = classification.Description,
                IsExecutableOrExploit = classification.IsExecutableOrExploit,
                SourceVector = sourceVector,
                ProcessName = processName,
                ProcessId = pid,
                DeviceSerial = deviceSerial,
                Timestamp = DateTime.UtcNow,
                IsDeduplicated = true,
                RawBytes = content
            };

            if (extraAttrs != null)
            {
                foreach (var kvp in extraAttrs) dedupCopy.Attributes[kvp.Key] = kvp.Value;
            }

            lock (_lock)
            {
                _allArtifacts.Add(dedupCopy);
            }
            return dedupCopy;
        }

        string fileStorageName = $"{sha256[..16]}_{safeFileName}";
        string vaultFilePath = Path.Combine(_vaultDirectory, fileStorageName);
        string manifestPath = Path.Combine(_vaultDirectory, $"{fileStorageName}.manifest.json");

        try
        {
            Directory.CreateDirectory(_vaultDirectory);
            byte[] toWrite = content;
            if (content.Length > _maxFullCaptureBytes)
            {
                vaultFilePath += ".head.bin";
                toWrite = new byte[Math.Min(content.Length, MaxHeaderDumpBytes)];
                Array.Copy(content, toWrite, toWrite.Length);
            }

            string tmpPath = vaultFilePath + $".{Guid.NewGuid():N}.tmp";
            File.WriteAllBytes(tmpPath, toWrite);
            File.Move(tmpPath, vaultFilePath, overwrite: true);
        }
        catch { }

        var info = new PushedArtifactInfo
        {
            ArtifactId = Guid.NewGuid().ToString("N"),
            FileName = fileName,
            TargetDevicePath = targetDevicePath,
            LocalSourcePath = localSourcePath ?? string.Empty,
            VaultFilePath = vaultFilePath,
            VaultManifestPath = manifestPath,
            FileSizeBytes = content.Length,
            Sha256 = sha256,
            Md5 = md5,
            FileClassification = classification.Classification,
            MagicDescription = classification.Description,
            IsExecutableOrExploit = classification.IsExecutableOrExploit,
            SourceVector = sourceVector,
            ProcessName = processName,
            ProcessId = pid,
            DeviceSerial = deviceSerial,
            Timestamp = DateTime.UtcNow,
            IsDeduplicated = false,
            RawBytes = content
        };

        if (extraAttrs != null)
        {
            foreach (var kvp in extraAttrs) info.Attributes[kvp.Key] = kvp.Value;
        }

        try
        {
            File.WriteAllText(manifestPath, info.ToJson());
        }
        catch { }

        Interlocked.Increment(ref _totalArtifactsCaptured);
        Interlocked.Add(ref _totalBytesSaved, content.Length);
        _artifactsBySha256[sha256] = info;

        lock (_lock)
        {
            _allArtifacts.Add(info);
        }

        return info;
    }

    public IReadOnlyList<PushedArtifactInfo> GetAllArtifacts()
    {
        lock (_lock)
        {
            return _allArtifacts.ToArray();
        }
    }

    public PushedArtifactInfo? GetArtifactBySha256(string sha256)
    {
        _artifactsBySha256.TryGetValue(sha256, out var info);
        return info;
    }

    /// <summary>
    /// Ensures the file size has stabilized across consecutive checks (and has valid EOCD if ZIP)
    /// before reading, preventing partial captures while a tool is still writing to disk.
    /// </summary>
    private static byte[]? ReadStableFileWithRetry(string path, int maxRetries, int delayMs)
    {
        long lastSeenLength = -1;
        for (int i = 0; i < maxRetries; i++)
        {
            try
            {
                var fi = new FileInfo(path);
                if (!fi.Exists) return null;
                if (fi.Length == 0 || fi.Length != lastSeenLength)
                {
                    lastSeenLength = fi.Length;
                    Thread.Sleep(delayMs);
                    continue;
                }

                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                if (fs.Length != lastSeenLength || fs.Length == 0)
                {
                    lastSeenLength = fs.Length;
                    Thread.Sleep(delayMs);
                    continue;
                }

                byte[] data = new byte[fs.Length];
                int read = 0;
                while (read < data.Length)
                {
                    int r = fs.Read(data, read, data.Length - read);
                    if (r <= 0) break;
                    read += r;
                }

                if (read != data.Length)
                {
                    Thread.Sleep(delayMs);
                    continue;
                }

                if (data.Length >= 4 && data[0] == 0x50 && data[1] == 0x4B && data[2] == 0x03 && data[3] == 0x04)
                {
                    if (!SmartFilePushArchiver.HasValidZipEocd(data) && i < maxRetries - 1)
                    {
                        Thread.Sleep(delayMs * 2);
                        continue;
                    }
                }

                return data;
            }
            catch (IOException)
            {
                Thread.Sleep(delayMs * (i + 1));
            }
            catch (UnauthorizedAccessException)
            {
                Thread.Sleep(delayMs * (i + 1));
            }
            catch
            {
                return null;
            }
        }
        return null;
    }

    private static string SanitizeFileName(string name)
    {
        string safe = InvalidCharsRegex.Replace(name, "_");
        if (safe.Length > 64) safe = safe[..64];
        return string.IsNullOrWhiteSpace(safe) ? "artifact.bin" : safe;
    }
}
