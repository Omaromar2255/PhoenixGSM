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
/// LAYER 12B — Content-Addressable Artifact Vault & Storage Manager
/// Securely stores, classifies, and indexes pushed files and exploit payloads with SHA-256 deduplication.
/// Generates JSON forensics manifests and provides micro-retry snapshotting before tools delete staged files.
/// </summary>
public sealed class AdbPushArtifactVault
{
    public const long DefaultMaxFullCaptureBytes = 64 * 1024 * 1024; // 64 MB full dump limit
    public const int MaxHeaderDumpBytes = 4 * 1024 * 1024; // 4 MB header dump for gigantic partitions

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

    /// <summary>
    /// Captures a local file from host disk (e.g. from an intercepted "adb push <local> <remote>" command)
    /// using micro-retry with non-exclusive FileShare permissions before the tool can delete it.
    /// </summary>
    public PushedArtifactInfo? TryCaptureLocalFile(
        string localPath,
        string targetDevicePath,
        string processName,
        int pid,
        string deviceSerial = "",
        Dictionary<string, string>? extraAttrs = null)
    {
        if (string.IsNullOrWhiteSpace(localPath)) return null;

        // Clean quotes or whitespace around path
        localPath = localPath.Trim(' ', '"', '\'');
        if (!File.Exists(localPath)) return null;

        byte[]? fileBytes = ReadFileWithMicroRetry(localPath, maxRetries: 5, delayMs: 15);
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

    /// <summary>
    /// Stores an artifact from byte content (used by in-flight ADB wire sync stream reassembly or memory buffers).
    /// </summary>
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

        // 1. Compute Cryptographic Hashes
        string sha256 = Convert.ToHexString(SHA256.HashData(content));
        string md5 = Convert.ToHexString(MD5.HashData(content));

        // 2. Classify content with SmartContentClassifier
        var classification = SmartContentClassifier.Classify(content);

        // 3. Deduplication Check via SHA-256
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

        // 4. Determine file persistence paths
        string fileStorageName = $"{sha256[..16]}_{safeFileName}";
        string vaultFilePath = Path.Combine(_vaultDirectory, fileStorageName);
        string manifestPath = Path.Combine(_vaultDirectory, $"{fileStorageName}.manifest.json");

        // 5. Write Physical File (with size limit tiering)
        try
        {
            if (content.Length <= _maxFullCaptureBytes)
            {
                File.WriteAllBytes(vaultFilePath, content);
            }
            else
            {
                // Large partition image: store header chunk
                vaultFilePath += ".head.bin";
                byte[] headChunk = new byte[Math.Min(content.Length, MaxHeaderDumpBytes)];
                Array.Copy(content, headChunk, headChunk.Length);
                File.WriteAllBytes(vaultFilePath, headChunk);
            }
        }
        catch { }

        // 6. Build Manifest Model
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

        // 7. Write JSON Manifest
        try
        {
            File.WriteAllText(manifestPath, info.ToJson());
        }
        catch { }

        // 8. Update Metrics and Cache
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

    private static byte[]? ReadFileWithMicroRetry(string path, int maxRetries, int delayMs)
    {
        for (int i = 0; i < maxRetries; i++)
        {
            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var ms = new MemoryStream();
                fs.CopyTo(ms);
                return ms.ToArray();
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
