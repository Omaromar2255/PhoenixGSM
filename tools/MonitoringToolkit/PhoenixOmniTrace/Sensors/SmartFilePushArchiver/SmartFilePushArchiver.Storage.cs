using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using PhoenixGSM.OmniTrace.Decoders;

namespace PhoenixGSM.OmniTrace.Sensors;

public sealed partial class SmartFilePushArchiver
{
    /// <summary>
    /// Dedicated background worker loop: saves small non-truncated files (e.g. 72-byte ASKSW.xml)
    /// directly from WireBytes or Host Disk, and recovers truncated large files from Host Disk + Process RAM.
    /// </summary>
    private async Task ProcessArchiveJobsLoopAsync(CancellationToken token)
    {
        await foreach (var job in _jobChannel.Reader.ReadAllAsync(token))
        {
            try
            {
                string fileName = Path.GetFileName(job.TargetPath);
                if (string.IsNullOrWhiteSpace(fileName) || IsIgnoredNoiseFile(fileName)) continue;

                long existingSavedSize = _savedFileSizesByPath.TryGetValue(job.TargetPath, out long s) ? s : 0;

                byte[] bestBytes = job.WireBytes ?? [];
                string bestVector = "USB Wire Stream";

                // If the wire capture was NOT truncated and matches the exact declared DATA size (e.g. 72-byte ASKSW.xml),
                // wireBytes is already 100% complete! Only check Host Disk for an exact match, never overwrite with oversized RAM!
                bool wireIsCompleteExact = !job.HadTruncatedUrb &&
                                           bestBytes.Length > 0 &&
                                           (job.TotalDeclaredBytes <= 0 || bestBytes.Length == job.TotalDeclaredBytes);

                if (wireIsCompleteExact)
                {
                    byte[]? diskExact = TryRecoverFromHostDisk(fileName, job.HeaderSignature);
                    if (diskExact != null && diskExact.Length >= bestBytes.Length)
                    {
                        bestBytes = diskExact;
                        bestVector = "Host Disk Snapshot";
                    }
                }
                else
                {
                    // 1. Check Eager Mid-Transfer Snapshot first
                    if (job.EagerSnapshotTask != null)
                    {
                        try
                        {
                            byte[]? eagerBytes = await job.EagerSnapshotTask.ConfigureAwait(false);
                            if (eagerBytes != null && eagerBytes.Length > bestBytes.Length)
                            {
                                bestBytes = eagerBytes;
                                bestVector = "Eager Mid-Transfer RAM/Disk Snapshot";
                            }
                        }
                        catch { }
                    }

                    long expectedSize = job.TotalDeclaredBytes > 0
                        ? job.TotalDeclaredBytes
                        : job.TotalActualUrbBytes;

                    bool needsFullRecovery = job.HadTruncatedUrb ||
                                             bestBytes.Length == 0 ||
                                             (job.TotalDeclaredBytes > bestBytes.Length);

                    // 2. Run Host Disk + 64-bit/32-bit Target Process RAM carving in parallel
                    if (needsFullRecovery && (expectedSize == 0 || bestBytes.Length < expectedSize))
                    {
                        var diskTask = Task.Run(() => TryRecoverFromHostDisk(fileName, job.HeaderSignature), token);
                        var ramTask = Task.Run(() => TryCarveFileFromTargetProcessRam(job.HeaderSignature, expectedSize), token);

                        await Task.WhenAll(diskTask, ramTask).ConfigureAwait(false);

                        byte[]? diskBytes = diskTask.Result;
                        byte[]? ramBytes = ramTask.Result;

                        if (diskBytes != null && diskBytes.Length > bestBytes.Length)
                        {
                            bestBytes = diskBytes;
                            bestVector = "Host Disk Snapshot";
                        }
                        if (ramBytes != null && ramBytes.Length > bestBytes.Length)
                        {
                            bestBytes = ramBytes;
                            bestVector = "Process RAM Carve (Passive)";
                        }
                    }
                }

                // Allow saving any non-empty file >= 1 byte (including 72-byte ASKSW.xml and tiny trustedTime files!)
                if (bestBytes.Length == 0 || bestBytes.Length <= existingSavedSize)
                {
                    continue;
                }

                var savedRecord = SaveSingleCleanFileToDisk(bestBytes, job.TargetPath, job.Mode, bestVector);
                if (savedRecord != null)
                {
                    _savedFileSizesByPath[job.TargetPath] = bestBytes.Length;
                    OnFileArchivedAsync?.Invoke(savedRecord, job.EndpointHex);
                }
            }
            catch { }
        }
    }

    /// <summary>
    /// Strictly saves ONLY ONE file per pushed artifact using its exact original filename.
    /// Supports files of any size >= 1 byte (including 72-byte ASKSW.xml).
    /// </summary>
    public static CapturedPushedFileRecord? SaveSingleCleanFileToDisk(
        byte[] fileBytes,
        string targetPath,
        string mode,
        string captureVector)
    {
        if (fileBytes == null || fileBytes.Length == 0) return null;

        string fname = Path.GetFileName(targetPath);
        if (string.IsNullOrWhiteSpace(fname) || IsIgnoredNoiseFile(fname)) return null;

        string artifactsDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "CapturedArtifacts");
        try
        {
            Directory.CreateDirectory(artifactsDir);
        }
        catch { }

        string originalSavedPath = Path.Combine(artifactsDir, fname);
        try
        {
            if (File.Exists(originalSavedPath))
            {
                long existingLen = new FileInfo(originalSavedPath).Length;
                if (fileBytes.Length < existingLen)
                {
                    fileBytes = File.ReadAllBytes(originalSavedPath);
                }
                else
                {
                    File.WriteAllBytes(originalSavedPath, fileBytes);
                }
            }
            else
            {
                File.WriteAllBytes(originalSavedPath, fileBytes);
            }
        }
        catch { }

        string sha256 = Convert.ToHexString(SHA256.HashData(fileBytes));
        string md5 = Convert.ToHexString(MD5.HashData(fileBytes));
        var classification = SmartContentClassifier.Classify(fileBytes);

        string summary = $"[ADB-PUSH] Saved: {targetPath} -> CapturedArtifacts/{fname} ({fileBytes.Length:N0} bytes | {classification.Description} | {captureVector})";

        return new CapturedPushedFileRecord
        {
            TargetDevicePath = targetPath,
            FileName = fname,
            FilePermissionMode = mode,
            LocalSavedPath = originalSavedPath,
            FileBytes = fileBytes,
            FileSizeBytes = fileBytes.Length,
            DeclaredDataSize = fileBytes.Length,
            Sha256 = sha256,
            Md5 = md5,
            FileClassification = classification.Classification,
            MagicDescription = classification.Description,
            IsExecutableOrExploit = classification.IsExecutableOrExploit,
            CaptureVector = captureVector,
            Timestamp = DateTime.UtcNow,
            Summary = summary,
            AdditionalDetails = $"Target Path: {targetPath}\nMode: {mode}\nTotal Bytes: {fileBytes.Length:N0}\nFormat: {classification.Description}\nSHA-256: {sha256}\nVector: {captureVector}\nSaved File: {originalSavedPath}"
        };
    }
}
