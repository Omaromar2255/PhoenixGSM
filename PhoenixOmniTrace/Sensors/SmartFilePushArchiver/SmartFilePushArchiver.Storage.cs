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
    /// Dedicated background worker loop:
    /// 1. Checks _recentCliPushByTarget (populated from `adb push &lt;local&gt; &lt;remote&gt;`) first so CMD pushes are 100% full size.
    /// 2. Recovers full files from Host Disk (including CMD/PowerShell/ADB PEB working directories) and Process RAM.
    /// </summary>
    private async Task ProcessArchiveJobsLoopAsync(CancellationToken token)
    {
        await foreach (var job in _jobChannel.Reader.ReadAllAsync(token))
        {
            try
            {
                string fileName = Path.GetFileName(job.TargetPath);
                if (string.IsNullOrWhiteSpace(fileName) || IsIgnoredNoiseFile(fileName)) continue;

                byte[] wireBytes = job.WireBytes ?? [];
                byte[] bestBytes = wireBytes;
                string bestVector = "USB Wire Stream";

                byte[]? verifyPrefix = wireBytes.Length > 0
                    ? wireBytes[..Math.Min(wireBytes.Length, 256)]
                    : job.HeaderSignature;

                // 0. Check if we already captured the exact local source file from an `adb push <local> <remote>` CLI command!
                byte[]? cliPushBytes = TryGetRecentCliPushBytes(job.TargetPath, fileName, verifyPrefix);
                if (cliPushBytes != null && cliPushBytes.Length >= bestBytes.Length)
                {
                    bestBytes = cliPushBytes;
                    bestVector = "Host CLI Push Snapshot (Full Original)";
                }

                // Wire is only complete on its own for tiny single-packet files (< 1KB) where no URB truncation occurred
                bool wireIsCompleteExact = !job.HadTruncatedUrb &&
                                           job.KernelDroppedDelta == 0 &&
                                           job.DataBlockCount <= 1 &&
                                           wireBytes.Length > 0 &&
                                           job.TotalDeclaredBytes > 0 &&
                                           wireBytes.Length == job.TotalDeclaredBytes;

                bool isCompleteCapture = wireIsCompleteExact || (cliPushBytes != null && cliPushBytes.Length > 0);

                if (wireIsCompleteExact)
                {
                    byte[]? diskExact = TryRecoverFromHostDisk(fileName, verifyPrefix);
                    if (diskExact != null && diskExact.Length >= bestBytes.Length &&
                        IsCandidateMatchingPrefix(diskExact, verifyPrefix))
                    {
                        bestBytes = diskExact;
                        bestVector = "Host Disk Snapshot";
                    }
                }
                else if (cliPushBytes == null)
                {
                    // 1. Check Eager Mid-Transfer Snapshot (taken at the exact millisecond the first DATA packet arrived)
                    if (job.EagerSnapshotTask != null)
                    {
                        try
                        {
                            byte[]? eagerBytes = await job.EagerSnapshotTask.ConfigureAwait(false);
                            if (eagerBytes != null && eagerBytes.Length > bestBytes.Length &&
                                IsCandidateMatchingPrefix(eagerBytes, verifyPrefix))
                            {
                                bestBytes = eagerBytes;
                                bestVector = "Eager Mid-Transfer RAM/Disk Snapshot";
                                isCompleteCapture = true;
                            }
                        }
                        catch { }
                    }

                    // Use TotalDeclaredBytes (never TotalActualUrbBytes, which includes SEND/DATA/DONE USB headers!)
                    long expectedFileSize = job.TotalDeclaredBytes > 0
                        ? job.TotalDeclaredBytes
                        : wireBytes.Length;

                    // 2. Run Host Disk (including CMD/ADB PEB CurrentDirectory) + Target Process RAM carving in parallel
                    var diskTask = Task.Run(() => TryRecoverFromHostDisk(fileName, verifyPrefix), token);
                    var ramTask = Task.Run(() => TryCarveFileFromTargetProcessRam(verifyPrefix, expectedFileSize), token);

                    await Task.WhenAll(diskTask, ramTask).ConfigureAwait(false);

                    byte[]? diskBytes = diskTask.Result;
                    byte[]? ramBytes = ramTask.Result;

                    if (diskBytes != null && diskBytes.Length >= bestBytes.Length &&
                        IsCandidateMatchingPrefix(diskBytes, verifyPrefix))
                    {
                        bestBytes = diskBytes;
                        bestVector = "Host Disk Snapshot";
                        isCompleteCapture = true;
                    }

                    if (ramBytes != null && ramBytes.Length > bestBytes.Length &&
                        IsCandidateMatchingPrefix(ramBytes, verifyPrefix))
                    {
                        bool ramZipValid = !IsZipHeader(ramBytes) || HasValidZipEocd(ramBytes);
                        if (ramZipValid || !isCompleteCapture)
                        {
                            bestBytes = ramBytes;
                            bestVector = "Process RAM Carve (Passive)";
                            isCompleteCapture = true;
                        }
                    }
                }

                if (bestBytes.Length == 0)
                {
                    continue;
                }

                // If NotifyAdbPushCommandLine already saved this exact transfer < 2 seconds ago at full size, avoid duplicate save
                if (_latestInstanceByPath.TryGetValue(job.TargetPath, out var recentSaved) &&
                    recentSaved.FileSize >= bestBytes.Length &&
                    File.Exists(recentSaved.LocalSavedPath) &&
                    (DateTime.UtcNow - File.GetLastWriteTimeUtc(recentSaved.LocalSavedPath)).TotalSeconds < 1.5 &&
                    job.UploadSequenceNumber > 1 &&
                    recentSaved.UploadNumber == job.UploadSequenceNumber)
                {
                    continue;
                }

                if (_savedTransfersById.TryGetValue(job.TransferSequenceId, out var existingTransfer) &&
                    bestBytes.Length <= existingTransfer.SavedSize &&
                    existingTransfer.IsComplete)
                {
                    continue;
                }

                string sessionDir = !string.IsNullOrWhiteSpace(job.SessionDirectory)
                    ? job.SessionDirectory
                    : CurrentSessionDirectory;
                string sessionFolder = !string.IsNullOrWhiteSpace(job.SessionFolderName)
                    ? job.SessionFolderName
                    : CurrentSessionFolderName;

                var savedRecord = SaveSingleCleanFileToDisk(
                    bestBytes,
                    job.TargetPath,
                    job.Mode,
                    bestVector,
                    sessionDir,
                    sessionFolder,
                    job.UploadSequenceNumber,
                    job.TransferSequenceId,
                    isCompleteCapture,
                    job.TotalDeclaredBytes,
                    job.KernelDroppedDelta);

                if (savedRecord != null)
                {
                    _savedTransfersById[job.TransferSequenceId] = (
                        savedRecord.LocalSavedPath,
                        savedRecord.SavedFileName,
                        savedRecord.FileSizeBytes,
                        savedRecord.UploadSequenceNumber,
                        savedRecord.IsCompleteCapture);

                    _latestInstanceByPath[job.TargetPath] = (
                        savedRecord.SavedFileName,
                        savedRecord.UploadSequenceNumber,
                        savedRecord.FileSizeBytes,
                        savedRecord.LocalSavedPath);

                    OnFileArchivedAsync?.Invoke(savedRecord, job.EndpointHex);
                }
            }
            catch { }
        }
    }

    private byte[]? TryGetRecentCliPushBytes(string targetPath, string fileName, byte[]? verifyPrefix)
    {
        DateTime cutoff = DateTime.UtcNow.AddSeconds(-30);
        if (!string.IsNullOrWhiteSpace(targetPath) &&
            _recentCliPushByTarget.TryGetValue(targetPath, out var byTarget) &&
            byTarget.CapturedAtUtc >= cutoff &&
            IsCandidateMatchingPrefix(byTarget.FileBytes, verifyPrefix))
        {
            return byTarget.FileBytes;
        }

        if (!string.IsNullOrWhiteSpace(fileName) &&
            _recentCliPushByTarget.TryGetValue(fileName, out var byName) &&
            byName.CapturedAtUtc >= cutoff &&
            IsCandidateMatchingPrefix(byName.FileBytes, verifyPrefix))
        {
            return byName.FileBytes;
        }

        return null;
    }

    private static bool IsCandidateMatchingPrefix(byte[]? candidate, byte[]? verifyPrefix)
    {
        if (candidate == null || candidate.Length == 0) return false;
        if (verifyPrefix == null || verifyPrefix.Length == 0) return true;

        int checkLen = Math.Min(Math.Min(verifyPrefix.Length, candidate.Length), 64);
        return candidate.AsSpan(0, checkLen).SequenceEqual(verifyPrefix.AsSpan(0, checkLen));
    }

    private static bool IsZipHeader(ReadOnlySpan<byte> data)
    {
        return data.Length >= 4 &&
               data[0] == 0x50 && data[1] == 0x4B && data[2] == 0x03 && data[3] == 0x04;
    }

    public static bool HasValidZipEocd(ReadOnlySpan<byte> data)
    {
        if (data.Length < 22) return false;
        int minSearch = Math.Max(0, data.Length - 65558);
        for (int i = data.Length - 22; i >= minSearch; i--)
        {
            if (data[i] == 0x50 && data[i + 1] == 0x4B && data[i + 2] == 0x05 && data[i + 3] == 0x06)
            {
                uint cdSize = BitConverter.ToUInt32(data.Slice(i + 12, 4));
                uint cdOffset = BitConverter.ToUInt32(data.Slice(i + 16, 4));
                if (cdOffset + cdSize <= (ulong)i)
                {
                    return true;
                }
            }
        }
        return false;
    }

    public static CapturedPushedFileRecord? SaveSingleCleanFileToDisk(
        byte[] fileBytes,
        string targetPath,
        string mode,
        string captureVector,
        string? sessionDirectory = null,
        string? sessionFolderName = null,
        int uploadSequenceNumber = 1,
        long transferSequenceId = 0,
        bool isCompleteCapture = true,
        long declaredSize = 0,
        long kernelDroppedDelta = 0)
    {
        if (fileBytes == null || fileBytes.Length == 0) return null;

        string fname = Path.GetFileName(targetPath);
        if (string.IsNullOrWhiteSpace(fname) || IsIgnoredNoiseFile(fname)) return null;

        string artifactsDir = !string.IsNullOrWhiteSpace(sessionDirectory)
            ? sessionDirectory
            : Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "CapturedArtifacts");

        string folderDisplayName = !string.IsNullOrWhiteSpace(sessionFolderName)
            ? $"CapturedArtifacts/{sessionFolderName}"
            : "CapturedArtifacts";

        string numberedFileName;
        string savedFilePath;

        lock (_diskWriteLock)
        {
            try
            {
                Directory.CreateDirectory(artifactsDir);

                int seq = Math.Max(1, uploadSequenceNumber);
                numberedFileName = BuildNumberedFileName(fname, seq);
                savedFilePath = Path.Combine(artifactsDir, numberedFileName);

                while (File.Exists(savedFilePath) && uploadSequenceNumber <= 1 && transferSequenceId == 0)
                {
                    seq++;
                    numberedFileName = BuildNumberedFileName(fname, seq);
                    savedFilePath = Path.Combine(artifactsDir, numberedFileName);
                }

                string tempWritePath = savedFilePath + $".{Guid.NewGuid():N}.tmp_write";
                using (var fs = new FileStream(tempWritePath, FileMode.Create, FileAccess.Write, FileShare.None, 65536, FileOptions.WriteThrough))
                {
                    fs.Write(fileBytes, 0, fileBytes.Length);
                    fs.Flush(flushToDisk: true);
                }

                File.Move(tempWritePath, savedFilePath, overwrite: true);
            }
            catch
            {
                return null;
            }
        }

        string sha256 = Convert.ToHexString(SHA256.HashData(fileBytes));
        string md5 = Convert.ToHexString(MD5.HashData(fileBytes));
        var classification = SmartContentClassifier.Classify(fileBytes);

        string instanceTag = uploadSequenceNumber > 1 ? $" [Upload #{uploadSequenceNumber}]" : string.Empty;
        string statusBadge = isCompleteCapture ? "Completed" : "Saved";
        string summary = $"[ADB-PUSH]{instanceTag} {statusBadge}: {targetPath} -> {folderDisplayName}/{numberedFileName} ({fileBytes.Length:N0} bytes | {classification.Description} | {captureVector})";

        return new CapturedPushedFileRecord
        {
            TargetDevicePath = targetPath,
            FileName = fname,
            SavedFileName = numberedFileName,
            UploadSequenceNumber = Math.Max(1, uploadSequenceNumber),
            TransferSequenceId = transferSequenceId,
            SessionFolderName = sessionFolderName ?? string.Empty,
            FilePermissionMode = mode,
            LocalSavedPath = savedFilePath,
            FileBytes = fileBytes,
            FileSizeBytes = fileBytes.Length,
            DeclaredDataSize = declaredSize > 0 ? declaredSize : fileBytes.Length,
            IsCompleteCapture = isCompleteCapture,
            KernelPacketsDroppedDelta = kernelDroppedDelta,
            Sha256 = sha256,
            Md5 = md5,
            FileClassification = classification.Classification,
            MagicDescription = classification.Description,
            IsExecutableOrExploit = classification.IsExecutableOrExploit,
            CaptureVector = captureVector,
            Timestamp = DateTime.UtcNow,
            Summary = summary,
            AdditionalDetails = $"Status: {statusBadge}\nTarget Path: {targetPath}\nUpload Instance: #{Math.Max(1, uploadSequenceNumber)} ({numberedFileName})\nSession Folder: {folderDisplayName}\nMode: {mode}\nSaved Bytes: {fileBytes.Length:N0}\nDeclared Wire Bytes: {declaredSize:N0}\nFormat: {classification.Description}\nSHA-256: {sha256}\nMD5: {md5}\nVector: {captureVector}\nSaved File: {savedFilePath}"
        };
    }
}
