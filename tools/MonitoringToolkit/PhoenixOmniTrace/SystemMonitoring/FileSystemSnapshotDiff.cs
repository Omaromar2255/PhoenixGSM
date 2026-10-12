using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace PhoenixGSM.OmniTrace.SystemMonitoring;

public class FileSystemSnapshot
{
    // مسار الملف كـمفتاح، الخصائص كـقيمة / Path as key, Hash/Size as value
    public Dictionary<string, (long Size, string Hash)> Files { get; set; } = new();
}

public class FileSystemDiff
{
    public List<string> AddedFiles { get; set; } = new();
    public List<string> DeletedFiles { get; set; } = new();
    public List<string> ModifiedFiles { get; set; } = new();
}

public class FileSystemSnapshotDiff : IDisposable
{
    /// <summary>
    /// أخذ لقطة للملفات / Take file system snapshot
    /// </summary>
    public FileSystemSnapshot TakeSnapshot(string directoryPath)
    {
        var snapshot = new FileSystemSnapshot();
        try
        {
            if (Directory.Exists(directoryPath))
            {
                foreach (var file in Directory.EnumerateFiles(directoryPath, "*.*", SearchOption.TopDirectoryOnly))
                {
                    var fileInfo = new FileInfo(file);
                    string hash = ComputeSha256(file);
                    snapshot.Files[file] = (fileInfo.Length, hash);
                }
            }
        }
        catch (Exception ex)
        {
            // Fail-open
            Console.WriteLine($"[FileSystemSnapshotDiff] TakeSnapshot Error: {ex.Message}");
        }
        return snapshot;
    }

    /// <summary>
    /// مقارنة الملفات / Compare snapshots
    /// </summary>
    public FileSystemDiff CompareSnapshots(FileSystemSnapshot before, FileSystemSnapshot after)
    {
        var diff = new FileSystemDiff();
        try
        {
            foreach (var kvp in after.Files)
            {
                if (!before.Files.ContainsKey(kvp.Key))
                {
                    diff.AddedFiles.Add(kvp.Key);
                }
                else if (before.Files[kvp.Key].Hash != kvp.Value.Hash)
                {
                    diff.ModifiedFiles.Add(kvp.Key);
                }
            }

            foreach (var key in before.Files.Keys)
            {
                if (!after.Files.ContainsKey(key))
                {
                    diff.DeletedFiles.Add(key);
                }
            }
        }
        catch (Exception ex)
        {
            // Fail-open
            Console.WriteLine($"[FileSystemSnapshotDiff] CompareSnapshots Error: {ex.Message}");
        }
        return diff;
    }

    private string ComputeSha256(string filePath)
    {
        try
        {
            using var sha256 = SHA256.Create();
            using var stream = File.OpenRead(filePath);
            var hash = sha256.ComputeHash(stream);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }
        catch
        {
            return string.Empty;
        }
    }

    public void Dispose()
    {
        // Cleanup
    }
}
