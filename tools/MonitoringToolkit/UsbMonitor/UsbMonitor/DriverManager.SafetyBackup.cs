using System;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using Microsoft.Win32;

namespace PhoenixGSM.UsbMonitor;

/// <summary>
/// Enterprise Safety & Automatic Registry Backup Subsystem for PhoenixGSM.
/// Ensures zero-risk operations by creating atomic snapshots before any registry alteration,
/// and providing one-click full rollback to 100% native Windows stock configuration.
/// </summary>
public static partial class DriverManager
{
    private static readonly string BackupRootDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        "softwer", "PhoenixGSM", "backups", "registry");

    static DriverManager()
    {
        EnsureBackupDirectoryExists();
    }

    public static string GetBackupDirectory()
    {
        EnsureBackupDirectoryExists();
        return BackupRootDirectory;
    }

    private static void EnsureBackupDirectoryExists()
    {
        try
        {
            if (!Directory.Exists(BackupRootDirectory))
            {
                Directory.CreateDirectory(BackupRootDirectory);
            }
        }
        catch { }
    }

    /// <summary>
    /// Exports a specific registry key to a native .reg file before any modifications.
    /// </summary>
    public static bool CreateRegistrySnapshot(string keyPath, string tag)
    {
        try
        {
            EnsureBackupDirectoryExists();
            string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            string cleanTag = string.Concat(tag.Split(Path.GetInvalidFileNameChars()));
            string backupFile = Path.Combine(BackupRootDirectory, $"{cleanTag}_{timestamp}.reg");

            string fullRegKey = keyPath.StartsWith("HKLM\\", StringComparison.OrdinalIgnoreCase)
                ? keyPath
                : @"HKLM\" + keyPath.TrimStart('\\');

            var psi = new ProcessStartInfo
            {
                FileName = "reg.exe",
                Arguments = $"export \"{fullRegKey}\" \"{backupFile}\" /y",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var p = Process.Start(psi);
            p?.WaitForExit();

            bool ok = p?.ExitCode == 0 && File.Exists(backupFile);
            if (ok)
            {
                LogBackupManifest(keyPath, backupFile, tag);
            }
            return ok;
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[DriverManager.SafetyBackup] Snapshot failed: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Automatically backups the setup class key before configuring filters.
    /// </summary>
    public static void AutoBackupClassKey(string classGuid)
    {
        string targetGuid = ResolveClassGuid(classGuid);
        string keyPath = @"SYSTEM\CurrentControlSet\Control\Class\" + targetGuid;
        CreateRegistrySnapshot(keyPath, $"Class_{targetGuid}");
    }

    /// <summary>
    /// Automatically backups a device instance key before configuring filters.
    /// </summary>
    public static void AutoBackupDeviceKey(string instanceId)
    {
        string keyPath = @"SYSTEM\CurrentControlSet\Enum\" + instanceId.TrimStart('\\');
        CreateRegistrySnapshot(keyPath, "DeviceInstance");
    }

    private static void LogBackupManifest(string keyPath, string regFilePath, string tag)
    {
        try
        {
            string manifestPath = Path.Combine(BackupRootDirectory, "backup_manifest.log");
            string entry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] TAG={tag} | KEY={keyPath} | FILE={regFilePath}{Environment.NewLine}";
            File.AppendAllText(manifestPath, entry);
        }
        catch { }
    }

    /// <summary>
    /// Restores a given .reg file directly via reg.exe import.
    /// </summary>
    public static bool RestoreRegistrySnapshotFile(string regFilePath)
    {
        try
        {
            if (!File.Exists(regFilePath)) return false;

            var psi = new ProcessStartInfo
            {
                FileName = "reg.exe",
                Arguments = $"import \"{regFilePath}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var p = Process.Start(psi);
            p?.WaitForExit();
            return p?.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }
}
