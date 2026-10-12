using System;
using System.IO;

namespace PhoenixGSM.OmniTrace.Rollback;

/// <summary>
/// Tracks a file creation/modification.
/// يتتبع إنشاء أو تعديل الملفات.
/// </summary>
public class FileChange : ISystemChange
{
    public string ChangeId { get; } = Guid.NewGuid().ToString();
    public string Description { get; }
    public DateTimeOffset Timestamp { get; } = DateTimeOffset.UtcNow;
    public bool IsApplied { get; private set; }

    private readonly string _filePath;
    private readonly string _newContent;
    private string? _backupPath;
    private bool _wasNew;

    public FileChange(string filePath, string newContent, string description)
    {
        _filePath = filePath;
        _newContent = newContent;
        Description = description;
    }

    public bool Apply()
    {
        try
        {
            _wasNew = !File.Exists(_filePath);
            if (!_wasNew)
            {
                // Create backup. إنشاء نسخة احتياطية
                string tempDir = Path.Combine(Path.GetTempPath(), "PhoenixOmniTrace_Backups", Guid.NewGuid().ToString());
                Directory.CreateDirectory(tempDir);
                _backupPath = Path.Combine(tempDir, Path.GetFileName(_filePath));
                File.Copy(_filePath, _backupPath, overwrite: true);
            }

            string? dir = Path.GetDirectoryName(_filePath);
            if (!string.IsNullOrEmpty(dir))
            {
                Directory.CreateDirectory(dir);
            }

            File.WriteAllText(_filePath, _newContent);
            IsApplied = true;
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[FileChange] Apply failed: {ex.Message}");
            return false;
        }
    }

    public bool Revert()
    {
        if (!IsApplied) return true;

        try
        {
            if (_wasNew)
            {
                if (File.Exists(_filePath))
                {
                    File.Delete(_filePath);
                }
            }
            else if (_backupPath != null && File.Exists(_backupPath))
            {
                File.Copy(_backupPath, _filePath, overwrite: true);
                File.Delete(_backupPath); // Cleanup backup. حذف النسخة الاحتياطية
            }
            IsApplied = false;
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[FileChange] Revert failed: {ex.Message}");
            return false;
        }
    }
}
