using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Runtime.Versioning;

namespace PhoenixGSM.OmniTrace.Rollback;

/// <summary>
/// Central manager that tracks ALL system changes.
/// المدير المركزي لتتبع جميع التغييرات في النظام.
/// </summary>
[SupportedOSPlatform("windows")]
public class SystemRollbackManager : IDisposable
{
    private readonly ConcurrentStack<ISystemChange> _changes = new();
    private bool _disposed;

    /// <summary>
    /// Track and apply a change.
    /// تسجيل وتطبيق التغيير.
    /// </summary>
    public bool TrackChange(ISystemChange change)
    {
        try
        {
            if (change.Apply())
            {
                _changes.Push(change);
                return true;
            }
            return false;
        }
        catch (Exception ex)
        {
            // Fail open, never crash. لا توقف النظام
            Console.WriteLine($"[SystemRollbackManager] Failed to apply change: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Revert all tracked changes.
    /// التراجع عن كل التغييرات.
    /// </summary>
    public void RevertAll()
    {
        try
        {
            while (_changes.TryPop(out var change))
            {
                try
                {
                    if (change.IsApplied)
                    {
                        change.Revert();
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[SystemRollbackManager] Failed to revert change {change.ChangeId}: {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SystemRollbackManager] Error in RevertAll: {ex.Message}");
        }
    }

    /// <summary>
    /// Revert the last N changes.
    /// التراجع عن آخر N تغييرات.
    /// </summary>
    public void RevertLast(int count)
    {
        try
        {
            for (int i = 0; i < count; i++)
            {
                if (_changes.TryPop(out var change))
                {
                    try
                    {
                        if (change.IsApplied)
                        {
                            change.Revert();
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[SystemRollbackManager] Failed to revert change {change.ChangeId}: {ex.Message}");
                    }
                }
                else
                {
                    break;
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SystemRollbackManager] Error in RevertLast: {ex.Message}");
        }
    }

    /// <summary>
    /// Get the read-only list of all applied changes.
    /// الحصول على قائمة التغييرات المطبقة.
    /// </summary>
    public IReadOnlyList<ISystemChange> GetChangeLog()
    {
        return _changes.ToArray();
    }

    /// <summary>
    /// Serialize change log to JSON.
    /// حفظ سجل التغييرات في ملف.
    /// </summary>
    public bool SaveSnapshot(string path)
    {
        try
        {
            var log = _changes.Select(c => new
            {
                c.ChangeId,
                c.Description,
                c.Timestamp,
                c.IsApplied
            }).ToList();

            string json = JsonSerializer.Serialize(log, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(path, json);
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SystemRollbackManager] Failed to save snapshot: {ex.Message}");
            return false;
        }
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            RevertAll();
            _disposed = true;
        }
        GC.SuppressFinalize(this);
    }
}
