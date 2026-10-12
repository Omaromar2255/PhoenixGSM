using System;
using Microsoft.Win32;
using System.Runtime.Versioning;

namespace PhoenixGSM.OmniTrace.Rollback;

/// <summary>
/// Tracks a single registry modification.
/// يتتبع تعديل سجل واحد في الويندوز.
/// </summary>
[SupportedOSPlatform("windows")]
public class RegistryChange : ISystemChange
{
    public string ChangeId { get; } = Guid.NewGuid().ToString();
    public string Description { get; }
    public DateTimeOffset Timestamp { get; } = DateTimeOffset.UtcNow;
    public bool IsApplied { get; private set; }

    private readonly RegistryHive _hive;
    private readonly string _keyPath;
    private readonly string _valueName;
    private readonly object? _newValue;
    private readonly RegistryValueKind _newKind;

    private object? _oldValue;
    private RegistryValueKind _oldKind;
    private bool _valueExisted;

    public RegistryChange(RegistryHive hive, string keyPath, string valueName, object? newValue, RegistryValueKind newKind, string description)
    {
        _hive = hive;
        _keyPath = keyPath;
        _valueName = valueName;
        _newValue = newValue;
        _newKind = newKind;
        Description = description;
    }

    public bool Apply()
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(_hive, RegistryView.Default);
            using var key = baseKey.CreateSubKey(_keyPath, writable: true);
            if (key == null) return false;

            _oldValue = key.GetValue(_valueName);
            _valueExisted = _oldValue != null;
            if (_valueExisted)
            {
                _oldKind = key.GetValueKind(_valueName);
            }

            if (_newValue == null)
            {
                key.DeleteValue(_valueName, throwOnMissingValue: false);
            }
            else
            {
                key.SetValue(_valueName, _newValue, _newKind);
            }

            IsApplied = true;
            return true;
        }
        catch (Exception ex)
        {
            // Fail open, log exception. تسجيل الخطأ دون إيقاف النظام
            Console.WriteLine($"[RegistryChange] Apply failed: {ex.Message}");
            return false;
        }
    }

    public bool Revert()
    {
        if (!IsApplied) return true;

        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(_hive, RegistryView.Default);
            using var key = baseKey.OpenSubKey(_keyPath, writable: true);
            if (key != null)
            {
                if (_valueExisted)
                {
                    key.SetValue(_valueName, _oldValue!, _oldKind);
                }
                else
                {
                    key.DeleteValue(_valueName, throwOnMissingValue: false);
                }
            }
            IsApplied = false;
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[RegistryChange] Revert failed: {ex.Message}");
            return false;
        }
    }
}
