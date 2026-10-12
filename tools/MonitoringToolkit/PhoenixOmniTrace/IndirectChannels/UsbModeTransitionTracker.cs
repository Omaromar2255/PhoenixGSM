using System;
using System.Collections.Concurrent;

namespace PhoenixGSM.OmniTrace.IndirectChannels;

public enum DeviceMode
{
    Disconnected,
    NormalAdb,
    Fastboot,
    SamsungOdinDownload,
    QualcommEdl,
    MediaTekBrom,
    ModemDiag,
    MtpPtp,
    Recovery,
    Unknown
}

public class DeviceModeTransition
{
    public string DeviceId { get; set; } = string.Empty;
    public DeviceMode PreviousMode { get; set; }
    public DeviceMode CurrentMode { get; set; }
    public bool IsSuspicious { get; set; }
    public string Reason { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; }
}

public class UsbModeTransitionTracker : IDisposable
{
    private readonly ConcurrentDictionary<string, DeviceMode> _deviceStates = new();

    public event EventHandler<DeviceModeTransition>? OnSuspiciousModeTransition;

    // تتبع حالة الجهاز وتحديد الانتقالات المشبوهة
    public DeviceModeTransition? TrackDeviceMode(string deviceId, ushort vid, ushort pid, string interfaceDescription)
    {
        try
        {
            var currentMode = DetermineMode(vid, pid, interfaceDescription);
            var prevMode = _deviceStates.TryGetValue(deviceId, out var p) ? p : DeviceMode.Disconnected;

            if (prevMode == currentMode)
                return null;

            _deviceStates[deviceId] = currentMode;

            var transition = new DeviceModeTransition
            {
                DeviceId = deviceId,
                PreviousMode = prevMode,
                CurrentMode = currentMode,
                Timestamp = DateTime.UtcNow
            };

            // Analyze for suspicious transitions - تحليل الانتقالات المشبوهة
            if (IsSuspiciousTransition(prevMode, currentMode, out string reason))
            {
                transition.IsSuspicious = true;
                transition.Reason = reason;
                OnSuspiciousModeTransition?.Invoke(this, transition);
            }

            return transition;
        }
        catch (Exception ex)
        {
            // Fail-open: لا توقف النظام في حالة الخطأ
            Console.WriteLine($"[Error] TrackDeviceMode failed: {ex.Message}");
            return null;
        }
    }

    private DeviceMode DetermineMode(ushort vid, ushort pid, string interfaceDescription)
    {
        string desc = interfaceDescription.ToLowerInvariant();
        
        if (vid == 0x04E8 && pid == 0x685D) return DeviceMode.SamsungOdinDownload;
        if (vid == 0x05C6 && pid == 0x9008) return DeviceMode.QualcommEdl;
        if (vid == 0x0E8D && pid == 0x0003) return DeviceMode.MediaTekBrom;
        
        if (desc.Contains("adb") || desc.Contains("android debug")) return DeviceMode.NormalAdb;
        if (desc.Contains("fastboot")) return DeviceMode.Fastboot;
        if (desc.Contains("diag")) return DeviceMode.ModemDiag;
        if (desc.Contains("mtp") || desc.Contains("ptp")) return DeviceMode.MtpPtp;
        if (desc.Contains("recovery")) return DeviceMode.Recovery;
        
        return DeviceMode.Unknown;
    }

    private bool IsSuspiciousTransition(DeviceMode from, DeviceMode to, out string reason)
    {
        reason = string.Empty;
        
        // Example: Normal -> EDL directly is suspicious (usually needs specific payload or cable)
        // انتقال مباشر إلى EDL يعتبر مشبوهاً
        if (from == DeviceMode.NormalAdb && to == DeviceMode.QualcommEdl)
        {
            reason = "Unexpected transition directly to EDL mode. Possible exploit or forced crash.";
            return true;
        }
        
        // Fastboot to Brom directly
        if (from == DeviceMode.Fastboot && to == DeviceMode.MediaTekBrom)
        {
            reason = "Suspicious jump to BROM from Fastboot. Possible bypass attempt.";
            return true;
        }

        return false;
    }

    public void Dispose()
    {
        _deviceStates.Clear();
    }
}
