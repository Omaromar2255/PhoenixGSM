using System;
using System.Collections.Generic;
using System.Text.Json;

namespace PhoenixGSM.OmniTrace.DeviceStateDiff;

public class DeviceStateSnapshot
{
    public List<string> InstalledPackages { get; set; } = new();
    public Dictionary<string, List<string>> GrantedDangerousPermissions { get; set; } = new();
    public List<string> DeviceAdministrators { get; set; } = new();
    public List<string> AccessibilityServices { get; set; } = new();
    public Dictionary<string, string> SettingsSecure { get; set; } = new();
    
    public string BootloaderStatus { get; set; } = "Locked";
    public string KnoxWarrantyVoid { get; set; } = "0x0";

    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    // تسلسل الحالة لتخزينها بتنسيق JSON
    public string ToJson()
    {
        return JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
    }

    public static DeviceStateSnapshot? FromJson(string json)
    {
        return JsonSerializer.Deserialize<DeviceStateSnapshot>(json);
    }
}
