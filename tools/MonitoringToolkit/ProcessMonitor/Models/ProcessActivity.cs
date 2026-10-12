namespace PhoenixGSM.ProcessMonitor.Models;

using System.Text.Json.Serialization;

/// <summary>
/// نموذج بيانات نشاط العملية
/// Process activity data model
/// </summary>
public class ProcessActivity
{
    [JsonPropertyName("timestamp")]
    public DateTime Timestamp { get; set; } = DateTime.Now;

    /// <summary>اسم العملية المراقبة / Monitored process name</summary>
    [JsonPropertyName("process_name")]
    public string ProcessName { get; set; } = "";

    [JsonPropertyName("process_id")]
    public int ProcessId { get; set; }

    /// <summary>نوع النشاط / Activity type</summary>
    [JsonPropertyName("activity_type")]
    public string ActivityType { get; set; } = "";

    /// <summary>تفاصيل النشاط / Activity details</summary>
    [JsonPropertyName("details")]
    public string Details { get; set; } = "";

    /// <summary>المسار أو العنوان المتأثر / Affected path or address</summary>
    [JsonPropertyName("path")]
    public string Path { get; set; } = "";

    /// <summary>بيانات إضافية / Extra data</summary>
    [JsonPropertyName("extra")]
    public Dictionary<string, string> Extra { get; set; } = [];
}

public static class ActivityTypes
{
    public const string FileRead = "FILE_READ";
    public const string FileWrite = "FILE_WRITE";
    public const string FileCreate = "FILE_CREATE";
    public const string FileDelete = "FILE_DELETE";
    public const string DllLoad = "DLL_LOAD";
    public const string ProcessStart = "PROCESS_START";
    public const string ProcessExit = "PROCESS_EXIT";
    public const string NetworkConnect = "NETWORK_CONNECT";
    public const string RegistryRead = "REGISTRY_READ";
    public const string RegistryWrite = "REGISTRY_WRITE";
    public const string UsbAccess = "USB_ACCESS";
    public const string ComPortAccess = "COM_PORT_ACCESS";
}
