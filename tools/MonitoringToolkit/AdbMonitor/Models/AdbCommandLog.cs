namespace PhoenixGSM.AdbMonitor.Models;

using System.Text.Json.Serialization;

/// <summary>
/// نموذج بيانات لتسجيل أوامر ADB الملتقطة
/// Data model for captured ADB command logs
/// </summary>
public class AdbCommandLog
{
    /// <summary>وقت تنفيذ الأمر / Command execution timestamp</summary>
    [JsonPropertyName("timestamp")]
    public DateTime Timestamp { get; set; } = DateTime.Now;

    /// <summary>اسم البرنامج الذي أرسل الأمر / Process that sent the command</summary>
    [JsonPropertyName("calling_process")]
    public string CallingProcess { get; set; } = "unknown";

    /// <summary>معرف العملية / Process ID</summary>
    [JsonPropertyName("process_id")]
    public int ProcessId { get; set; }

    /// <summary>الأمر الكامل / Full command line</summary>
    [JsonPropertyName("command")]
    public string Command { get; set; } = string.Empty;

    /// <summary>معاملات الأمر / Command arguments</summary>
    [JsonPropertyName("arguments")]
    public string[] Arguments { get; set; } = [];

    /// <summary>الرد من الجهاز (أول 2000 حرف) / Device response (first 2000 chars)</summary>
    [JsonPropertyName("response")]
    public string Response { get; set; } = string.Empty;

    /// <summary>كود الخروج / Exit code</summary>
    [JsonPropertyName("exit_code")]
    public int ExitCode { get; set; }

    /// <summary>مدة التنفيذ بالمللي ثانية / Execution duration in ms</summary>
    [JsonPropertyName("duration_ms")]
    public long DurationMs { get; set; }

    /// <summary>تصنيف الأمر / Command category</summary>
    [JsonPropertyName("category")]
    public string Category { get; set; } = "GENERAL";

    /// <summary>الجهاز المستهدف / Target device serial</summary>
    [JsonPropertyName("device_serial")]
    public string DeviceSerial { get; set; } = string.Empty;

    /// <summary>هل نجح الأمر / Whether command succeeded</summary>
    [JsonPropertyName("success")]
    public bool Success { get; set; }

    /// <summary>ملاحظات إضافية / Additional notes</summary>
    [JsonPropertyName("notes")]
    public string Notes { get; set; } = string.Empty;
}

/// <summary>
/// تصنيفات أوامر ADB
/// ADB command categories
/// </summary>
public static class AdbCategories
{
    public const string Shell = "SHELL";
    public const string Push = "FILE_PUSH";
    public const string Pull = "FILE_PULL";
    public const string Install = "APP_INSTALL";
    public const string Uninstall = "APP_UNINSTALL";
    public const string Reboot = "REBOOT";
    public const string Sideload = "SIDELOAD";
    public const string Devices = "DEVICES";
    public const string Logcat = "LOGCAT";
    public const string Forward = "PORT_FORWARD";
    public const string Backup = "BACKUP";
    public const string Restore = "RESTORE";
    public const string Root = "ROOT";
    public const string Remount = "REMOUNT";
    public const string General = "GENERAL";

    /// <summary>
    /// تصنيف الأمر تلقائياً بناءً على المحتوى
    /// Auto-categorize command based on content
    /// </summary>
    public static string Categorize(string command)
    {
        if (string.IsNullOrEmpty(command)) return General;

        var lower = command.ToLowerInvariant();
        return lower switch
        {
            _ when lower.Contains("shell") => Shell,
            _ when lower.Contains("push") => Push,
            _ when lower.Contains("pull") => Pull,
            _ when lower.Contains("install") => Install,
            _ when lower.Contains("uninstall") => Uninstall,
            _ when lower.Contains("reboot") => Reboot,
            _ when lower.Contains("sideload") => Sideload,
            _ when lower.Contains("devices") => Devices,
            _ when lower.Contains("logcat") => Logcat,
            _ when lower.Contains("forward") => Forward,
            _ when lower.Contains("backup") => Backup,
            _ when lower.Contains("restore") => Restore,
            _ when lower.Contains("root") => Root,
            _ when lower.Contains("remount") => Remount,
            _ => General
        };
    }
}
