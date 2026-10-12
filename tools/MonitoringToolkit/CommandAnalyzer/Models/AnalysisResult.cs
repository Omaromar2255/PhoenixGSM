namespace PhoenixGSM.CommandAnalyzer.Models;

using System.Text.Json.Serialization;

/// <summary>
/// نتيجة تحليل الأوامر الملتقطة
/// Analysis result for captured commands
/// </summary>
public class AnalysisResult
{
    [JsonPropertyName("analysis_date")]
    public DateTime AnalysisDate { get; set; } = DateTime.Now;

    [JsonPropertyName("source_tool")]
    public string SourceTool { get; set; } = "";

    [JsonPropertyName("total_commands")]
    public int TotalCommands { get; set; }

    [JsonPropertyName("total_serial_packets")]
    public int TotalSerialPackets { get; set; }

    [JsonPropertyName("total_process_activities")]
    public int TotalProcessActivities { get; set; }

    [JsonPropertyName("total_usb_frames")]
    public int TotalUsbFrames { get; set; }

    /// <summary>تصنيف حزم USB حسب أمر ADB</summary>
    [JsonPropertyName("usb_command_breakdown")]
    public Dictionary<string, int> UsbCommandBreakdown { get; set; } = [];

    /// <summary>الأحداث المترابطة زمنياً عبر جميع الأدوات</summary>
    [JsonPropertyName("chronological_events")]
    public List<CorrelatedEvent> ChronologicalEvents { get; set; } = [];
    [JsonPropertyName("category_breakdown")]
    public Dictionary<string, int> CategoryBreakdown { get; set; } = [];

    /// <summary>البروتوكولات المكتشفة / Detected protocols</summary>
    [JsonPropertyName("detected_protocols")]
    public Dictionary<string, int> DetectedProtocols { get; set; } = [];

    /// <summary>تسلسلات العمليات المكتشفة / Detected operation sequences</summary>
    [JsonPropertyName("operation_sequences")]
    public List<OperationSequence> OperationSequences { get; set; } = [];

    /// <summary>أكثر الأوامر استخداماً / Most used commands</summary>
    [JsonPropertyName("top_commands")]
    public List<CommandFrequency> TopCommands { get; set; } = [];

    /// <summary>الملفات المهمة المكتشفة / Important files discovered</summary>
    [JsonPropertyName("important_files")]
    public List<string> ImportantFiles { get; set; } = [];

    /// <summary>السيرفرات المكتشفة / Discovered servers</summary>
    [JsonPropertyName("discovered_servers")]
    public List<string> DiscoveredServers { get; set; } = [];

    /// <summary>أوامر AT المكتشفة / Discovered AT commands</summary>
    [JsonPropertyName("at_commands")]
    public List<string> AtCommands { get; set; } = [];

    /// <summary>توصيات للتنفيذ / Implementation recommendations</summary>
    [JsonPropertyName("recommendations")]
    public List<string> Recommendations { get; set; } = [];
}

/// <summary>
/// تسلسل عملية مكتشف (مثلاً: خطوات FRP Bypass)
/// Discovered operation sequence (e.g., FRP Bypass steps)
/// </summary>
public class OperationSequence
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("description")]
    public string Description { get; set; } = "";

    [JsonPropertyName("steps")]
    public List<SequenceStep> Steps { get; set; } = [];

    [JsonPropertyName("occurrence_count")]
    public int OccurrenceCount { get; set; } = 1;
}

public class SequenceStep
{
    [JsonPropertyName("order")]
    public int Order { get; set; }

    [JsonPropertyName("type")]
    public string Type { get; set; } = ""; // ADB, AT, USB, FILE

    [JsonPropertyName("command")]
    public string Command { get; set; } = "";

    [JsonPropertyName("description")]
    public string Description { get; set; } = "";
}

public class CommandFrequency
{
    [JsonPropertyName("command")]
    public string Command { get; set; } = "";

    [JsonPropertyName("count")]
    public int Count { get; set; }

    [JsonPropertyName("category")]
    public string Category { get; set; } = "";
}

public class CorrelatedEvent
{
    [JsonPropertyName("timestamp")]
    public DateTime Timestamp { get; set; }

    [JsonPropertyName("source")]
    public string Source { get; set; } = ""; // ADB, USB, SERIAL, PROCESS

    [JsonPropertyName("summary")]
    public string Summary { get; set; } = "";

    [JsonPropertyName("details")]
    public string Details { get; set; } = "";
}

