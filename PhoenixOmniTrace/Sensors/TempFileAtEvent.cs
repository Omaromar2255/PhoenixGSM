using System;
using System.Collections.Generic;

namespace PhoenixGSM.OmniTrace.Sensors;

/// <summary>
/// Event model for an intercepted temporary file containing staged AT commands or modem payloads.
/// </summary>
public sealed class TempFileAtEvent
{
    public string FilePath { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
    public string DirectoryPath { get; set; } = string.Empty;
    public long FileSize { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public List<string> AtCommands { get; set; } = [];
    public string RawContent { get; set; } = string.Empty;
    public byte[] RawBytes { get; set; } = [];
    public string TargetHint { get; set; } = "USB Modem Interface";
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string SourceTag { get; set; } = "TEMP-AT";
    public bool IsBinaryPayload { get; set; }
}
