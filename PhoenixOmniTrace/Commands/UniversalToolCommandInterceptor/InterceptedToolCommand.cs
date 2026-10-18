using System;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.Commands;

/// <summary>
/// Detailed metadata for intercepted GSM tool execution commands.
/// </summary>
public sealed class InterceptedToolCommand
{
    public int ProcessId { get; set; }
    public int ParentProcessId { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public string ParentProcessName { get; set; } = string.Empty;
    public string ExecutablePath { get; set; } = string.Empty;
    public string CommandLine { get; set; } = string.Empty;
    public string CommandAction { get; set; } = string.Empty;
    public string FormattedSummary { get; set; } = string.Empty;
    public string TargetOrEndpoint { get; set; } = string.Empty;
    public string SourceTag { get; set; } = "TOOL-CMD";
    public string ProtocolName { get; set; } = "GSM-TOOL";
    public KnownProtocol Protocol { get; set; } = KnownProtocol.HostCommand;
    public string Category { get; set; } = "Process";
    public string? DecodedScript { get; set; }
    public string TechnicalDetails { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string InterceptionEngine { get; set; } = "WMI";
}
