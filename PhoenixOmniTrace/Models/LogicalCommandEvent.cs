using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace PhoenixGSM.OmniTrace.Models;

/// <summary>
/// LAYER 11 — Logical Command Event Model
/// Represents a reconstructed human-level command or protocol transaction.
/// Crucial architectural rule: sourceProcess is purely AttributionMetadata,
/// NOT part of command identity.
/// </summary>
public sealed class LogicalCommandEvent
{
    [JsonPropertyName("commandId")]
    public string CommandId { get; set; } = Guid.NewGuid().ToString("N");

    [JsonPropertyName("timestamp")]
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;

    [JsonPropertyName("transport")]
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public TransportType Transport { get; set; } = TransportType.BULK;

    [JsonPropertyName("protocol")]
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public KnownProtocol Protocol { get; set; } = KnownProtocol.ADB;

    [JsonPropertyName("service")]
    public string Service { get; set; } = string.Empty;

    [JsonPropertyName("session")]
    public string SessionIdentity { get; set; } = string.Empty;

    [JsonPropertyName("device")]
    public string DeviceIdentity { get; set; } = string.Empty;

    [JsonPropertyName("direction")]
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public PacketDirection Direction { get; set; } = PacketDirection.HOST_TO_DEVICE;

    [JsonPropertyName("command")]
    public string Command { get; set; } = string.Empty;

    [JsonPropertyName("rawEvidence")]
    public List<ulong> RawEvidenceSequences { get; set; } = [];

    [JsonPropertyName("evidenceHashes")]
    public List<string> EvidenceHashes { get; set; } = [];

    [JsonPropertyName("confidence")]
    public double Confidence { get; set; } = 1.0;

    [JsonPropertyName("attribution")]
    public ProcessAttributionMetadata Attribution { get; set; } = new();

    [JsonPropertyName("details")]
    public Dictionary<string, string> Details { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    public override string ToString()
    {
        string attr = Attribution.ProcessId > 0 ? $" [PID:{Attribution.ProcessId} {Attribution.ImageName}]" : "";
        return $"[{Timestamp:HH:mm:ss.fff}] [{Protocol}/{Service}] {Command}{attr} (Confidence={Confidence:P0})";
    }
}

public sealed class ProcessAttributionMetadata
{
    [JsonPropertyName("pid")]
    public int ProcessId { get; set; }

    [JsonPropertyName("ppid")]
    public int ParentProcessId { get; set; }

    [JsonPropertyName("processGuid")]
    public string ProcessGuid { get; set; } = string.Empty;

    [JsonPropertyName("imageName")]
    public string ImageName { get; set; } = string.Empty;

    [JsonPropertyName("imagePath")]
    public string ImagePath { get; set; } = string.Empty;

    [JsonPropertyName("commandLine")]
    public string CommandLine { get; set; } = string.Empty;

    [JsonPropertyName("user")]
    public string User { get; set; } = string.Empty;

    [JsonPropertyName("startTime")]
    public DateTimeOffset? StartTime { get; set; }

    [JsonPropertyName("exitTime")]
    public DateTimeOffset? ExitTime { get; set; }
}
