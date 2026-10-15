using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace PhoenixGSM.OmniTrace.Models;

/// <summary>
/// Information and forensics model for an intercepted pushed artifact / staged binary.
/// </summary>
public sealed class PushedArtifactInfo
{
    [JsonPropertyName("artifactId")]
    public string ArtifactId { get; set; } = Guid.NewGuid().ToString("N");

    [JsonPropertyName("fileName")]
    public string FileName { get; set; } = string.Empty;

    [JsonPropertyName("targetDevicePath")]
    public string TargetDevicePath { get; set; } = string.Empty;

    [JsonPropertyName("localSourcePath")]
    public string LocalSourcePath { get; set; } = string.Empty;

    [JsonPropertyName("vaultFilePath")]
    public string VaultFilePath { get; set; } = string.Empty;

    [JsonPropertyName("vaultManifestPath")]
    public string VaultManifestPath { get; set; } = string.Empty;

    [JsonPropertyName("fileSizeBytes")]
    public long FileSizeBytes { get; set; }

    [JsonPropertyName("sha256")]
    public string Sha256 { get; set; } = string.Empty;

    [JsonPropertyName("md5")]
    public string Md5 { get; set; } = string.Empty;

    [JsonPropertyName("fileClassification")]
    public string FileClassification { get; set; } = "UNKNOWN";

    [JsonPropertyName("magicDescription")]
    public string MagicDescription { get; set; } = string.Empty;

    [JsonPropertyName("isExecutableOrExploit")]
    public bool IsExecutableOrExploit { get; set; }

    [JsonPropertyName("sourceVector")]
    public string SourceVector { get; set; } = "HostPrePush";

    [JsonPropertyName("processName")]
    public string ProcessName { get; set; } = string.Empty;

    [JsonPropertyName("processId")]
    public int ProcessId { get; set; }

    [JsonPropertyName("deviceSerial")]
    public string DeviceSerial { get; set; } = string.Empty;

    [JsonPropertyName("timestamp")]
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    [JsonPropertyName("isDeduplicated")]
    public bool IsDeduplicated { get; set; }

    [JsonPropertyName("attributes")]
    public Dictionary<string, string> Attributes { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// In-memory raw bytes of the captured file for live inspection and forensic viewing.
    /// </summary>
    [JsonIgnore]
    public byte[]? RawBytes { get; set; }

    public string ToJson()
    {
        return JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
    }

    public static PushedArtifactInfo? FromJson(string json)
    {
        return JsonSerializer.Deserialize<PushedArtifactInfo>(json);
    }

    public override string ToString()
    {
        return $"[{Timestamp:HH:mm:ss}] [{FileClassification}] {FileName} -> {TargetDevicePath} ({FileSizeBytes:N0} bytes, SHA256={Sha256[..8]}...)";
    }
}
