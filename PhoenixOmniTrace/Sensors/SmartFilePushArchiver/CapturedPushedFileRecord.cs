using System;
using System.Threading.Tasks;

namespace PhoenixGSM.OmniTrace.Sensors;

/// <summary>
/// Record representing a complete captured file pushed to the device via ADB or WinUSB.
/// Saves strictly ONE file per pushed artifact with its exact original name and full size.
/// </summary>
public sealed class CapturedPushedFileRecord
{
    public string TargetDevicePath { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
    public string FilePermissionMode { get; set; } = "33188";
    public string LocalSavedPath { get; set; } = string.Empty;
    public byte[] FileBytes { get; set; } = [];
    public long FileSizeBytes { get; set; }
    public long DeclaredDataSize { get; set; }
    public string Sha256 { get; set; } = string.Empty;
    public string Md5 { get; set; } = string.Empty;
    public string FileClassification { get; set; } = "Binary File";
    public string MagicDescription { get; set; } = string.Empty;
    public bool IsExecutableOrExploit { get; set; }
    public string CaptureVector { get; set; } = "USB Wire Stream";
    public string ProcessName { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string Summary { get; set; } = string.Empty;
    public string AdditionalDetails { get; set; } = string.Empty;
}

/// <summary>
/// Non-blocking background job for 100% passive, parallel full-size file recovery and disk saving.
/// </summary>
internal sealed class PendingFileArchiveJob
{
    public string TargetPath { get; init; } = string.Empty;
    public string Mode { get; init; } = "33188";
    public byte[] WireBytes { get; init; } = [];
    public byte[]? HeaderSignature { get; init; }
    public Task<byte[]?>? EagerSnapshotTask { get; init; }
    public long TotalDeclaredBytes { get; init; }
    public long TotalActualUrbBytes { get; init; }
    public bool HadTruncatedUrb { get; init; }
    public string EndpointHex { get; init; } = "0x01";
    public string TriggerReason { get; init; } = "DONE";
}
