using System;
using System.Threading.Tasks;

namespace PhoenixGSM.OmniTrace.Sensors;

/// <summary>
/// Record representing a captured file pushed to the device via ADB or WinUSB.
/// Includes integrity status (Complete vs Partial Wire), upload sequence numbering, and session folder info.
/// </summary>
public sealed class CapturedPushedFileRecord
{
    public string TargetDevicePath { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
    public string SavedFileName { get; set; } = string.Empty;
    public int UploadSequenceNumber { get; set; } = 1;
    public long TransferSequenceId { get; set; }
    public string SessionFolderName { get; set; } = string.Empty;
    public string FilePermissionMode { get; set; } = "33188";
    public string LocalSavedPath { get; set; } = string.Empty;
    public byte[] FileBytes { get; set; } = [];
    public long FileSizeBytes { get; set; }
    public long DeclaredDataSize { get; set; }
    public bool IsCompleteCapture { get; set; } = true;
    public long KernelPacketsDroppedDelta { get; set; }
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
/// Non-blocking background job for passive full-size file recovery, verification, and atomic disk saving.
/// </summary>
internal sealed class PendingFileArchiveJob
{
    public long TransferSequenceId { get; init; }
    public int UploadSequenceNumber { get; init; } = 1;
    public string SessionDirectory { get; init; } = string.Empty;
    public string SessionFolderName { get; init; } = string.Empty;
    public string TargetPath { get; init; } = string.Empty;
    public string Mode { get; init; } = "33188";
    public byte[] WireBytes { get; init; } = [];
    public byte[]? HeaderSignature { get; init; }
    public Task<byte[]?>? EagerSnapshotTask { get; init; }
    public long TotalDeclaredBytes { get; init; }
    public long TotalActualUrbBytes { get; init; }
    public int DataBlockCount { get; init; }
    public bool HadTruncatedUrb { get; init; }
    public bool SawExplicitDone { get; init; }
    public long KernelDroppedDelta { get; init; }
    public string EndpointHex { get; init; } = "0x01";
    public string TriggerReason { get; init; } = "DONE";
}
