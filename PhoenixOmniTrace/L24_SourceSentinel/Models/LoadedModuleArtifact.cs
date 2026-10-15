using System;

namespace PhoenixOmniTrace.L24_SourceSentinel.Models;

public record LoadedModuleArtifact(
    string ModuleName, 
    string FilePath, 
    IntPtr BaseAddress, 
    int MemorySize,
    bool IsUnpackedInRam = false,
    DateTime DetectionTimestamp = default,
    int ProcessId = 0
)
{
    public string FormattedBaseAddress => $"0x{BaseAddress.ToInt64():X8}";
    public string FormattedSize => $"{MemorySize / 1024} KB";
    public string DisplaySummary => IsUnpackedInRam 
        ? $"[RAM Unpacked] {ModuleName} @ {FormattedBaseAddress} ({FormattedSize})"
        : $"{ModuleName} [{FormattedSize}] @ {FormattedBaseAddress}";
}
