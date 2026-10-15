using System;

namespace PhoenixOmniTrace.L24_SourceSentinel.Models;

public enum HandleResourceType
{
    Unknown,
    SerialPort,      // \\.\COMx or \Device\Serialx
    UsbDevice,       // WinUSB, USB Hub / Endpoint
    NamedPipe,       // \\.\pipe\...
    DiskFile,        // Local filesystem helper, DLL, DA binary
    RegistryKey,     // Registry radar query
    NetworkSocket    // Raw socket handle
}

public sealed class TrackedHandleInfo
{
    public IntPtr HandleValue { get; init; }
    public int ProcessId { get; init; }
    public string TargetPath { get; set; } = string.Empty;
    public HandleResourceType ResourceType { get; set; } = HandleResourceType.Unknown;
    public DateTime OpenedTimestamp { get; init; } = DateTime.UtcNow;
    public string OpeningCallerOrigin { get; init; } = string.Empty;

    public static HandleResourceType DetectResourceType(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return HandleResourceType.Unknown;

        string upper = path.ToUpperInvariant();
        if (upper.Contains("COM") || upper.Contains("SERIAL"))
            return HandleResourceType.SerialPort;
        if (upper.Contains("USB") || upper.Contains("VID_") || upper.Contains("WINUSB"))
            return HandleResourceType.UsbDevice;
        if (upper.Contains("PIPE\\") || upper.StartsWith("\\\\.\\PIPE"))
            return HandleResourceType.NamedPipe;
        if (upper.Contains("REGISTRY") || upper.Contains("HKLM") || upper.Contains("HKCU"))
            return HandleResourceType.RegistryKey;
        if (upper.Contains(":\\") || upper.StartsWith("\\??\\"))
            return HandleResourceType.DiskFile;

        return HandleResourceType.Unknown;
    }
}
