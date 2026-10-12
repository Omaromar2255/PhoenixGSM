using System;
using System.Collections.Generic;

namespace PhoenixGSM.OmniTrace.Apple.Models;

/// <summary>
/// Structured information model for an interpreted Apple iOS protocol operation.
/// </summary>
public sealed class AppleDecodedCommand
{
    public AppleDeviceMode Mode { get; set; } = AppleDeviceMode.Normal;
    public string Category { get; set; } = "General";
    public string Operation { get; set; } = string.Empty;
    public string Summary { get; set; } = string.Empty;
    public string Parameters { get; set; } = string.Empty;
    public string? Ecid { get; set; }
    public string? Cpid { get; set; }
    public string? Bdid { get; set; }
    public string? SerialNumber { get; set; }
    public string? Model { get; set; }
    public Dictionary<string, string> Details { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    public override string ToString()
    {
        string modeTag = Mode switch
        {
            AppleDeviceMode.Recovery => "[iOS RECOVERY]",
            AppleDeviceMode.Dfu => "[iOS DFU]",
            AppleDeviceMode.PwnedDfu => "[iOS PWNED DFU]",
            AppleDeviceMode.RamdiskSsh => "[iOS RAMDISK SSH]",
            AppleDeviceMode.PurpleDiag => "[iOS PURPLE DIAG]",
            AppleDeviceMode.Restore => "[iOS RESTORE]",
            _ => "[iOS NORMAL]"
        };

        string devTag = !string.IsNullOrEmpty(Ecid) ? $" (ECID:{Ecid})" : "";
        return $"{modeTag}{devTag} {Operation}: {Summary}";
    }
}
