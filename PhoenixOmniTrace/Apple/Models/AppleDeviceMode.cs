using System;

namespace PhoenixGSM.OmniTrace.Apple.Models;

/// <summary>
/// Operating modes for Apple iOS devices across the entire servicing lifecycle.
/// </summary>
public enum AppleDeviceMode
{
    /// <summary>Normal booted iOS environment (usbmuxd, lockdownd, AFC, MTP/PTP).</summary>
    Normal,

    /// <summary>iBoot Apple Recovery Mode (irecovery, getenv, setenv, fsboot).</summary>
    Recovery,

    /// <summary>Hardware SecureROM Device Firmware Upgrade Mode (USB DFU class).</summary>
    Dfu,

    /// <summary>SecureROM exploit triggered (checkm8 / PWND:[checkm8]).</summary>
    PwnedDfu,

    /// <summary>Custom SSH Ramdisk loaded in memory (iproxy, mount_apfs, ticket extraction).</summary>
    RamdiskSsh,

    /// <summary>Factory Diagnostics / Purple Mode (SysCfg read/write over CDC serial).</summary>
    PurpleDiag,

    /// <summary>Active IPSW Flashing / Restore Mode (restored_external / ASR).</summary>
    Restore,

    /// <summary>Unspecified or transitioning mode.</summary>
    Unknown
}
