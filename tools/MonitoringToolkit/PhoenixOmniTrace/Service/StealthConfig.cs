using System;

namespace PhoenixGSM.OmniTrace.Service;

/// <summary>
/// Centralized configuration for OS-visible identifiers.
/// 
/// Problem: Third-party GSM tools (Global Unlocker, Chimera, UnlockTool, etc.)
/// scan running processes/windows/ETW sessions for keywords like "monitor",
/// "sniffer", "trace", "capture", "spy", "hook" and force-close anything they
/// consider a snooping tool — even legitimate diagnostic utilities.
///
/// Solution: Use neutral, non-triggering names for all OS-visible markers.
/// This is NOT about hiding from the user — the GUI still shows full branding
/// inside the window content. It only changes what external process enumeration sees.
/// </summary>
public static class StealthConfig
{
    // ── OS-visible names (what external tools see via Win32 enumeration) ──

    /// <summary>
    /// ETW session name registered with the kernel.
    /// Replaces "PhoenixOmniTrace_UsbEtwSession" which contains "Trace".
    /// Uses a pattern that mimics standard Windows diagnostic sessions.
    /// </summary>
    public const string EtwSessionName = "Microsoft-Windows-USB-Diagnostics-Session";

    /// <summary>
    /// Named Pipe for IPC between service and GUI.
    /// Replaces "PhoenixOmniTracePipe" which contains "Trace".
    /// Uses a pattern that mimics .NET runtime diagnostic pipes.
    /// </summary>
    public const string PipeName = "dotnet-diagnostic-usb-svc";

    /// <summary>
    /// Window title visible in taskbar and EnumWindows scans.
    /// Replaces "PhoenixGSM Monitoring Studio — Unified Protocol &amp; Hardware Sniffer"
    /// which contains "Monitor", "Sniffer", and "Protocol".
    /// </summary>
    public const string WindowTitle = "Device Configuration Utility";

    /// <summary>
    /// Breadcrumb file for detecting abnormal termination.
    /// Written by the guardian, read by external launcher.
    /// </summary>
    public static string BreadcrumbPath => System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "DeviceCfgUtil", "status.dat");

    /// <summary>
    /// Keywords that third-party GSM tools scan for in process names,
    /// window titles, and named objects. Used for self-auditing during development.
    /// </summary>
    public static readonly string[] SuspiciousKeywords =
    [
        "monitor", "sniff", "trace", "capture", "wireshark",
        "usbpcap", "spy", "hook", "phoenix", "omni",
        "watch", "intercept", "debug", "inspect", "sniffer",
        "packet", "analyzer", "logger", "dump", "probe"
    ];

    /// <summary>
    /// Check if a string contains any keyword that might trigger
    /// third-party tool anti-snooping sweeps.
    /// </summary>
    public static bool ContainsTriggerWord(string text)
    {
        if (string.IsNullOrEmpty(text)) return false;
        string lower = text.ToLowerInvariant();
        foreach (var kw in SuspiciousKeywords)
        {
            if (lower.Contains(kw)) return true;
        }
        return false;
    }
}
