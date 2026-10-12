using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using Microsoft.Win32;

namespace PhoenixGSM.UsbMonitor;

/// <summary>
/// Core Driver & Filter Manager for PhoenixUsbMonitor.
/// Coordinates kernel driver service installation, Device Class Upper/LowerFilters,
/// surgical per-device instance filters, and system rollbacks.
/// </summary>
public static partial class DriverManager
{
    public const string ServiceName = "PhoenixUsbMonitor";

    // Well-known Device / Setup Classes
    public const string ClassAndroid = "{3F966BD9-FA04-4EC5-991C-D326973B5128}";
    public const string ClassWinUsb = "{88BAE032-5A81-49F0-BC3D-A4FF138216D6}";
    public const string ClassUsb = "{36FC9E60-C465-11CF-8056-444553540000}";
    public const string ClassPorts = "{4D36E978-E325-11CE-BFC1-08002BE10318}";
    public const string ClassModem = "{4D36E96D-E325-11CE-BFC1-08002BE10318}";

    public static readonly Dictionary<string, (string Guid, string Name)> KnownClasses = new(StringComparer.OrdinalIgnoreCase)
    {
        ["android"] = (ClassAndroid, "Android Devices (AndroidUsbDeviceClass)"),
        ["winusb"] = (ClassWinUsb, "WinUSB Generic Devices (USBDevice)"),
        ["usb"] = (ClassUsb, "Universal Serial Bus Controllers & Hubs"),
        ["ports"] = (ClassPorts, "Ports (COM & LPT / Qualcomm EDL / MTK Preloader)"),
        ["modem"] = (ClassModem, "Modem Devices (USB Modems / Honor / Huawei / Samsung)"),
    };

    public static string ResolveClassGuid(string input)
    {
        if (KnownClasses.TryGetValue(input.Trim(), out var match))
        {
            return match.Guid;
        }

        string clean = input.Trim().Trim('{', '}');
        return "{" + clean.ToUpperInvariant() + "}";
    }

    public static string GetDriverSysPath()
    {
        // 1. Check in local release directory
        var localBin = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "PhoenixUsbMonitor.sys");
        if (File.Exists(localBin)) return Path.GetFullPath(localBin);

        // 2. Check in sibling PhoenixUsbMonitor\bin\Release
        var siblingPath = Path.GetFullPath(Path.Combine(
            AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "..",
            "PhoenixUsbMonitor", "bin", "Release", "PhoenixUsbMonitor.sys"));
        if (File.Exists(siblingPath)) return siblingPath;

        // 3. Fallback to hardcoded workspace path
        var devPath = @"C:\Users\pc5\softwer\PhoenixGSM\tools\MonitoringToolkit\UsbMonitor\PhoenixUsbMonitor\bin\Release\PhoenixUsbMonitor.sys";
        return devPath;
    }

    public static bool IsTestSigningEnabled()
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "bcdedit.exe",
                Arguments = "",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc == null) return false;
            string output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit();
            return output.IndexOf("testsigning             Yes", StringComparison.OrdinalIgnoreCase) >= 0;
        }
        catch
        {
            return false;
        }
    }

    public static bool IsServiceInstalled()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + ServiceName, false);
            return key != null;
        }
        catch
        {
            return false;
        }
    }

    public static string GetServiceStatus()
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = $"query {ServiceName}",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            if (p == null) return "Unknown";
            string output = p.StandardOutput.ReadToEnd();
            p.WaitForExit();

            if (output.Contains("STATE") && output.Contains("RUNNING")) return "Running";
            if (output.Contains("STATE") && output.Contains("STOPPED")) return "Stopped";
            if (output.Contains("FAILED 1060")) return "Not Installed";
            return "Unknown";
        }
        catch
        {
            return "Unknown";
        }
    }
}
