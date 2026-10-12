using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Win32;

namespace PhoenixGSM.UsbMonitor;

public static partial class DriverManager
{
    #region Rollback & Active Filter Discovery

    public static List<string> GetActiveFilterAttachments()
    {
        var attachments = new List<string>();

        // 1. Scan Class keys
        try
        {
            using var classRoot = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Class");
            if (classRoot != null)
            {
                foreach (var sub in classRoot.GetSubKeyNames())
                {
                    using var k = classRoot.OpenSubKey(sub);
                    var lower = k?.GetValue("LowerFilters") as string[] ?? (k?.GetValue("LowerFilters") is string s ? new[] { s } : null);
                    var upper = k?.GetValue("UpperFilters") as string[] ?? (k?.GetValue("UpperFilters") is string s2 ? new[] { s2 } : null);

                    if (lower != null && lower.Any(x => x.Equals(ServiceName, StringComparison.OrdinalIgnoreCase)))
                    {
                        var desc = k?.GetValue("Class")?.ToString() ?? sub;
                        attachments.Add($"[Class LowerFilter] {desc} ({sub})");
                    }
                    if (upper != null && upper.Any(x => x.Equals(ServiceName, StringComparison.OrdinalIgnoreCase)))
                    {
                        var desc = k?.GetValue("Class")?.ToString() ?? sub;
                        attachments.Add($"[Class UpperFilter] {desc} ({sub})");
                    }
                }
            }
        }
        catch { }

        // 2. Scan USB and PORTS Device keys
        string[] enumDeviceRoots = new[] { "USB", "PORTS" };
        foreach (var rootName in enumDeviceRoots)
        {
            try
            {
                using var rootKey = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Enum\{rootName}");
                if (rootKey == null) continue;

                foreach (var devKeyName in rootKey.GetSubKeyNames())
                {
                    using var devKey = rootKey.OpenSubKey(devKeyName);
                    if (devKey == null) continue;

                    foreach (var instName in devKey.GetSubKeyNames())
                    {
                        using var instKey = devKey.OpenSubKey(instName);
                        if (instKey == null) continue;

                        var lower = instKey.GetValue("LowerFilters") as string[] ?? (instKey.GetValue("LowerFilters") is string s ? new[] { s } : null);
                        if (lower != null && lower.Any(x => x.Equals(ServiceName, StringComparison.OrdinalIgnoreCase)))
                        {
                            var friendly = instKey.GetValue("FriendlyName")?.ToString() ?? instKey.GetValue("DeviceDesc")?.ToString() ?? devKeyName;
                            attachments.Add($"[Device LowerFilter] {friendly} ({rootName}\\{devKeyName}\\{instName})");
                        }

                        var upper = instKey.GetValue("UpperFilters") as string[] ?? (instKey.GetValue("UpperFilters") is string s2 ? new[] { s2 } : null);
                        if (upper != null && upper.Any(x => x.Equals(ServiceName, StringComparison.OrdinalIgnoreCase)))
                        {
                            var friendly = instKey.GetValue("FriendlyName")?.ToString() ?? instKey.GetValue("DeviceDesc")?.ToString() ?? devKeyName;
                            attachments.Add($"[Device UpperFilter] {friendly} ({rootName}\\{devKeyName}\\{instName})");
                        }
                    }
                }
            }
            catch { }
        }

        return attachments;
    }

    public static void RemoveAllFilters()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  [*] Scanning and removing all PhoenixUsbMonitor filter registrations (Complete Rollback)...");
        Console.ResetColor();

        int removed = 0;

        // Clean Classes
        try
        {
            using var classRoot = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Class", true);
            if (classRoot != null)
            {
                foreach (var sub in classRoot.GetSubKeyNames())
                {
                    using var k = classRoot.OpenSubKey(sub, true);
                    if (k == null) continue;

                    var lower = k.GetValue("LowerFilters") as string[] ?? (k.GetValue("LowerFilters") is string sl ? new[] { sl } : null);
                    if (lower != null && lower.Any(x => x.Equals(ServiceName, StringComparison.OrdinalIgnoreCase)))
                    {
                        var filtered = lower.Where(x => !x.Equals(ServiceName, StringComparison.OrdinalIgnoreCase)).ToArray();
                        if (filtered.Length == 0) k.DeleteValue("LowerFilters", false);
                        else k.SetValue("LowerFilters", filtered, RegistryValueKind.MultiString);
                        removed++;
                        Console.WriteLine($"      Removed LowerFilter from Class {sub}");
                        RestartActiveDevicesOfClass(sub);
                    }

                    var upper = k.GetValue("UpperFilters") as string[] ?? (k.GetValue("UpperFilters") is string su ? new[] { su } : null);
                    if (upper != null && upper.Any(x => x.Equals(ServiceName, StringComparison.OrdinalIgnoreCase)))
                    {
                        var filtered = upper.Where(x => !x.Equals(ServiceName, StringComparison.OrdinalIgnoreCase)).ToArray();
                        if (filtered.Length == 0) k.DeleteValue("UpperFilters", false);
                        else k.SetValue("UpperFilters", filtered, RegistryValueKind.MultiString);
                        removed++;
                        Console.WriteLine($"      Removed UpperFilter from Class {sub}");
                        RestartActiveDevicesOfClass(sub);
                    }
                }
            }
        }
        catch { }

        // Clean Devices across all common Enum roots
        string[] enumRoots = new[] { "USB", "PORTS", "FTDIBUS", "USBSTOR" };
        foreach (var rootName in enumRoots)
        {
            try
            {
                using var rootKey = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Enum\{rootName}", true);
                if (rootKey == null) continue;

                foreach (var devKeyName in rootKey.GetSubKeyNames())
                {
                    using var devKey = rootKey.OpenSubKey(devKeyName, true);
                    if (devKey == null) continue;

                    foreach (var instName in devKey.GetSubKeyNames())
                    {
                        using var instKey = devKey.OpenSubKey(instName, true);
                        if (instKey == null) continue;

                        var lower = instKey.GetValue("LowerFilters") as string[];
                        if (lower != null && lower.Any(x => x.Equals(ServiceName, StringComparison.OrdinalIgnoreCase)))
                        {
                            var filtered = lower.Where(x => !x.Equals(ServiceName, StringComparison.OrdinalIgnoreCase)).ToArray();
                            if (filtered.Length == 0) instKey.DeleteValue("LowerFilters", false);
                            else instKey.SetValue("LowerFilters", filtered, RegistryValueKind.MultiString);
                            removed++;
                            Console.WriteLine($"      Removed LowerFilter from Device {rootName}\\{devKeyName}\\{instName}");
                            
                            // Restart device to reload stock Windows driver
                            RestartDevice($"{rootName}\\{devKeyName}\\{instName}");
                        }

                        var upper = instKey.GetValue("UpperFilters") as string[];
                        if (upper != null && upper.Any(x => x.Equals(ServiceName, StringComparison.OrdinalIgnoreCase)))
                        {
                            var filtered = upper.Where(x => !x.Equals(ServiceName, StringComparison.OrdinalIgnoreCase)).ToArray();
                            if (filtered.Length == 0) instKey.DeleteValue("UpperFilters", false);
                            else instKey.SetValue("UpperFilters", filtered, RegistryValueKind.MultiString);
                            removed++;
                            Console.WriteLine($"      Removed UpperFilter from Device {rootName}\\{devKeyName}\\{instName}");
                            RestartDevice($"{rootName}\\{devKeyName}\\{instName}");
                        }
                    }
                }
            }
            catch { }
        }

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"  [+] Rollback complete. Removed {removed} filter attachment(s).");
        Console.ResetColor();
    }

    /// <summary>
    /// Restores 100% stock native Windows drivers and configuration.
    /// Strips all filter attachments and stops the driver service immediately.
    /// </summary>
    public static void RestoreStockWindowsConfiguration()
    {
        try
        {
            RemoveAllFilters();
            StopService();
        }
        catch { }
    }

    #endregion

    public static void ShowStatus()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("+========================================================================+");
        Console.WriteLine("|             PhoenixGSM — USB Filter Driver System Status               |");
        Console.WriteLine("+========================================================================+");
        Console.ResetColor();

        string sysPath = GetDriverSysPath();
        bool binExists = File.Exists(sysPath);
        bool testSigning = IsTestSigningEnabled();
        bool svcInstalled = IsServiceInstalled();
        var svcStatus = GetServiceStatus();

        using var client = new UsbDriverClient();
        bool devAccessible = client.IsDriverAvailable();

        Console.WriteLine("\n[1] Driver Binary:");
        Console.WriteLine($"    Path   : {sysPath}");
        Console.WriteLine($"    Status : {(binExists ? "[FOUND]" : "[NOT FOUND]")}");

        Console.WriteLine("\n[2] Windows Kernel Environment:");
        Console.WriteLine($"    Test Signing Mode (BCD) : {(testSigning ? "[ENABLED]" : "[DISABLED]")}");

        Console.WriteLine("\n[3] Service Configuration:");
        Console.WriteLine($"    Service Name : {ServiceName}");
        Console.WriteLine($"    Installed    : {(svcInstalled ? "[YES]" : "[NO]")}");
        Console.WriteLine($"    State        : {svcStatus}");

        Console.WriteLine("\n[4] Active Filter Attachments (Classes & Devices):");
        var activeFilters = GetActiveFilterAttachments();
        if (activeFilters.Count == 0)
        {
            Console.WriteLine("    No active LowerFilter / UpperFilter attachments configured.");
        }
        else
        {
            foreach (var af in activeFilters)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"    - {af}");
                Console.ResetColor();
            }
        }

        Console.WriteLine("\n[5] User-Mode Communication Endpoint:");
        Console.WriteLine($"    Device Link  : \\\\.\\{ServiceName}");
        Console.WriteLine($"    Accessibility: {(devAccessible ? "[ACCESSIBLE - READY FOR CAPTURE]" : "[NOT ACTIVE]")}");

        if (devAccessible && client.Connect())
        {
            var stats = client.GetStats();
            if (stats.HasValue)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"\n[6] Live Driver Statistics:");
                Console.WriteLine($"    Driver Version   : 0x{stats.Value.DriverVersion:X8}");
                Console.WriteLine($"    Packets Captured : {stats.Value.TotalPacketsCaptured:N0}");
                Console.WriteLine($"    Packets Dropped  : {stats.Value.TotalPacketsDropped:N0}");
                Console.WriteLine($"    Bytes Captured   : {stats.Value.TotalBytesCaptured:N0}");
                Console.WriteLine($"    Queued / Max     : {stats.Value.CurrentlyQueued} / {stats.Value.MaxQueueCapacity}");
                Console.ResetColor();
            }
        }
        else if (!testSigning)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n[!] Setup Guidance:");
            Console.WriteLine("    To run the kernel filter driver on Windows 64-bit:");
            Console.WriteLine("    1. Enable test signing: 'bcdedit /set testsigning on'");
            Console.WriteLine("    2. Restart your computer.");
            Console.WriteLine("    3. Attach filter to target: 'UsbMonitor --attach-device <InstanceId>' or '--attach-class <class>'");
            Console.WriteLine("    4. Run: 'UsbMonitor --capture'");
            Console.ResetColor();
        }

        Console.WriteLine();
    }
}
