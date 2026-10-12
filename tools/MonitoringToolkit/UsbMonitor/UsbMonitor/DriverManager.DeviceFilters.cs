using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Microsoft.Win32;

namespace PhoenixGSM.UsbMonitor;

public static partial class DriverManager
{
    #region Device Instance Filter Management (Surgical Per-Device LowerFilter & UpperFilter)

    public static bool AttachDeviceLowerFilter(string instanceId, bool restartDevice = true)
    {
        // Enterprise Safety: Create atomic snapshot before modifying device registry
        AutoBackupDeviceKey(instanceId);

        string regPath = @"SYSTEM\CurrentControlSet\Enum\" + instanceId.TrimStart('\\');
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(regPath, true);
            if (key == null)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"  [-] Device Instance registry key not found: HKLM\\{regPath}");
                Console.ResetColor();
                return false;
            }

            var val = key.GetValue("LowerFilters");
            string[] existing = Array.Empty<string>();
            if (val is string[] arr) existing = arr;
            else if (val is string s && !string.IsNullOrWhiteSpace(s)) existing = new[] { s };

            if (!existing.Any(x => x.Equals(ServiceName, StringComparison.OrdinalIgnoreCase)))
            {
                var updated = existing.Concat(new[] { ServiceName }).ToArray();
                key.SetValue("LowerFilters", updated, RegistryValueKind.MultiString);
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"  [+] Successfully attached '{ServiceName}' as LowerFilter for device '{instanceId}'.");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"  [*] '{ServiceName}' already attached to device '{instanceId}'.");
                Console.ResetColor();
            }

            if (restartDevice)
            {
                RestartDevice(instanceId);
            }

            return true;
        }
        catch (UnauthorizedAccessException)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("  [-] Access Denied: Administrator privileges required to attach device filter.");
            Console.ResetColor();
            return false;
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  [-] Failed to attach device filter: {ex.Message}");
            Console.ResetColor();
            return false;
        }
    }

    public static bool DetachDeviceLowerFilter(string instanceId, bool restartDevice = true)
    {
        string regPath = @"SYSTEM\CurrentControlSet\Enum\" + instanceId.TrimStart('\\');
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(regPath, true);
            if (key == null) return false;

            var val = key.GetValue("LowerFilters");
            if (val is string[] arr)
            {
                var filtered = arr.Where(x => !x.Equals(ServiceName, StringComparison.OrdinalIgnoreCase)).ToArray();
                if (filtered.Length == 0) key.DeleteValue("LowerFilters", false);
                else key.SetValue("LowerFilters", filtered, RegistryValueKind.MultiString);

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"  [+] Successfully detached '{ServiceName}' from device '{instanceId}'.");
                Console.ResetColor();
            }

            if (restartDevice)
            {
                RestartDevice(instanceId);
            }

            return true;
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  [-] Failed to detach device filter: {ex.Message}");
            Console.ResetColor();
            return false;
        }
    }

    public static bool AttachDeviceUpperFilter(string instanceId, bool restartDevice = true)
    {
        // Enterprise Safety: Create atomic snapshot before modifying device registry
        AutoBackupDeviceKey(instanceId);

        string regPath = @"SYSTEM\CurrentControlSet\Enum\" + instanceId.TrimStart('\\');
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(regPath, true);
            if (key == null)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"  [-] Device Instance registry key not found: HKLM\\{regPath}");
                Console.ResetColor();
                return false;
            }

            var val = key.GetValue("UpperFilters");
            string[] existing = Array.Empty<string>();
            if (val is string[] arr) existing = arr;
            else if (val is string s && !string.IsNullOrWhiteSpace(s)) existing = new[] { s };

            if (!existing.Any(x => x.Equals(ServiceName, StringComparison.OrdinalIgnoreCase)))
            {
                var updated = existing.Concat(new[] { ServiceName }).ToArray();
                key.SetValue("UpperFilters", updated, RegistryValueKind.MultiString);
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"  [+] Successfully attached '{ServiceName}' as UpperFilter for device '{instanceId}'.");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"  [*] '{ServiceName}' already attached as UpperFilter to device '{instanceId}'.");
                Console.ResetColor();
            }

            if (restartDevice)
            {
                RestartDevice(instanceId);
            }

            return true;
        }
        catch (UnauthorizedAccessException)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("  [-] Access Denied: Administrator privileges required to attach device UpperFilter.");
            Console.ResetColor();
            return false;
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  [-] Failed to attach device UpperFilter: {ex.Message}");
            Console.ResetColor();
            return false;
        }
    }

    public static bool DetachDeviceUpperFilter(string instanceId, bool restartDevice = true)
    {
        string regPath = @"SYSTEM\CurrentControlSet\Enum\" + instanceId.TrimStart('\\');
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(regPath, true);
            if (key == null) return false;

            var val = key.GetValue("UpperFilters");
            if (val is string[] arr)
            {
                var filtered = arr.Where(x => !x.Equals(ServiceName, StringComparison.OrdinalIgnoreCase)).ToArray();
                if (filtered.Length == 0) key.DeleteValue("UpperFilters", false);
                else key.SetValue("UpperFilters", filtered, RegistryValueKind.MultiString);

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"  [+] Successfully detached '{ServiceName}' UpperFilter from device '{instanceId}'.");
                Console.ResetColor();
            }

            if (restartDevice)
            {
                RestartDevice(instanceId);
            }

            return true;
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  [-] Failed to detach device UpperFilter: {ex.Message}");
            Console.ResetColor();
            return false;
        }
    }

    public static bool RestartDevice(string instanceId)
    {
        try
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"  [*] Restarting device '{instanceId}' via PnPUtil...");
            Console.ResetColor();

            var psi = new ProcessStartInfo
            {
                FileName = "pnputil.exe",
                Arguments = $"/restart-device \"{instanceId}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi);
            proc?.WaitForExit();
            string stdout = proc?.StandardOutput.ReadToEnd() ?? "";

            if (proc?.ExitCode == 0 || stdout.Contains("successfully"))
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"  [+] Device restarted successfully. Filter driver loaded.");
                Console.ResetColor();
                return true;
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"  [!] PnPUtil returned: {stdout.Trim()}");
                Console.WriteLine($"      (You can unplug and replug the USB cable for changes to take effect)");
                Console.ResetColor();
                return false;
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"  [!] Could not automatically restart device: {ex.Message}");
            Console.ResetColor();
            return false;
        }
    }

    #endregion
}
