using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Microsoft.Win32;

namespace PhoenixGSM.UsbMonitor;

public static partial class DriverManager
{
    #region Class LowerFilters Management

    public static bool IsLowerFilterConfigured(string classGuid = ClassAndroid)
    {
        try
        {
            string keyPath = @"SYSTEM\CurrentControlSet\Control\Class\" + ResolveClassGuid(classGuid);
            using var key = Registry.LocalMachine.OpenSubKey(keyPath, false);
            if (key == null) return false;

            var val = key.GetValue("LowerFilters");
            if (val is string[] array)
            {
                return array.Any(s => s.Equals(ServiceName, StringComparison.OrdinalIgnoreCase));
            }
            if (val is string str)
            {
                return str.Equals(ServiceName, StringComparison.OrdinalIgnoreCase);
            }
            return false;
        }
        catch
        {
            return false;
        }
    }

    public static bool ConfigureLowerFilter(string classGuid = ClassAndroid)
    {
        string targetGuid = ResolveClassGuid(classGuid);
        string keyPath = @"SYSTEM\CurrentControlSet\Control\Class\" + targetGuid;

        // Enterprise Safety: Create atomic registry snapshot before any change
        AutoBackupClassKey(targetGuid);

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(keyPath, true);
            if (key == null)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"  [-] Registry class key not found: HKLM\\{keyPath}");
                Console.ResetColor();
                return false;
            }

            if (targetGuid.Equals(ClassAndroid, StringComparison.OrdinalIgnoreCase))
            {
                CleanConflictingUpperFilters(targetGuid);
            }

            var val = key.GetValue("LowerFilters");
            string[] existing = Array.Empty<string>();

            if (val is string[] array)
            {
                existing = array;
            }
            else if (val is string single && !string.IsNullOrWhiteSpace(single))
            {
                existing = new[] { single };
            }

            if (existing.Any(s => s.Equals(ServiceName, StringComparison.OrdinalIgnoreCase)))
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"  [*] '{ServiceName}' is already in LowerFilters for Class {targetGuid}.");
                Console.ResetColor();
                return true;
            }

            var updated = existing.Concat(new[] { ServiceName }).ToArray();
            key.SetValue("LowerFilters", updated, RegistryValueKind.MultiString);

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  [+] Successfully added '{ServiceName}' to Class {targetGuid} LowerFilters.");
            Console.WriteLine($"      Active LowerFilters: {string.Join(", ", updated)}");
            Console.ResetColor();
            return true;
        }
        catch (UnauthorizedAccessException)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("  [-] Access Denied: Administrator privileges required to modify registry LowerFilters.");
            Console.ResetColor();
            return false;
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  [-] Error configuring LowerFilters: {ex.Message}");
            Console.ResetColor();
            return false;
        }
    }

    public static bool RemoveLowerFilter(string classGuid = ClassAndroid, bool restartDevices = false)
    {
        string targetGuid = ResolveClassGuid(classGuid);
        string keyPath = @"SYSTEM\CurrentControlSet\Control\Class\" + targetGuid;

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(keyPath, true);
            if (key == null) return false;

            var val = key.GetValue("LowerFilters");
            if (val is string[] array)
            {
                var filtered = array.Where(s => !s.Equals(ServiceName, StringComparison.OrdinalIgnoreCase)).ToArray();
                if (filtered.Length == 0)
                {
                    key.DeleteValue("LowerFilters", false);
                }
                else
                {
                    key.SetValue("LowerFilters", filtered, RegistryValueKind.MultiString);
                }

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"  [+] Removed '{ServiceName}' from Class {targetGuid} LowerFilters.");
                Console.ResetColor();
            }
            else if (val is string single && single.Equals(ServiceName, StringComparison.OrdinalIgnoreCase))
            {
                key.DeleteValue("LowerFilters", false);
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"  [+] Removed '{ServiceName}' from Class {targetGuid} LowerFilters.");
                Console.ResetColor();
            }

            if (targetGuid.Equals(ClassAndroid, StringComparison.OrdinalIgnoreCase))
            {
                CleanConflictingUpperFilters(targetGuid);
            }

            if (restartDevices)
            {
                RestartActiveDevicesOfClass(targetGuid);
            }

            return true;
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  [-] Error removing LowerFilter: {ex.Message}");
            Console.ResetColor();
            return false;
        }
    }

    public static bool CleanConflictingUpperFilters(string classGuid = ClassAndroid)
    {
        string targetGuid = ResolveClassGuid(classGuid);
        string keyPath = @"SYSTEM\CurrentControlSet\Control\Class\" + targetGuid;

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(keyPath, true);
            if (key == null) return false;

            var val = key.GetValue("UpperFilters");
            if (val is string[] array && array.Any(s => s.Equals(ServiceName, StringComparison.OrdinalIgnoreCase)))
            {
                var filtered = array.Where(s => !s.Equals(ServiceName, StringComparison.OrdinalIgnoreCase)).ToArray();
                if (filtered.Length == 0)
                {
                    key.DeleteValue("UpperFilters", false);
                }
                else
                {
                    key.SetValue("UpperFilters", filtered, RegistryValueKind.MultiString);
                }

                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"  [*] Cleaned conflicting '{ServiceName}' from Class {targetGuid} UpperFilters.");
                Console.ResetColor();
            }
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static bool IsUpperFilterConfigured(string classGuid = ClassPorts)
    {
        try
        {
            string keyPath = @"SYSTEM\CurrentControlSet\Control\Class\" + ResolveClassGuid(classGuid);
            using var key = Registry.LocalMachine.OpenSubKey(keyPath, false);
            if (key == null) return false;

            var val = key.GetValue("UpperFilters");
            if (val is string[] array)
            {
                return array.Any(s => s.Equals(ServiceName, StringComparison.OrdinalIgnoreCase));
            }
            if (val is string str)
            {
                return str.Equals(ServiceName, StringComparison.OrdinalIgnoreCase);
            }
            return false;
        }
        catch
        {
            return false;
        }
    }

    public static bool ConfigureUpperFilter(string classGuid = ClassPorts, bool restartDevices = false)
    {
        string targetGuid = ResolveClassGuid(classGuid);
        string keyPath = @"SYSTEM\CurrentControlSet\Control\Class\" + targetGuid;

        // Enterprise Safety: Create atomic registry snapshot before any change
        AutoBackupClassKey(targetGuid);

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(keyPath, true);
            if (key == null)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"  [-] Registry class key not found: HKLM\\{keyPath}");
                Console.ResetColor();
                return false;
            }

            var val = key.GetValue("UpperFilters");
            string[] existing = Array.Empty<string>();

            if (val is string[] array)
            {
                existing = array;
            }
            else if (val is string single && !string.IsNullOrWhiteSpace(single))
            {
                existing = new[] { single };
            }

            bool alreadyPresent = existing.Any(s => s.Equals(ServiceName, StringComparison.OrdinalIgnoreCase));
            if (!alreadyPresent)
            {
                var updated = existing.Concat(new[] { ServiceName }).ToArray();
                key.SetValue("UpperFilters", updated, RegistryValueKind.MultiString);

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"  [+] Successfully added '{ServiceName}' to Class {targetGuid} UpperFilters.");
                Console.WriteLine($"      Active UpperFilters: {string.Join(", ", updated)}");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"  [*] '{ServiceName}' is already in UpperFilters for Class {targetGuid}.");
                Console.ResetColor();
            }

            if (restartDevices)
            {
                RestartActiveDevicesOfClass(targetGuid);
            }

            return true;
        }
        catch (UnauthorizedAccessException)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("  [-] Access Denied: Administrator privileges required to modify registry UpperFilters.");
            Console.ResetColor();
            return false;
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  [-] Error configuring UpperFilters: {ex.Message}");
            Console.ResetColor();
            return false;
        }
    }

    public static int RestartActiveDevicesOfClass(string classGuidOrName)
    {
        string targetGuid = ResolveClassGuid(classGuidOrName);
        int restarted = 0;
        var connectedInstances = new List<string>();

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "pnputil.exe",
                Arguments = "/enum-devices /connected",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi);
            string output = proc?.StandardOutput.ReadToEnd() ?? "";
            proc?.WaitForExit();

            string currentInstance = "";
            using var reader = new StringReader(output);
            string? line;
            while ((line = reader.ReadLine()) != null)
            {
                string trimmed = line.Trim();
                if (trimmed.StartsWith("Instance ID:", StringComparison.OrdinalIgnoreCase))
                {
                    currentInstance = trimmed.Substring(12).Trim();
                }
                else if (trimmed.StartsWith("Class GUID:", StringComparison.OrdinalIgnoreCase))
                {
                    string guid = trimmed.Substring(11).Trim();
                    if (!string.IsNullOrEmpty(currentInstance) &&
                        guid.Equals(targetGuid, StringComparison.OrdinalIgnoreCase))
                    {
                        connectedInstances.Add(currentInstance);
                    }
                }
            }
        }
        catch { }

        if (connectedInstances.Count > 0)
        {
            foreach (var inst in connectedInstances)
            {
                if (RestartDevice(inst))
                {
                    restarted++;
                }
            }
        }

        return restarted;
    }

    public static bool RemoveUpperFilter(string classGuid = ClassPorts, bool restartDevices = false)
    {
        string targetGuid = ResolveClassGuid(classGuid);
        string keyPath = @"SYSTEM\CurrentControlSet\Control\Class\" + targetGuid;

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(keyPath, true);
            if (key == null) return false;

            var val = key.GetValue("UpperFilters");
            if (val is string[] array)
            {
                var filtered = array.Where(s => !s.Equals(ServiceName, StringComparison.OrdinalIgnoreCase)).ToArray();
                if (filtered.Length == 0)
                {
                    key.DeleteValue("UpperFilters", false);
                }
                else
                {
                    key.SetValue("UpperFilters", filtered, RegistryValueKind.MultiString);
                }

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"  [+] Removed '{ServiceName}' from Class {targetGuid} UpperFilters.");
                Console.ResetColor();
            }
            else if (val is string single && single.Equals(ServiceName, StringComparison.OrdinalIgnoreCase))
            {
                key.DeleteValue("UpperFilters", false);
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"  [+] Removed '{ServiceName}' from Class {targetGuid} UpperFilters.");
                Console.ResetColor();
            }

            if (restartDevices)
            {
                RestartActiveDevicesOfClass(targetGuid);
            }

            return true;
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  [-] Error removing UpperFilter: {ex.Message}");
            Console.ResetColor();
            return false;
        }
    }

    public static bool IsPortAndModemFilterConfigured()
    {
        return IsUpperFilterConfigured(ClassPorts) ||
               IsUpperFilterConfigured(ClassModem) ||
               IsLowerFilterConfigured(ClassPorts) ||
               IsLowerFilterConfigured(ClassModem);
    }

    public static bool ConfigurePortAndModemFilters(bool restartDevices = true)
    {
        bool okPorts = ConfigureUpperFilter(ClassPorts, restartDevices);
        bool okModem = ConfigureUpperFilter(ClassModem, restartDevices);
        return okPorts || okModem;
    }

    public static bool RemovePortAndModemFilters(bool restartDevices = true)
    {
        bool okPortsUp = RemoveUpperFilter(ClassPorts, restartDevices);
        bool okPortsLow = RemoveLowerFilter(ClassPorts, restartDevices);
        bool okModemUp = RemoveUpperFilter(ClassModem, restartDevices);
        bool okModemLow = RemoveLowerFilter(ClassModem, restartDevices);
        return okPortsUp || okPortsLow || okModemUp || okModemLow;
    }

    #endregion
}
