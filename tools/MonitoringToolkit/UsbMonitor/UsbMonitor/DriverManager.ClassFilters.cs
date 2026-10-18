using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Microsoft.Win32;

namespace PhoenixGSM.UsbMonitor;

public static partial class DriverManager
{
    #region Class LowerFilters Management & WinUSB Assertion Prevention

    /// <summary>
    /// Cleans all conflicting UpperFilters on USB/WinUSB/Android classes and device nodes,
    /// removes global ClassWinUsb LowerFilters that collide with composite parent devices,
    /// and purges non-WinUSB ghost entries from GUID_ANDROID_USB_DEVICE_CLASS
    /// ({f72fe0d4-cbcb-407d-8814-9ed673d0dd6b}) so tools like KEY-Tool.exe (AdbWinUsbApi)
    /// never fail WinUsb_Initialize or trigger "Expression: INVALID_HANDLE_VALUE == usb_device_handle_".
    /// </summary>
    public static void SanitizeWinUsbAndAndroidStack()
    {
        try
        {
            // 1. Never allow UpperFilters on Android, WinUSB, or USB Hub classes
            CleanConflictingUpperFilters(ClassAndroid);
            CleanConflictingUpperFilters(ClassWinUsb);
            CleanConflictingUpperFilters(ClassUsb);

            // 2. Clean any UpperFilters attached to individual WinUSB / Android / Composite USB device instances
            using var usbEnumKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\USB", true);
            if (usbEnumKey != null)
            {
                foreach (string vidPid in usbEnumKey.GetSubKeyNames())
                {
                    try
                    {
                        using var devGroupKey = usbEnumKey.OpenSubKey(vidPid, true);
                        if (devGroupKey == null) continue;

                        foreach (string instName in devGroupKey.GetSubKeyNames())
                        {
                            try
                            {
                                using var instKey = devGroupKey.OpenSubKey(instName, true);
                                if (instKey == null) continue;

                                string service = (instKey.GetValue("Service") as string ?? "").Trim();
                                string classGuid = (instKey.GetValue("ClassGUID") as string ?? "").Trim();

                                bool isWinUsbOrComposite =
                                    service.Equals("WINUSB", StringComparison.OrdinalIgnoreCase) ||
                                    service.Equals("usbccgp", StringComparison.OrdinalIgnoreCase) ||
                                    service.Equals("WUDFRd", StringComparison.OrdinalIgnoreCase) ||
                                    classGuid.Equals(ClassAndroid, StringComparison.OrdinalIgnoreCase) ||
                                    classGuid.Equals(ClassWinUsb, StringComparison.OrdinalIgnoreCase) ||
                                    classGuid.Equals(ClassUsb, StringComparison.OrdinalIgnoreCase);

                                if (isWinUsbOrComposite)
                                {
                                    var upVal = instKey.GetValue("UpperFilters");
                                    if (upVal is string[] upArr && upArr.Any(s => s.Equals(ServiceName, StringComparison.OrdinalIgnoreCase)))
                                    {
                                        var cleaned = upArr.Where(s => !s.Equals(ServiceName, StringComparison.OrdinalIgnoreCase)).ToArray();
                                        if (cleaned.Length == 0) instKey.DeleteValue("UpperFilters", false);
                                        else instKey.SetValue("UpperFilters", cleaned, RegistryValueKind.MultiString);
                                    }
                                    else if (upVal is string upStr && upStr.Equals(ServiceName, StringComparison.OrdinalIgnoreCase))
                                    {
                                        instKey.DeleteValue("UpperFilters", false);
                                    }
                                }

                                // Also remove LowerFilters from usbccgp composite parent nodes so only the actual leaf WinUSB interface is filtered
                                if (service.Equals("usbccgp", StringComparison.OrdinalIgnoreCase))
                                {
                                    var lowVal = instKey.GetValue("LowerFilters");
                                    if (lowVal is string[] lowArr && lowArr.Any(s => s.Equals(ServiceName, StringComparison.OrdinalIgnoreCase)))
                                    {
                                        var cleaned = lowArr.Where(s => !s.Equals(ServiceName, StringComparison.OrdinalIgnoreCase)).ToArray();
                                        if (cleaned.Length == 0) instKey.DeleteValue("LowerFilters", false);
                                        else instKey.SetValue("LowerFilters", cleaned, RegistryValueKind.MultiString);
                                    }
                                    else if (lowVal is string lowStr && lowStr.Equals(ServiceName, StringComparison.OrdinalIgnoreCase))
                                    {
                                        instKey.DeleteValue("LowerFilters", false);
                                    }
                                }
                            }
                            catch { }
                        }
                    }
                    catch { }
                }
            }

            // 3. Clean non-WinUSB ghost interfaces under GUID_ANDROID_USB_DEVICE_CLASS ({f72fe0d4-cbcb-407d-8814-9ed673d0dd6b})
            // When a non-WinUSB device (e.g. usbccgp parent, modem, or internal device) is listed here,
            // AdbWinApi.dll opens it with CreateFile (succeeds) and calls WinUsb_Initialize (fails!),
            // triggering adb_winusb_interface.cpp Line 42: "INVALID_HANDLE_VALUE == usb_device_handle_".
            const string adbInterfaceClassKeyPath = @"SYSTEM\CurrentControlSet\Control\DeviceClasses\{f72fe0d4-cbcb-407d-8814-9ed673d0dd6b}";
            using var adbIfKey = Registry.LocalMachine.OpenSubKey(adbInterfaceClassKeyPath, true);
            if (adbIfKey != null)
            {
                foreach (string subName in adbIfKey.GetSubKeyNames())
                {
                    try
                    {
                        using var subKey = adbIfKey.OpenSubKey(subName, true);
                        string devInstance = (subKey?.GetValue("DeviceInstance") as string ?? "").Trim();
                        if (string.IsNullOrEmpty(devInstance)) continue;

                        using var enumInstKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\" + devInstance, false);
                        if (enumInstKey == null) continue;

                        string svc = (enumInstKey.GetValue("Service") as string ?? "").Trim();
                        if (!string.IsNullOrEmpty(svc) && !svc.Equals("WINUSB", StringComparison.OrdinalIgnoreCase))
                        {
                            subKey?.Close();
                            adbIfKey.DeleteSubKeyTree(subName, false);
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }
    }

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

        // Always sanitize UpperFilters and ghost Android interfaces first to prevent AdbWinUsbApi Line 42 assertion
        SanitizeWinUsbAndAndroidStack();

        // If user clicked "Enable WinUSB Filter", remove any global ClassWinUsb ({88BAE032-...}) filter
        // that collides with composite parents/3uTools/non-phone devices, and route cleanly to ClassAndroid ({3F966BD9-...})
        if (targetGuid.Equals(ClassWinUsb, StringComparison.OrdinalIgnoreCase))
        {
            RemoveLowerFilter(ClassWinUsb, restartDevices: false);
            targetGuid = ClassAndroid;
        }

        string keyPath = @"SYSTEM\CurrentControlSet\Control\Class\" + targetGuid;

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

            CleanConflictingUpperFilters(targetGuid);

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

            CleanConflictingUpperFilters(targetGuid);

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
            if (val is string[] array && array.Any(s =>
                s.Equals(ServiceName, StringComparison.OrdinalIgnoreCase) ||
                s.Equals("UsbDk", StringComparison.OrdinalIgnoreCase) ||
                s.Equals("USBPcap", StringComparison.OrdinalIgnoreCase)))
            {
                var filtered = array.Where(s =>
                    !s.Equals(ServiceName, StringComparison.OrdinalIgnoreCase) &&
                    !s.Equals("UsbDk", StringComparison.OrdinalIgnoreCase) &&
                    !s.Equals("USBPcap", StringComparison.OrdinalIgnoreCase)).ToArray();

                if (filtered.Length == 0)
                {
                    key.DeleteValue("UpperFilters", false);
                }
                else
                {
                    key.SetValue("UpperFilters", filtered, RegistryValueKind.MultiString);
                }

                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"  [*] Cleaned conflicting UpperFilters from Class {targetGuid}.");
                Console.ResetColor();
            }
            else if (val is string single && (
                single.Equals(ServiceName, StringComparison.OrdinalIgnoreCase) ||
                single.Equals("UsbDk", StringComparison.OrdinalIgnoreCase) ||
                single.Equals("USBPcap", StringComparison.OrdinalIgnoreCase)))
            {
                key.DeleteValue("UpperFilters", false);
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

        // Safety guard: NEVER attach UpperFilter to Android, WinUSB, or USB Hub classes!
        if (targetGuid.Equals(ClassAndroid, StringComparison.OrdinalIgnoreCase) ||
            targetGuid.Equals(ClassWinUsb, StringComparison.OrdinalIgnoreCase) ||
            targetGuid.Equals(ClassUsb, StringComparison.OrdinalIgnoreCase))
        {
            return ConfigureLowerFilter(targetGuid);
        }

        string keyPath = @"SYSTEM\CurrentControlSet\Control\Class\" + targetGuid;

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
        SanitizeWinUsbAndAndroidStack();
        bool okPorts = ConfigureUpperFilter(ClassPorts, restartDevices);
        bool okModem = ConfigureUpperFilter(ClassModem, restartDevices);
        return okPorts || okModem;
    }

    public static bool RemovePortAndModemFilters(bool restartDevices = true)
    {
        SanitizeWinUsbAndAndroidStack();
        bool okPortsUp = RemoveUpperFilter(ClassPorts, restartDevices);
        bool okPortsLow = RemoveLowerFilter(ClassPorts, restartDevices);
        bool okModemUp = RemoveUpperFilter(ClassModem, restartDevices);
        bool okModemLow = RemoveLowerFilter(ClassModem, restartDevices);
        return okPortsUp || okPortsLow || okModemUp || okModemLow;
    }

    #endregion
}
