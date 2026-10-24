using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using PhoenixGSM.UsbMonitorDiscovery.Models;

namespace PhoenixGSM.UsbMonitorDiscovery;

public class UsbScanner
{
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_SHARE_READ = 1;
    private const uint FILE_SHARE_WRITE = 2;
    private const uint OPEN_EXISTING = 3;

    private const uint IOCTL_USB_GET_NODE_INFORMATION = 0x220408;
    private const uint IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX = 0x220448;
    private const uint IOCTL_USB_GET_NODE_CONNECTION_INFORMATION = 0x22040C;
    private const uint IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION = 0x220410;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern SafeFileHandle CreateFile(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition,
        uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(
        SafeFileHandle hDevice, uint dwIoControlCode,
        IntPtr lpInBuffer, uint nInBufferSize,
        IntPtr lpOutBuffer, uint nOutBufferSize,
        out uint lpBytesReturned, IntPtr lpOverlapped);

    public bool EnableDebug { get; set; }

    public List<UsbDeviceInfo> ScanAllDevices()
    {
        var devices = new List<UsbDeviceInfo>();
        var hubPaths = GetHubPaths();
        if (EnableDebug)
        {
            Console.WriteLine($"[DEBUG] Found {hubPaths.Count} hub paths:");
            foreach (var h in hubPaths) Console.WriteLine($"  - {h}");
        }

        foreach (var hubPath in hubPaths)
        {
            var hubDevices = ScanHub(hubPath);
            foreach (var d in hubDevices)
            {
                // Avoid duplicates if scanned across aliases
                if (!devices.Any(existing => existing.Vid == d.Vid && existing.Pid == d.Pid && existing.PortNumber == d.PortNumber))
                {
                    devices.Add(d);
                }
            }
        }

        // Correlate with Windows PnP details
        CorrelateWithPnP(devices);

        return devices;
    }

    public List<string> GetHubPaths()
    {
        var paths = new List<string>();
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\DeviceClasses\{f18a0e88-c30c-11d0-8815-00a0c906bed8}");
            if (key != null)
            {
                foreach (var subName in key.GetSubKeyNames())
                {
                    if (subName.StartsWith("##?#"))
                    {
                        var clean = subName.Substring(4);
                        paths.Add(@"\\.\" + clean);
                    }
                    else if (subName.StartsWith(@"\\?\") || subName.StartsWith(@"\\.\"))
                    {
                        paths.Add(subName);
                    }
                }
            }
        }
        catch { }

        // Standard Host Controllers fallback
        for (int i = 0; i < 4; i++)
        {
            paths.Add($@"\\.\HCD{i}");
        }

        return paths.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private List<UsbDeviceInfo> ScanHub(string hubPath)
    {
        var devices = new List<UsbDeviceInfo>();

        // Open hub with query access (0 desired access) so we never contend or block hardware PnP enumeration
        using var hHub = CreateFile(hubPath, 0, FILE_SHARE_WRITE | FILE_SHARE_READ, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (hHub.IsInvalid)
        {
            if (EnableDebug) Console.WriteLine($"[DEBUG] Failed to open {hubPath} with query access. Error: {Marshal.GetLastWin32Error()}");
            return devices;
        }

        return QueryHubHandle(hHub, hubPath);
    }

    private List<UsbDeviceInfo> QueryHubHandle(SafeFileHandle hHub, string hubPath)
    {
        var devices = new List<UsbDeviceInfo>();

        int nodeInfoSize = 76;
        IntPtr nodeBuf = Marshal.AllocHGlobal(nodeInfoSize);
        byte numPorts = 0;

        try
        {
            if (DeviceIoControl(hHub, IOCTL_USB_GET_NODE_INFORMATION, nodeBuf, (uint)nodeInfoSize, nodeBuf, (uint)nodeInfoSize, out _, IntPtr.Zero))
            {
                numPorts = Marshal.ReadByte(nodeBuf, 6);
                if (EnableDebug) Console.WriteLine($"[DEBUG] Hub {hubPath} opened! Ports: {numPorts}");
            }
            else
            {
                if (EnableDebug) Console.WriteLine($"[DEBUG] Hub {hubPath} GET_NODE_INFORMATION failed. Error: {Marshal.GetLastWin32Error()}");
            }
        }
        finally
        {
            Marshal.FreeHGlobal(nodeBuf);
        }

        if (numPorts == 0 || numPorts > 64)
            numPorts = 16;

        int connSize = 2048;
        IntPtr connBuf = Marshal.AllocHGlobal(connSize);

        try
        {
            for (int port = 1; port <= numPorts; port++)
            {
                for (int i = 0; i < connSize; i++) Marshal.WriteByte(connBuf, i, 0);
                Marshal.WriteInt32(connBuf, 0, port);

                bool ok = DeviceIoControl(hHub, IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX, connBuf, (uint)connSize, connBuf, (uint)connSize, out uint retBytes, IntPtr.Zero);
                bool isEx = true;
                if (!ok)
                {
                    for (int i = 0; i < connSize; i++) Marshal.WriteByte(connBuf, i, 0);
                    Marshal.WriteInt32(connBuf, 0, port);
                    ok = DeviceIoControl(hHub, IOCTL_USB_GET_NODE_CONNECTION_INFORMATION, connBuf, (uint)connSize, connBuf, (uint)connSize, out retBytes, IntPtr.Zero);
                    isEx = false;
                }

                if (ok)
                {
                    ushort vid = (ushort)Marshal.ReadInt16(connBuf, 4 + 8);
                    ushort pid = (ushort)Marshal.ReadInt16(connBuf, 4 + 10);
                    int connectionStatus = Marshal.ReadInt32(connBuf, isEx ? 32 : 24);

                    if (EnableDebug)
                    {
                        Console.WriteLine($"[DEBUG] Port {port}: Status={connectionStatus}, VID={vid:X4}, PID={pid:X4}, isEx={isEx}");
                    }

                    if (vid == 0 && pid == 0) continue; // No device on this port
                    byte devClass = Marshal.ReadByte(connBuf, 4 + 4);
                    byte devSubClass = Marshal.ReadByte(connBuf, 4 + 5);
                    byte devProto = Marshal.ReadByte(connBuf, 4 + 6);

                    string speed = "HighSpeed";
                    if (isEx)
                    {
                        int speedVal = Marshal.ReadInt32(connBuf, 36);
                        speed = speedVal switch
                        {
                            0 => "LowSpeed (1.5 Mbps)",
                            1 => "FullSpeed (12 Mbps)",
                            2 => "HighSpeed (480 Mbps)",
                            3 => "SuperSpeed (5 Gbps)",
                            4 => "SuperSpeedPlus (10 Gbps)",
                            _ => "Standard Speed"
                        };
                    }

                    var dev = new UsbDeviceInfo
                    {
                        Vid = vid,
                        Pid = pid,
                        PortNumber = port,
                        HubPath = hubPath,
                        Speed = speed
                    };

                    QueryConfigurationDescriptor(hHub, port, dev);

                    devices.Add(dev);
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(connBuf);
        }

        return devices;
    }

    private void QueryConfigurationDescriptor(SafeFileHandle hHub, int port, UsbDeviceInfo dev)
    {
        int reqSize = 4096;
        IntPtr reqBuf = Marshal.AllocHGlobal(reqSize);

        try
        {
            for (int i = 0; i < reqSize; i++) Marshal.WriteByte(reqBuf, i, 0);
            Marshal.WriteInt32(reqBuf, 0, port);
            Marshal.WriteByte(reqBuf, 4, 0x80); // bmRequestType (Device to Host)
            Marshal.WriteByte(reqBuf, 5, 0x06); // bRequest (GET_DESCRIPTOR)
            Marshal.WriteByte(reqBuf, 6, 0x00); // Descriptor Index (0)
            Marshal.WriteByte(reqBuf, 7, 0x02); // Descriptor Type (2 = CONFIGURATION)
            Marshal.WriteInt16(reqBuf, 8, 0);   // wIndex (0)
            Marshal.WriteInt16(reqBuf, 10, (short)(reqSize - 12)); // wLength

            if (DeviceIoControl(hHub, IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION, reqBuf, (uint)reqSize, reqBuf, (uint)reqSize, out uint returned, IntPtr.Zero))
            {
                if (EnableDebug) Console.WriteLine($"[DEBUG] Port {port}: GET_DESCRIPTOR returned {returned} bytes!");
                if (returned > 12)
                {
                    int descLength = (int)returned - 12;
                    byte[] desc = new byte[descLength];
                    Marshal.Copy(new IntPtr(reqBuf.ToInt64() + 12), desc, 0, descLength);

                    ParseConfigurationDescriptor(desc, dev);
                }
            }
            else
            {
                if (EnableDebug) Console.WriteLine($"[DEBUG] Port {port}: GET_DESCRIPTOR failed. Error: {Marshal.GetLastWin32Error()}");
            }
        }
        finally
        {
            Marshal.FreeHGlobal(reqBuf);
        }
    }

    private void ParseConfigurationDescriptor(byte[] desc, UsbDeviceInfo dev)
    {
        int offset = 0;
        UsbInterfaceInfo? currentIf = null;

        while (offset + 2 <= desc.Length)
        {
            byte len = desc[offset];
            if (len < 2 || offset + len > desc.Length) break;
            byte type = desc[offset + 1];

            if (type == 4 && len >= 9) // Interface Descriptor
            {
                byte ifNum = desc[offset + 2];
                byte alt = desc[offset + 3];
                byte numEp = desc[offset + 4];
                byte ifClass = desc[offset + 5];
                byte ifSubClass = desc[offset + 6];
                byte ifProto = desc[offset + 7];

                bool isAdb = (ifClass == 0xFF && ifSubClass == 0x42 && ifProto == 0x01);
                bool isModemOrCdc = (ifClass == 0x02 || ifClass == 0x0A || (ifClass == 0xFF && (ifSubClass is 0x01 or 0x02 or 0x03 or 0x06)));
                string descr = GetInterfaceClassDescription(ifClass, ifSubClass, ifProto);

                currentIf = new UsbInterfaceInfo
                {
                    InterfaceNumber = ifNum,
                    AlternateSetting = alt,
                    Class = ifClass,
                    SubClass = ifSubClass,
                    Protocol = ifProto,
                    ClassDescription = descr,
                    IsAdbInterface = isAdb
                };

                if (isAdb)
                {
                    dev.IsAndroidAdb = true;
                    dev.IsPhoneOrModem = true;
                }
                if (isModemOrCdc)
                {
                    dev.IsPhoneOrModem = true;
                    dev.IsModemInterface = true;
                }

                dev.Interfaces.Add(currentIf);
            }
            else if (type == 5 && len >= 7 && currentIf != null) // Endpoint Descriptor
            {
                byte epAddr = desc[offset + 2];
                byte attr = desc[offset + 3];
                ushort maxPacket = BitConverter.ToUInt16(desc, offset + 4);
                byte interval = desc[offset + 6];

                string dir = (epAddr & 0x80) != 0 ? "IN" : "OUT";
                string ttype = (attr & 0x03) switch
                {
                    0 => "CONTROL",
                    1 => "ISOCHRONOUS",
                    2 => "BULK",
                    3 => "INTERRUPT",
                    _ => "UNKNOWN"
                };

                currentIf.Endpoints.Add(new UsbEndpointInfo
                {
                    EndpointAddress = epAddr,
                    Direction = dir,
                    TransferType = ttype,
                    MaxPacketSize = maxPacket,
                    Interval = interval
                });
            }

            offset += len;
        }
    }

    private static string GetInterfaceClassDescription(byte cls, byte subCls, byte proto)
    {
        if (cls == 0xFF && subCls == 0x42 && proto == 0x01)
            return "Android ADB Interface (Class FFh, SubClass 42h, Proto 01h)";
        if (cls == 0xFF && subCls == 0x42 && proto == 0x03)
            return "Android Fastboot Interface (Class FFh, SubClass 42h, Proto 03h)";
        if (cls == 0x03)
            return "Human Interface Device (HID)";
        if (cls == 0x02)
            return "Communications and CDC Control (Modem/COM)";
        if (cls == 0x0A)
            return "CDC-Data";
        if (cls == 0x08)
            return "Mass Storage (U-Disk/MTP)";
        if (cls == 0xE0)
            return "Wireless Controller (Bluetooth)";
        if (cls == 0xFF)
            return $"Vendor Specific (SubClass 0x{subCls:X2}, Proto 0x{proto:X2})";

        return $"Standard Class 0x{cls:X2} (SubClass 0x{subCls:X2})";
    }

    private void CorrelateWithPnP(List<UsbDeviceInfo> devices)
    {
        var pnpMap = new Dictionary<string, PnpDevEntry>(StringComparer.OrdinalIgnoreCase);

        try
        {
            using var usbKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\USB");
            if (usbKey != null)
            {
                foreach (var deviceSubKeyName in usbKey.GetSubKeyNames())
                {
                    using var devKey = usbKey.OpenSubKey(deviceSubKeyName);
                    if (devKey == null) continue;

                    foreach (var instId in devKey.GetSubKeyNames())
                    {
                        using var instKey = devKey.OpenSubKey(instId);
                        if (instKey == null) continue;

                        var desc = instKey.GetValue("DeviceDesc")?.ToString() ?? "";
                        if (desc.Contains(";")) desc = desc.Substring(desc.IndexOf(';') + 1);
                        var friendly = instKey.GetValue("FriendlyName")?.ToString() ?? desc;
                        var srv = instKey.GetValue("Service")?.ToString() ?? "";
                        var cls = instKey.GetValue("Class")?.ToString() ?? "";
                        var fullInst = $@"USB\{deviceSubKeyName}\{instId}";

                        var entry = new PnpDevEntry
                        {
                            InstanceId = fullInst,
                            KeyName = deviceSubKeyName,
                            FriendlyName = string.IsNullOrWhiteSpace(friendly) ? desc : friendly,
                            Service = srv,
                            Class = cls
                        };

                        pnpMap[fullInst] = entry;
                    }
                }
            }
        }
        catch { }

        foreach (var dev in devices)
        {
            string vidPidPattern = $"VID_{dev.VidHex}&PID_{dev.PidHex}";

            var matching = pnpMap.Values
                .Where(p => p.KeyName.IndexOf(vidPidPattern, StringComparison.OrdinalIgnoreCase) >= 0)
                .ToList();

            var mainEntry = matching.FirstOrDefault(p => !p.KeyName.Contains("&MI_") && !p.KeyName.Contains("&ADB") && !p.KeyName.Contains("&MODEM"))
                           ?? matching.FirstOrDefault();

            if (mainEntry != null)
            {
                dev.DeviceName = mainEntry.FriendlyName;
                dev.InstanceId = mainEntry.InstanceId;
                dev.Driver = mainEntry.Service;
                dev.Service = mainEntry.Service;
                dev.Class = mainEntry.Class;
            }

            if (string.IsNullOrWhiteSpace(dev.DeviceName))
            {
                dev.DeviceName = GetKnownDeviceName(dev.Vid, dev.Pid);
            }

            foreach (var sub in matching.Where(p => p != mainEntry))
            {
                string? mi = null;
                int miIdx = sub.KeyName.IndexOf("&MI_", StringComparison.OrdinalIgnoreCase);
                if (miIdx >= 0 && miIdx + 6 <= sub.KeyName.Length)
                {
                    mi = sub.KeyName.Substring(miIdx + 4, 2);
                }
                else if (sub.KeyName.Contains("&ADB", StringComparison.OrdinalIgnoreCase))
                {
                    mi = "ADB";
                }
                else if (sub.KeyName.Contains("&MODEM", StringComparison.OrdinalIgnoreCase))
                {
                    mi = "MODEM";
                }

                dev.SubDevices.Add(new UsbSubDevicePnpInfo
                {
                    InstanceId = sub.InstanceId,
                    FriendlyName = sub.FriendlyName,
                    Class = sub.Class,
                    Service = sub.Service,
                    InterfaceNumber = mi
                });

                if (sub.Class.Equals("AndroidUsbDeviceClass", StringComparison.OrdinalIgnoreCase) ||
                    (sub.Service.Equals("WinUSB", StringComparison.OrdinalIgnoreCase) && sub.FriendlyName.Contains("ADB", StringComparison.OrdinalIgnoreCase)))
                {
                    dev.IsAndroidAdb = true;
                    dev.IsPhoneOrModem = true;
                }

                if (sub.Class.Equals("Modem", StringComparison.OrdinalIgnoreCase) ||
                    sub.FriendlyName.Contains("Modem", StringComparison.OrdinalIgnoreCase))
                {
                    dev.IsPhoneOrModem = true;
                    dev.IsModemInterface = true;
                }

                if (sub.Class.Equals("Ports", StringComparison.OrdinalIgnoreCase) ||
                    sub.FriendlyName.Contains("PC UI", StringComparison.OrdinalIgnoreCase) ||
                    sub.FriendlyName.Contains("Diagnostic", StringComparison.OrdinalIgnoreCase) ||
                    sub.FriendlyName.Contains("VCOM", StringComparison.OrdinalIgnoreCase) ||
                    sub.FriendlyName.Contains("Serial", StringComparison.OrdinalIgnoreCase))
                {
                    dev.IsPhoneOrModem = true;
                    dev.IsSerialPortInterface = true;
                }

                if (string.IsNullOrEmpty(dev.AttachedPort))
                {
                    var m = System.Text.RegularExpressions.Regex.Match(sub.FriendlyName, @"\((COM\d+)\)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                    if (m.Success)
                    {
                        dev.AttachedPort = m.Groups[1].Value.ToUpperInvariant();
                    }
                    else if (sub.Class.Equals("Modem", StringComparison.OrdinalIgnoreCase) || 
                             sub.FriendlyName.Contains("Modem", StringComparison.OrdinalIgnoreCase) || 
                             sub.KeyName.Contains("MODEM", StringComparison.OrdinalIgnoreCase))
                    {
                        // Resolve COM port for USB Modem from ClassModem registry
                        try
                        {
                            using var modemKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Class\{4D36E96D-E325-11CE-BFC1-08002BE10318}");
                            if (modemKey != null)
                            {
                                foreach (var subKeyName in modemKey.GetSubKeyNames())
                                {
                                    if (subKeyName.Length == 4 && int.TryParse(subKeyName, out _))
                                    {
                                        using var devK = modemKey.OpenSubKey(subKeyName);
                                        var attached = devK?.GetValue("AttachedTo")?.ToString();
                                        var matchId = devK?.GetValue("MatchingDeviceId")?.ToString();
                                        if (!string.IsNullOrWhiteSpace(attached) && attached.StartsWith("COM", StringComparison.OrdinalIgnoreCase))
                                        {
                                            string vidHex = dev.Vid.ToString("X4");
                                            if (!string.IsNullOrWhiteSpace(matchId) && 
                                                (sub.KeyName.IndexOf(matchId, StringComparison.OrdinalIgnoreCase) >= 0 ||
                                                 matchId.Contains(vidHex, StringComparison.OrdinalIgnoreCase)))
                                            {
                                                dev.AttachedPort = attached.ToUpperInvariant();
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        catch { }
                    }
                }
            }

            // Vendor check for known phone manufacturers (including Apple 0x05AC)
            bool isPhoneVendor = dev.Vid is 0x05AC or 0x12D1 or 0x04E8 or 0x2717 or 0x22D9 or 0x2B4E or 0x22B8 or 0x18D1 or 0x0E8D or 0x05C6 or 0x1782 or 0x1199 or 0x0BB4 or 0x1004 or 0x0FCE;
            if (isPhoneVendor)
            {
                dev.IsPhoneOrModem = true;
            }

            if (dev.Vid == 0x05AC)
            {
                dev.IsPhoneOrModem = true;
                dev.DeviceModeHint = dev.Pid switch
                {
                    0x1227 => "Apple DFU Mode (SecureROM 05AC:1227)",
                    0x1222 => "Apple WTF / DFU Mode (05AC:1222)",
                    0x1281 => "Apple Recovery / iBoot Mode (05AC:1281)",
                    0x4141 => "Apple PongoOS / Checkra1n Shell Mode (05AC:4141)",
                    0x1881 => "Apple Purple / Factory Diag Mode (05AC:1881)",
                    _ => "Apple iOS Normal Mode (usbmuxd / Lockdown)"
                };
            }
            else if (dev.IsAndroidAdb)
            {
                dev.DeviceModeHint = "ADB Mode";
            }
            else if (dev.Vid == 0x0E8D)
            {
                dev.IsPhoneOrModem = true;
                dev.DeviceModeHint = dev.Pid switch
                {
                    0x0003 => $"MTK BROM Mode{(dev.AttachedPort != null ? $" on {dev.AttachedPort}" : "")}",
                    0x2000 => $"MTK Preloader Mode{(dev.AttachedPort != null ? $" on {dev.AttachedPort}" : "")}",
                    0x2001 => $"MTK DA Mode{(dev.AttachedPort != null ? $" on {dev.AttachedPort}" : "")}",
                    0x2046 => $"MTK USB VCOM Mode{(dev.AttachedPort != null ? $" on {dev.AttachedPort}" : "")}",
                    _ => $"MTK Device Mode{(dev.AttachedPort != null ? $" on {dev.AttachedPort}" : "")}"
                };
            }
            else if (dev.IsPhoneOrModem)
            {
                dev.DeviceModeHint = dev.IsModemInterface
                    ? $"Normal Mode (Modem{(dev.AttachedPort != null ? $" on {dev.AttachedPort}" : "")})"
                    : $"Normal Mode (Phone / PC UI{(dev.AttachedPort != null ? $" on {dev.AttachedPort}" : "")})";
            }
            else
            {
                dev.DeviceModeHint = "Standard USB Device";
            }
        }
    }

    private static string GetKnownDeviceName(ushort vid, ushort pid)
    {
        return (vid, pid) switch
        {
            (0x12D1, _) => "HUAWEI / HONOR USB Device (Normal Mode / Modem)",
            (0x04E8, 0x6860) => "SAMSUNG Mobile USB Device (Galaxy Series)",
            (0x04E8, 0x685D) => "SAMSUNG Mobile USB CDC Device",
            (0x05AC, 0x12A8) => "Apple iPhone / iPad (Normal Mode)",
            (0x05AC, 0x1227) => "Apple Mobile Device (DFU Mode)",
            (0x05AC, 0x1281) => "Apple Recovery (iBoot Mode)",
            (0x0E8D, 0x0003) => "MediaTek USB Port (BROM Mode - BootROM)",
            (0x0E8D, 0x2000) => "MediaTek PreLoader USB VCOM Port",
            (0x0E8D, 0x2001) => "MediaTek DA USB VCOM Port",
            (0x0E8D, 0x2046) => "MediaTek USB Port (BROM / Preloader)",
            (0x0E8D, _) => "MediaTek USB Device",
            (0x05C6, 0x9008) => "Qualcomm HS-USB QDLoader 9008 (EDL Mode)",
            (0x05C6, 0x9091) => "Qualcomm HS-USB Diagnostics 9091",
            (0x18D1, 0x4EE7) => "Google Android ADB Device",
            (0x2E8A, _) => "Raspberry Pi USB Device",
            (0x1199, 0xA001) => "Sierra Wireless EM7345 4G LTE Modem",
            (0x8087, 0x8001) => "Intel Integrated USB Hub",
            (0x8087, 0x0A2A) => "Intel Wireless Bluetooth Adapter",
            (0x1A40, 0x0101) => "Terminus Technology USB 2.0 Hub",
            (0x04D9, 0x1702) => "Holtek USB Input Device (Keyboard/Mouse)",
            (0x045E, 0x0084) => "Microsoft USB Input Device",
            _ => $"USB Device [VID={vid:X4}, PID={pid:X4}]"
        };
    }

    public List<UsbDeviceInfo> GetConfiguredAndroidDevices()
    {
        var list = new List<UsbDeviceInfo>();
        try
        {
            using var classKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Class\{3F966BD9-FA04-4EC5-991C-D326973B5128}");
            if (classKey != null)
            {
                foreach (var sub in classKey.GetSubKeyNames())
                {
                    using var k = classKey.OpenSubKey(sub);
                    if (k == null) continue;

                    var desc = k.GetValue("DriverDesc")?.ToString() ?? "";
                    var matchId = k.GetValue("MatchingDeviceId")?.ToString() ?? "";
                    var provider = k.GetValue("ProviderName")?.ToString() ?? "";
                    var ver = k.GetValue("DriverVersion")?.ToString() ?? "";

                    if (!string.IsNullOrWhiteSpace(desc))
                    {
                        list.Add(new UsbDeviceInfo
                        {
                            DeviceName = $"{desc} ({provider})",
                            InstanceId = matchId,
                            Driver = $"Version {ver}",
                            Class = "AndroidUsbDeviceClass",
                            IsConnected = false,
                            IsAndroidAdb = true
                        });
                    }
                }
            }
        }
        catch { }

        return list;
    }

    private class PnpDevEntry
    {
        public string InstanceId { get; set; } = "";
        public string KeyName { get; set; } = "";
        public string FriendlyName { get; set; } = "";
        public string Service { get; set; } = "";
        public string Class { get; set; } = "";
    }
}
