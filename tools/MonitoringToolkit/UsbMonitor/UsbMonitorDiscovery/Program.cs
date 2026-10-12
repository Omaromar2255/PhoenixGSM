// ╔══════════════════════════════════════════════════════════════╗
// ║  PhoenixGSM — USB Monitor Discovery                          ║
// ║  Discovers USB topology, interfaces, and endpoint descriptors║
// ╚══════════════════════════════════════════════════════════════╝

using System.Text;
using System.Text.Json;
using PhoenixGSM.UsbMonitorDiscovery;
using PhoenixGSM.UsbMonitorDiscovery.Models;

Console.OutputEncoding = Encoding.UTF8;

var scanner = new UsbScanner();

if (args.Length > 0 && (args[0] is "--help" or "-h" or "/?"))
{
    ShowHelp();
    return;
}

bool jsonOutput = args.Any(a => a is "--json" or "-j");
bool adbOnly = args.Any(a => a is "--adb" or "-a");
bool watchMode = args.Any(a => a is "--watch" or "-w");
bool debugMode = args.Any(a => a is "--debug" or "-d");

scanner.EnableDebug = debugMode;

if (!jsonOutput)
{
    PrintHeader();
}

if (watchMode)
{
    await RunWatchLoopAsync(scanner, adbOnly, jsonOutput);
    return;
}

RunDiscovery(scanner, adbOnly, jsonOutput);

static void RunDiscovery(UsbScanner scanner, bool adbOnly, bool jsonOutput)
{
    var devices = scanner.ScanAllDevices();

    if (adbOnly)
    {
        devices = devices.Where(d => d.IsAndroidAdb).ToList();
    }

    if (jsonOutput)
    {
        var options = new JsonSerializerOptions { WriteIndented = true };
        Console.WriteLine(JsonSerializer.Serialize(devices, options));
        return;
    }

    if (devices.Count == 0)
    {
        if (adbOnly)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  [!] No active Android ADB devices detected on USB ports right now.");
            Console.ResetColor();

            // Show configured Android devices from driver store
            var configured = scanner.GetConfiguredAndroidDevices();
            if (configured.Count > 0)
            {
                Console.WriteLine("\n  Configured Android USB drivers in system registry:");
                foreach (var cfg in configured)
                {
                    Console.WriteLine($"    * {cfg.DeviceName} -> {cfg.Driver} ({cfg.InstanceId})");
                }
            }
        }
        else
        {
            Console.WriteLine("  No USB devices detected.");
        }
        return;
    }

    Console.ForegroundColor = ConsoleColor.Green;
    Console.WriteLine($"  [+] Discovered {devices.Count} active USB device(s) via Live Descriptors:\n");
    Console.ResetColor();

    foreach (var dev in devices)
    {
        PrintDeviceBlock(dev);
    }
}

static void PrintDeviceBlock(UsbDeviceInfo dev)
{
    Console.ForegroundColor = dev.IsAndroidAdb ? ConsoleColor.Cyan : ConsoleColor.White;
    Console.WriteLine("┌────────────────────────────────────────────────────────────────────────┐");
    Console.WriteLine($"│ Device:        {dev.DeviceName,-55} │");
    Console.WriteLine($"│ VID:           {dev.VidHex,-55} │");
    Console.WriteLine($"│ PID:           {dev.PidHex,-55} │");

    // Display MI / Sub-devices if composite
    if (dev.SubDevices.Count > 0)
    {
        var miList = string.Join(", ", dev.SubDevices.Select(s => s.InterfaceNumber ?? "MI"));
        Console.WriteLine($"│ MI:            {miList,-55} │");
    }
    else
    {
        Console.WriteLine($"│ MI:            {"None (Single-function device)",-55} │");
    }

    Console.WriteLine($"│ Instance ID:   {dev.InstanceId,-55} │");
    Console.WriteLine($"│ Class:         {dev.Class,-55} │");
    Console.WriteLine($"│ Driver:        {dev.Driver,-55} │");
    Console.WriteLine($"│ Speed:         {dev.Speed,-55} │");
    Console.WriteLine($"│ Hub Port:      {dev.PortNumber,-55} │");

    if (dev.Interfaces.Count > 0)
    {
        Console.WriteLine("├────────────────────────────────────────────────────────────────────────┤");
        Console.WriteLine("│ Descriptors (Live USB Descriptors):                                    │");

        foreach (var iface in dev.Interfaces)
        {
            var ifHeader = $"Interface: {iface.InterfaceNumber} (Alt {iface.AlternateSetting}) - {iface.ClassDescription}";
            if (iface.IsAdbInterface)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"│   >>> {ifHeader,-63} │");
                Console.ResetColor();
            }
            else
            {
                Console.WriteLine($"│   * {ifHeader,-65} │");
            }

            if (iface.Endpoints.Count == 0)
            {
                Console.WriteLine("│       (No endpoints declared for this interface)                       │");
            }
            else
            {
                foreach (var ep in iface.Endpoints)
                {
                    var epLine = $"EP={ep.EndpointHex} {ep.Direction} | Transfer={ep.TransferType} | MaxPacket={ep.MaxPacketSize} B";
                    Console.WriteLine($"│       {epLine,-64} │");
                }
            }
        }
    }
    else
    {
        Console.WriteLine("│ Descriptors:   No configuration descriptors returned                   │");
    }

    Console.WriteLine("└────────────────────────────────────────────────────────────────────────┘\n");
    Console.ResetColor();
}

static async Task RunWatchLoopAsync(UsbScanner scanner, bool adbOnly, bool jsonOutput)
{
    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine("  [*] Watching for USB topology changes... (Press Ctrl+C to stop)\n");
    Console.ResetColor();

    string lastFingerprint = "";

    while (true)
    {
        var devices = scanner.ScanAllDevices();
        if (adbOnly) devices = devices.Where(d => d.IsAndroidAdb).ToList();

        var fingerprint = string.Join(";", devices.Select(d => $"{d.VidHex}:{d.PidHex}:{d.PortNumber}"));

        if (fingerprint != lastFingerprint)
        {
            lastFingerprint = fingerprint;
            Console.Clear();
            PrintHeader();
            Console.WriteLine($"  [Event @ {DateTime.Now:HH:mm:ss.fff}] USB Topology Updated:");
            RunDiscovery(scanner, adbOnly, jsonOutput);
        }

        await Task.Delay(1000);
    }
}

static void PrintHeader()
{
    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine(@"
+========================================================================+
|               PhoenixGSM — USB Topology & Descriptor Discovery         |
|         Extracts VID, PID, Interfaces, Endpoints from USB Descriptors  |
+========================================================================+");
    Console.ResetColor();
}

static void ShowHelp()
{
    PrintHeader();
    Console.WriteLine(@"
  Usage:
    UsbMonitorDiscovery.exe             Discover all connected USB devices
    UsbMonitorDiscovery.exe --adb       Filter only Android / ADB devices
    UsbMonitorDiscovery.exe --watch     Live monitoring of USB connect/disconnect
    UsbMonitorDiscovery.exe --json      Output structured JSON for automation
    UsbMonitorDiscovery.exe --help      Show this help menu

  Output fields per device:
    - Device Name & Friendly Name
    - VID (Vendor ID) & PID (Product ID)
    - MI (Composite Interface Identifiers)
    - Device Instance ID (PnP Path)
    - Device Class & Service Driver (WinUSB, ssudbus, etc.)
    - Interface Number & Protocol Description
    - Endpoint Address (e.g. 0x02 OUT, 0x81 IN)
    - Transfer Type (BULK, INTERRUPT, CONTROL, ISOCHRONOUS)
    - Max Packet Size (e.g. 512 bytes, 1024 bytes)
");
}
