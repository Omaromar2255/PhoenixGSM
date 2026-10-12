// ╔══════════════════════════════════════════════════════════════╗
// ║  PhoenixGSM — USB Monitor                                   ║
// ║  Captures, logs, and decodes USB traffic (ADB & Non-ADB)    ║
// ╚══════════════════════════════════════════════════════════════╝

using System.Text;
using System.Text.Json;
using PhoenixGSM.UsbMonitor;
using PhoenixGSM.UsbMonitor.Models;
using PhoenixGSM.UsbMonitor.Protocol;
using PhoenixGSM.UsbMonitorDiscovery;

Console.OutputEncoding = Encoding.UTF8;

var logger = new UsbLogger();
var scanner = new UsbScanner();

if (args.Length == 0)
{
    ShowHelp();
    return;
}

switch (args[0].ToLower())
{
    case "--list" or "-l":
        RunList(scanner, args);
        break;

    case "--watch" or "-w":
        await RunWatchAsync(scanner);
        break;

    case "--test" or "-t":
        AdbProtocolTests.RunAllTests();
        break;

    case "--capture" or "-c":
        await RunCaptureAsync(logger, scanner, args);
        break;

    case "--status":
        DriverManager.ShowStatus();
        break;

    case "--install-driver":
        RunInstallDriver(args);
        break;

    case "--uninstall-driver":
        RunUninstallDriver();
        break;

    case "--attach-device" or "-ad":
        if (args.Length < 2)
        {
            Console.WriteLine("  [-] Error: Please specify the Device Instance ID (e.g., USB\\VID_05C6&PID_9008\\5&18D4...)");
            return;
        }
        DriverManager.AttachDeviceLowerFilter(args[1]);
        break;

    case "--detach-device" or "-dd":
        if (args.Length < 2)
        {
            Console.WriteLine("  [-] Error: Please specify the Device Instance ID to detach.");
            return;
        }
        DriverManager.DetachDeviceLowerFilter(args[1]);
        break;

    case "--attach-class" or "-ac":
        string targetClass = args.Length > 1 ? args[1] : "android";
        DriverManager.ConfigureLowerFilter(targetClass);
        break;

    case "--detach-class" or "-dc":
        string detachClass = args.Length > 1 ? args[1] : "android";
        DriverManager.RemoveLowerFilter(detachClass);
        break;

    case "--rollback" or "--remove-all-filters":
        DriverManager.RemoveAllFilters();
        break;

    case "--stats" or "-s":
        ShowStats(logger);
        break;

    case "--export" or "-e":
        ExportLogs(logger, args);
        break;

    case "--simulate":
        await RunSimulationAsync(logger);
        break;

    default:
        ShowHelp();
        break;
}

static void RunList(UsbScanner scanner, string[] args)
{
    bool adbOnly = args.Any(a => a is "--adb" or "-a");
    bool json = args.Any(a => a is "--json" or "-j");

    var devices = scanner.ScanAllDevices();
    if (adbOnly) devices = devices.Where(d => d.IsAndroidAdb).ToList();

    if (json)
    {
        Console.WriteLine(JsonSerializer.Serialize(devices, new JsonSerializerOptions { WriteIndented = true }));
        return;
    }

    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine("+========================================================================+");
    Console.WriteLine("|               PhoenixGSM — Connected USB Devices & Endpoints          |");
    Console.WriteLine("+========================================================================+");
    Console.ResetColor();

    if (devices.Count == 0)
    {
        Console.WriteLine("  No USB devices found matching criteria.");
        return;
    }

    foreach (var dev in devices)
    {
        Console.ForegroundColor = dev.IsAndroidAdb ? ConsoleColor.Cyan : ConsoleColor.White;
        Console.WriteLine($"\n[Device] {dev.DeviceName}");
        Console.ResetColor();
        Console.WriteLine($"  ID         : VID={dev.VidHex} PID={dev.PidHex} (Port {dev.PortNumber}, Speed: {dev.Speed})");
        Console.WriteLine($"  Instance   : {dev.InstanceId}");
        Console.WriteLine($"  Driver/Svc : {dev.Driver} | Class: {dev.Class}");
        Console.WriteLine($"  Mode       : {(dev.IsAndroidAdb ? "Android ADB Interface Active" : "Non-ADB / WinUSB / Serial Mode")}");

        if (dev.Interfaces.Count > 0)
        {
            Console.WriteLine("  Interfaces & Endpoints:");
            foreach (var iface in dev.Interfaces)
            {
                var adbTag = iface.IsAdbInterface ? " [ADB]" : "";
                Console.WriteLine($"    Interface #{iface.InterfaceNumber}: {iface.ClassDescription}{adbTag}");
                foreach (var ep in iface.Endpoints)
                {
                    Console.WriteLine($"      -> EP {ep.EndpointHex,-4} | {ep.Direction,-3} | {ep.TransferType,-11} | MaxPacket: {ep.MaxPacketSize} B");
                }
            }
        }
    }
    Console.WriteLine();
}

static async Task RunWatchAsync(UsbScanner scanner)
{
    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine("+========================================================================+");
    Console.WriteLine("|            PhoenixGSM — USB Dynamic Topology & Device Watcher          |");
    Console.WriteLine("+========================================================================+");
    Console.ResetColor();
    Console.WriteLine("  Polling USB topology every 1 second... (Press Ctrl+C to exit)\n");

    var lastState = "";
    while (true)
    {
        var devices = scanner.ScanAllDevices();
        var current = string.Join(";", devices.Select(d => $"{d.VidHex}:{d.PidHex}:{d.PortNumber}"));

        if (current != lastState)
        {
            lastState = current;
            Console.WriteLine($"\n[{DateTime.Now:HH:mm:ss}] USB Topology changed: {devices.Count} device(s) online");
            foreach (var d in devices)
            {
                var adbTag = d.IsAndroidAdb ? " [ADB]" : " [Non-ADB/WinUSB]";
                Console.WriteLine($"  -> VID={d.VidHex} PID={d.PidHex} {d.DeviceName}{adbTag} (Instance: {d.InstanceId})");
            }
        }

        await Task.Delay(1000);
    }
}

static async Task RunCaptureAsync(UsbLogger logger, UsbScanner scanner, string[] args)
{
    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine("+========================================================================+");
    Console.WriteLine("|           PhoenixGSM — Universal USB Live Traffic Monitor              |");
    Console.WriteLine("+========================================================================+");
    Console.ResetColor();

    Console.WriteLine($"  Log output: {logger.CurrentLogFile}");

    using var driverClient = new UsbDriverClient();
    bool isDriverLive = driverClient.IsDriverAvailable();

    bool allDevices = args.Any(a => a is "--all" or "-A");
    var devices = scanner.ScanAllDevices();
    if (!allDevices && devices.Any(d => d.IsAndroidAdb))
    {
        devices = devices.Where(d => d.IsAndroidAdb).ToList();
    }

    if (devices.Count == 0)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("  [!] Notice: No USB devices detected for monitoring.");
        Console.WriteLine("  [*] Connect a phone/device or use '--all' to monitor all connected devices.");
        Console.ResetColor();
    }
    else
    {
        Console.ForegroundColor = ConsoleColor.Green;
        foreach (var d in devices)
        {
            var tag = d.IsAndroidAdb ? "[ADB]" : "[WinUSB/Custom]";
            Console.WriteLine($"  [+] Detected USB Device: {d.DeviceName} {tag} (VID={d.VidHex}, PID={d.PidHex})");
            foreach (var iface in d.Interfaces)
            {
                foreach (var ep in iface.Endpoints)
                {
                    Console.WriteLine($"      Endpoint: {ep.EndpointHex} {ep.Direction,-3} | Type: {ep.TransferType,-4} | MaxSize: {ep.MaxPacketSize} B");
                }
            }
        }
        Console.ResetColor();
    }

    Console.WriteLine();

    if (!isDriverLive)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("  [!] Notice: Kernel Filter Driver endpoint (\\\\.\\PhoenixUsbMonitor) is not active.");
        Console.WriteLine("      The user-mode sniffer requires the PhoenixUsbMonitor kernel driver to intercept USB packets.");
        Console.ResetColor();

        DriverManager.ShowStatus();

        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("  [*] Tip: To test end-to-end decoding & logging right now without driver, run:");
        Console.WriteLine("      UsbMonitor --simulate\n");
        Console.ResetColor();
        return;
    }

    if (!driverClient.Connect())
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("  [-] Failed to open handle to \\\\.\\PhoenixUsbMonitor.");
        Console.ResetColor();
        return;
    }

    var stats = driverClient.GetStats();
    Console.ForegroundColor = ConsoleColor.Green;
    Console.WriteLine($"  [+] Connected to \\\\.\\PhoenixUsbMonitor kernel device.");
    if (stats.HasValue)
    {
        Console.WriteLine($"      Driver Version : 0x{stats.Value.DriverVersion:X8}");
        Console.WriteLine($"      Queue Capacity : {stats.Value.MaxQueueCapacity} packets");
        Console.WriteLine($"      Total Captured : {stats.Value.TotalPacketsCaptured} packets");
    }
    Console.ResetColor();

    Console.WriteLine("\n  Listening for USB traffic across Bulk and Control endpoints... (Press Ctrl+C to stop)\n");

    var parser = new AdbProtocolParser();
    var cts = new CancellationTokenSource();
    Console.CancelKeyPress += (_, e) =>
    {
        e.Cancel = true;
        cts.Cancel();
    };

    ulong localCaptured = 0;
    try
    {
        while (!cts.Token.IsCancellationRequested)
        {
            var kPacket = driverClient.DequeuePacket();
            if (kPacket.HasValue)
            {
                localCaptured++;
                var pkt = kPacket.Value;
                string dir = pkt.Direction == 0 ? "OUT" : "IN";
                byte[] chunk = new byte[pkt.CapturedLength];
                if (pkt.CapturedLength > 0 && pkt.Data != null)
                {
                    Array.Copy(pkt.Data, chunk, Math.Min((int)pkt.CapturedLength, pkt.Data.Length));
                }

                string epHex = $"0x{pkt.EndpointAddress:X2}";
                var matchedDev = devices.FirstOrDefault(d => d.Interfaces.Any(i => i.Endpoints.Any(e => e.EndpointAddress == pkt.EndpointAddress)))
                                ?? devices.FirstOrDefault();
                string devName = matchedDev?.DeviceName ?? "USB Device";
                string vid = matchedDev?.VidHex ?? "";
                string pid = matchedDev?.PidHex ?? "";

                var frames = parser.ProcessChunk(chunk, dir, devName, vid, pid, 1, epHex);
                foreach (var frame in frames)
                {
                    logger.LogFrame(frame);
                    Console.ForegroundColor = frame.Direction == "OUT" ? ConsoleColor.Cyan : ConsoleColor.Green;
                    Console.WriteLine($"[{frame.Timestamp:HH:mm:ss.fff}] [{frame.Direction,3}] EP={frame.Endpoint} | [{frame.Protocol}] {frame.Command,-4} | {frame.GetDetailSummary()}");
                    Console.ResetColor();
                }
            }
            else
            {
                await Task.Delay(10, cts.Token);
            }
        }
    }
    catch (OperationCanceledException) { }

    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine($"\n  Capture stopped. Captured {localCaptured} packets during session.");
    Console.WriteLine($"  Log saved to: {logger.CurrentLogFile}");
    Console.ResetColor();
}

static async Task RunSimulationAsync(UsbLogger logger)
{
    await Task.CompletedTask;
    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine("+========================================================================+");
    Console.WriteLine("|       PhoenixGSM — Multi-Protocol Traffic Simulation (ADB & WinUSB)    |");
    Console.WriteLine("+========================================================================+");
    Console.ResetColor();

    Console.WriteLine($"  Writing decoded frames to: {logger.CurrentLogFile}\n");

    var parser = new AdbProtocolParser();

    // 1. Simulate ADB session
    Console.WriteLine("  [1/4] Simulating ADB Handshake & Commands...");
    var cnxnPacket = BuildAdbPacket(AdbProtocolParser.A_CNXN, 0x01000001, 1048576, Encoding.UTF8.GetBytes("device::ro.product.model=Galaxy;ro.build.version.release=14;"));
    var cnxnFrames = parser.ProcessChunk(cnxnPacket, "OUT", "Samsung Galaxy S24", "04E8", "6860", 1, "0x02");
    foreach (var f in cnxnFrames)
    {
        logger.LogFrame(f);
        Console.WriteLine($"    [{f.Direction,3}] [{f.Protocol}] {f.Command} -> {f.GetDetailSummary()}");
    }

    // 2. Simulate Fastboot command & response (WinUSB mode)
    Console.WriteLine("\n  [2/4] Simulating Fastboot Protocol over WinUSB...");
    var fbCmd = Encoding.ASCII.GetBytes("getvar:version");
    var fbResp = Encoding.ASCII.GetBytes("OKAY0.5");
    var fbOutFrames = parser.ProcessChunk(fbCmd, "OUT", "Google Pixel 8 (Fastboot)", "18D1", "4EE0", 0, "0x01");
    var fbInFrames = parser.ProcessChunk(fbResp, "IN", "Google Pixel 8 (Fastboot)", "18D1", "4EE0", 0, "0x81");
    foreach (var f in fbOutFrames.Concat(fbInFrames))
    {
        logger.LogFrame(f);
        Console.WriteLine($"    [{f.Direction,3}] [{f.Protocol}] {f.Command} -> {f.GetDetailSummary()}");
    }

    // 3. Simulate Qualcomm Firehose XML command (EDL / WinUSB mode)
    Console.WriteLine("\n  [3/4] Simulating Qualcomm Firehose Protocol (EDL)...");
    var qcomXml = Encoding.UTF8.GetBytes("<?xml version=\"1.0\" ?><data><configure MemoryName=\"ufs\" Verbose=\"0\" MaxPayloadSizeToTargetInBytes=\"1048576\"/></data>");
    var qcomFrames = parser.ProcessChunk(qcomXml, "OUT", "Qualcomm HS-USB QDLoader 9008", "05C6", "9008", 0, "0x02");
    foreach (var f in qcomFrames)
    {
        logger.LogFrame(f);
        Console.WriteLine($"    [{f.Direction,3}] [{f.Protocol}] {f.Command} -> {f.GetDetailSummary()}");
    }

    // 4. Simulate Generic WinUSB Raw transfer
    Console.WriteLine("\n  [4/4] Simulating Generic WinUSB Raw Tool Exchange...");
    var rawBytes = new byte[] { 0x55, 0xAA, 0x10, 0x20, 0x30, 0x40, 0x01, 0xFF, 0xFE, 0xFD };
    var rawFrames = parser.ProcessChunk(rawBytes, "OUT", "Generic WinUSB Mobile Device", "1234", "5678", 0, "0x03");
    foreach (var f in rawFrames)
    {
        logger.LogFrame(f);
        Console.WriteLine($"    [{f.Direction,3}] [{f.Protocol}] {f.Command} -> {f.GetDetailSummary()}");
    }

    Console.ForegroundColor = ConsoleColor.Green;
    Console.WriteLine("\n  [+] Multi-protocol simulation completed successfully! All frames decoded and logged.");
    Console.ResetColor();
}

static byte[] BuildAdbPacket(uint command, uint arg0, uint arg1, byte[] payload)
{
    uint magic = command ^ 0xFFFFFFFF;
    uint dataLen = (uint)(payload?.Length ?? 0);
    uint check = 0;
    if (payload != null)
    {
        foreach (byte b in payload) check += b;
    }

    byte[] packet = new byte[24 + dataLen];
    Array.Copy(BitConverter.GetBytes(command), 0, packet, 0, 4);
    Array.Copy(BitConverter.GetBytes(arg0), 0, packet, 4, 4);
    Array.Copy(BitConverter.GetBytes(arg1), 0, packet, 8, 4);
    Array.Copy(BitConverter.GetBytes(dataLen), 0, packet, 12, 4);
    Array.Copy(BitConverter.GetBytes(check), 0, packet, 16, 4);
    Array.Copy(BitConverter.GetBytes(magic), 0, packet, 20, 4);

    if (payload != null && payload.Length > 0)
    {
        Array.Copy(payload, 0, packet, 24, payload.Length);
    }

    return packet;
}

static void ShowStats(UsbLogger logger)
{
    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine("+========================================================================+");
    Console.WriteLine("|             PhoenixGSM — USB Traffic Capture Statistics                |");
    Console.WriteLine("+========================================================================+");
    Console.ResetColor();

    var allLogs = logger.ReadAllLogs().ToList();
    if (allLogs.Count == 0)
    {
        Console.WriteLine("  No logs found in: " + logger.LogDirectory);
        return;
    }

    Console.WriteLine($"  Total Frames Logged : {allLogs.Count:N0}");
    Console.WriteLine($"  Logs Directory      : {logger.LogDirectory}\n");

    Console.ForegroundColor = ConsoleColor.White;
    Console.WriteLine("  By Protocol:");
    Console.ResetColor();
    foreach (var g in allLogs.GroupBy(f => f.Protocol).OrderByDescending(g => g.Count()))
    {
        Console.WriteLine($"    {g.Key,-20} : {g.Count(),6:N0} frames");
    }

    Console.ForegroundColor = ConsoleColor.White;
    Console.WriteLine("\n  By Direction:");
    Console.ResetColor();
    foreach (var g in allLogs.GroupBy(f => f.Direction))
    {
        Console.WriteLine($"    {g.Key,-20} : {g.Count(),6:N0} frames");
    }
}

static void ExportLogs(UsbLogger logger, string[] args)
{
    string format = args.Length > 1 ? args[1].ToLower() : "json";
    var allLogs = logger.ReadAllLogs().ToList();
    string exportPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "PhoenixGSM", "Reports", $"usb_export_{DateTime.UtcNow:yyyyMMdd_HHmmss}.{format}");

    Directory.CreateDirectory(Path.GetDirectoryName(exportPath)!);

    if (format == "json")
    {
        File.WriteAllText(exportPath, JsonSerializer.Serialize(allLogs, new JsonSerializerOptions { WriteIndented = true }));
    }
    else if (format == "csv")
    {
        var sb = new StringBuilder();
        sb.AppendLine("Timestamp,Direction,Protocol,Command,DataLength,Endpoint,Device,Summary");
        foreach (var f in allLogs)
        {
            sb.AppendLine($"\"{f.Timestamp:O}\",\"{f.Direction}\",\"{f.Protocol}\",\"{f.Command}\",{f.DataLength},\"{f.Endpoint}\",\"{f.Device}\",\"{f.GetDetailSummary().Replace("\"", "\"\"")}\"");
        }
        File.WriteAllText(exportPath, sb.ToString());
    }

    Console.ForegroundColor = ConsoleColor.Green;
    Console.WriteLine($"  [+] Exported {allLogs.Count} frames to: {exportPath}");
    Console.ResetColor();
}

static void RunInstallDriver(string[] args)
{
    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine("+========================================================================+");
    Console.WriteLine("|            PhoenixGSM — Install USB Filter Driver Service              |");
    Console.WriteLine("+========================================================================+");
    Console.ResetColor();

    bool ok = DriverManager.InstallService();
    if (!ok) return;

    bool attachFilter = !args.Any(a => a is "--no-filter");
    if (attachFilter)
    {
        string targetClass = args.FirstOrDefault(a => a.StartsWith("--class="))?.Substring(8) ?? "android";
        DriverManager.ConfigureLowerFilter(targetClass);
    }

    Console.WriteLine("\n  Attempting to start driver service...");
    DriverManager.StartService();

    Console.WriteLine();
    DriverManager.ShowStatus();
}

static void RunUninstallDriver()
{
    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine("+========================================================================+");
    Console.WriteLine("|          PhoenixGSM — Uninstall USB Filter Driver Service              |");
    Console.WriteLine("+========================================================================+");
    Console.ResetColor();

    DriverManager.RemoveLowerFilter("android");
    DriverManager.UninstallService();

    Console.WriteLine();
    DriverManager.ShowStatus();
}

static void ShowHelp()
{
    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine(@"
+========================================================================+
|               PhoenixGSM — Universal USB Traffic Monitor               |
|   Decodes USB Traffic: ADB, WinUSB, Fastboot, Qualcomm, Odin, MTK      |
+========================================================================+");
    Console.ResetColor();
    Console.WriteLine(@"
  Device & Topology:
    UsbMonitor --list              List all USB devices, interfaces & endpoints
    UsbMonitor --list --adb        List only Android ADB devices
    UsbMonitor --watch             Watch for live USB connect/disconnect events

  Traffic Capture:
    UsbMonitor --capture           Capture live traffic (ADB by default)
    UsbMonitor --capture --all     Capture on ALL USB devices (WinUSB, EDL, Odin, etc.)
    UsbMonitor --simulate          Simulate multi-protocol USB session (ADB & WinUSB)
    UsbMonitor --test              Run protocol parser test suite

  Kernel Filter Driver & Attachment:
    UsbMonitor --status            Display driver, testsigning, and active filters
    UsbMonitor --install-driver    Register service and configure LowerFilter
    UsbMonitor --uninstall-driver  Unregister driver service
    UsbMonitor --attach-device <ID> Attach LowerFilter to specific USB device (e.g. VID/PID)
    UsbMonitor --detach-device <ID> Detach LowerFilter from specific USB device
    UsbMonitor --attach-class <cls> Attach to class (android, winusb, usb, ports, or GUID)
    UsbMonitor --detach-class <cls> Detach from class
    UsbMonitor --rollback          Remove ALL filter attachments across Windows safely

  Logs & Reporting:
    UsbMonitor --stats             Display statistics of captured traffic
    UsbMonitor --export [json|csv] Export captured packets to report
");
}
