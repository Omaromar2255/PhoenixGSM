// ╔══════════════════════════════════════════════════════════════╗
// ║  PhoenixGSM — Serial Port Sniffer                           ║
// ║  Captures AT commands and serial protocols from boxes        ║
// ╚══════════════════════════════════════════════════════════════╝

using System.Text;
using PhoenixGSM.SerialSniffer;

Console.OutputEncoding = Encoding.UTF8;

var logDir = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
    "PhoenixGSM", "Logs", "Serial");

var monitor = new ComPortMonitor(logDir);
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    monitor.Stop();
};

if (args.Length == 0)
{
    ShowHelp();
    return;
}

switch (args[0].ToLower())
{
    // List available ports
    case "--list" or "-l":
        ComPortMonitor.ListPorts();
        break;

    // Monitor specific port
    case "--port" or "-p":
        if (args.Length < 2)
        {
            Console.WriteLine("Error: Specify port: --port COM3 [--baud 115200]");
            break;
        }
        var port = args[1];
        var baud = 115200;
        for (int i = 2; i < args.Length - 1; i++)
        {
            if (args[i] is "--baud" or "-b")
                int.TryParse(args[i + 1], out baud);
        }
        await monitor.StartMonitoringAsync(port, baud);
        break;

    // Watch for new ports
    case "--watch" or "-w":
        await monitor.WatchForNewPortsAsync();
        break;

    // Scan all baud rates
    case "--scan" or "-s":
        if (args.Length < 2)
        {
            Console.WriteLine("Error: Specify port: --scan COM3");
            break;
        }
        await ScanBaudRatesAsync(args[1]);
        break;

    default:
        ShowHelp();
        break;
}

/// <summary>Scan baud rates</summary>
static async Task ScanBaudRatesAsync(string portName)
{
    int[] baudRates = [9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600];

    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine($"Scanning baud rates on {portName}...\n");
    Console.ResetColor();

    foreach (var baud in baudRates)
    {
        Console.Write($"  [*] {baud,8} baud... ");
        try
        {
            using var sp = new System.IO.Ports.SerialPort(portName, baud);
            sp.ReadTimeout = 2000;
            sp.Open();

            sp.Write("AT\r\n");
            await Task.Delay(500);

            if (sp.BytesToRead > 0)
            {
                var response = sp.ReadExisting();
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"[+] Response: {response.Trim().Replace("\r\n", " | ")}");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine("[-] No response");
                Console.ResetColor();
            }
            sp.Close();
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[!] {ex.Message}");
            Console.ResetColor();
        }
    }
}

static void ShowHelp()
{
    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine(@"
+==========================================================+
|         PhoenixGSM — Serial Port Sniffer                 |
|   Captures AT commands and serial protocols from boxes   |
+==========================================================+");
    Console.ResetColor();
    Console.WriteLine(@"
  Usage:
    SerialSniffer --list                    List available COM ports
    SerialSniffer --port COM3               Monitor port at default 115200 baud
    SerialSniffer --port COM3 --baud 9600   Monitor port with specific baud rate
    SerialSniffer --watch                   Watch for newly attached ports
    SerialSniffer --scan COM3               Scan port for responsive baud rate

  Supported Protocols:
    * AT Commands    - Modem commands (Network lock, IMEI, etc.)
    * Odin Protocol  - Samsung Download Mode
    * Qualcomm DIAG  - Qualcomm Diagnostic Mode
    * MTK BROM       - MediaTek Boot ROM
");
}
