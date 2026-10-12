// ╔══════════════════════════════════════════════════════════════╗
// ║  PhoenixGSM — Process Activity Monitor                      ║
// ║  Tracks what mobile tools do at the system level             ║
// ╚══════════════════════════════════════════════════════════════╝

using System.Text;
using PhoenixGSM.ProcessMonitor;

Console.OutputEncoding = Encoding.UTF8;

var logDir = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
    "PhoenixGSM", "Logs", "Process");

if (args.Length == 0 || args[0] is "--help" or "-h")
{
    ShowHelp();
    return;
}

string targetProcess;

switch (args[0].ToLower())
{
    case "--target" or "-t":
        if (args.Length < 2)
        {
            Console.WriteLine("Error: Specify process name: --target z3x_samsung_tool");
            return;
        }
        targetProcess = args[1].Replace(".exe", "");
        break;

    case "--list" or "-l":
        ListRunningTools();
        return;

    default:
        targetProcess = args[0].Replace(".exe", "");
        break;
}

using var spy = new ProcessSpy(targetProcess, logDir);
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    spy.Stop();
};

await spy.StartAsync();

/// <summary>
/// List known running servicing tools
/// </summary>
static void ListRunningTools()
{
    string[] knownTools =
    [
        "z3x", "octoplus", "octopus", "umt", "chimera",
        "unlockTool", "3utools", "itools", "samfw",
        "odin", "samsungTool", "dc-unlocker", "infinity",
        "bst", "mrt", "ufi", "medusa", "hydra",
        "eft", "nck", "furious", "volcano", "miracle"
    ];

    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine("+======================================+");
    Console.WriteLine("|       Active Servicing Tools         |");
    Console.WriteLine("+======================================+");
    Console.ResetColor();

    var found = false;
    foreach (var proc in System.Diagnostics.Process.GetProcesses())
    {
        try
        {
            var name = proc.ProcessName.ToLower();
            if (knownTools.Any(t => name.Contains(t.ToLower())))
            {
                found = true;
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write($"  [+] {proc.ProcessName}");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($" (PID: {proc.Id})");
                Console.ResetColor();
            }
        }
        catch { }
    }

    if (!found)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("  [!] No known servicing tools detected currently.");
        Console.ResetColor();
    }

    Console.ForegroundColor = ConsoleColor.DarkGray;
    Console.WriteLine("\n  Tip: Launch your tool, then run:");
    Console.WriteLine("       ProcessMonitor --target <tool_name>");
    Console.ResetColor();
}

static void ShowHelp()
{
    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine(@"
+==========================================================+
|         PhoenixGSM — Process Activity Monitor            |
|       Tracks what tools do at the system level           |
+==========================================================+");
    Console.ResetColor();
    Console.WriteLine(@"
  Usage:
    ProcessMonitor --target <name>      Monitor a specific process (e.g. z3x, 3utools)
    ProcessMonitor --list               List currently running servicing tools
    ProcessMonitor --help               Show help menu

  What it monitors:
    * Files        - Files created, read, or modified
    * Subprocesses - Child processes spawned (e.g. adb.exe, fastboot.exe)
    * DLLs         - Loaded modules and drivers
    * Network      - Remote connection endpoints
");
}
