// ╔══════════════════════════════════════════════════════════════╗
// ║  PhoenixGSM — ADB Monitor                                  ║
// ║  Captures and logs every ADB command from any tool          ║
// ╚══════════════════════════════════════════════════════════════╝

using System.Text;
using PhoenixGSM.AdbMonitor;

Console.OutputEncoding = Encoding.UTF8;

var logDir = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
    "PhoenixGSM", "Logs", "ADB");

if (args.Length > 0)
{
    switch (args[0].ToLower())
    {
        case "--install":
            var installDir = args.Length > 1 ? args[1] : FindAdbDirectory();
            if (installDir != null)
                AdbInterceptor.Install(installDir);
            else
                Console.WriteLine("Error: Specify ADB directory: --install <path>");
            return;

        case "--uninstall":
            var uninstallDir = args.Length > 1 ? args[1] : FindAdbDirectory();
            if (uninstallDir != null)
                AdbInterceptor.Uninstall(uninstallDir);
            else
                Console.WriteLine("Error: Specify ADB directory: --uninstall <path>");
            return;

        case "--logs":
            ShowLogs(logDir);
            return;

        case "--help":
            ShowHelp();
            return;

        case "--stats":
            await ShowStatsAsync(logDir);
            return;
    }
}

var exeDir = Path.GetDirectoryName(System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName) ?? ".";
var realAdbPath = Path.Combine(exeDir, "adb_real.exe");

if (!File.Exists(realAdbPath))
{
    realAdbPath = FindRealAdb() ?? "adb_real.exe";
}

if (!File.Exists(realAdbPath))
{
    Console.ForegroundColor = ConsoleColor.Red;
    Console.Error.WriteLine("Error: adb_real.exe not found.");
    Console.Error.WriteLine("Run: AdbMonitor --install <path_to_adb_folder>");
    Console.ResetColor();
    Environment.Exit(1);
}

var interceptor = new AdbInterceptor(realAdbPath, logDir);
var exitCode = await interceptor.ExecuteAndLogAsync(args);
Environment.Exit(exitCode);

static string? FindAdbDirectory()
{
    string[] commonPaths =
    [
        @"C:\adb",
        @"C:\platform-tools",
        @"C:\android\platform-tools",
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Android", "Sdk", "platform-tools"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "Minimal ADB and Fastboot"),
    ];

    foreach (var path in commonPaths)
    {
        if (File.Exists(Path.Combine(path, "adb.exe")))
            return path;
    }

    var pathEnv = Environment.GetEnvironmentVariable("PATH") ?? "";
    foreach (var dir in pathEnv.Split(';'))
    {
        if (File.Exists(Path.Combine(dir, "adb.exe")))
            return dir;
    }

    return null;
}

static string? FindRealAdb()
{
    var dir = FindAdbDirectory();
    if (dir == null) return null;
    var realPath = Path.Combine(dir, "adb_real.exe");
    return File.Exists(realPath) ? realPath : null;
}

static void ShowLogs(string logDir)
{
    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine("+======================================+");
    Console.WriteLine("|          ADB Monitor Logs            |");
    Console.WriteLine("+======================================+");
    Console.ResetColor();

    if (!Directory.Exists(logDir))
    {
        Console.WriteLine("  No logs recorded yet.");
        return;
    }

    var files = Directory.GetFiles(logDir, "adb_log_*.jsonl")
        .OrderByDescending(f => f);

    foreach (var file in files)
    {
        var info = new FileInfo(file);
        var lineCount = File.ReadLines(file).Count();
        Console.WriteLine($"  * {info.Name} - {lineCount} commands - {info.Length / 1024.0:F1} KB");
    }
}

static async Task ShowStatsAsync(string logDir)
{
    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine("+======================================+");
    Console.WriteLine("|       ADB Monitoring Statistics      |");
    Console.WriteLine("+======================================+");
    Console.ResetColor();

    if (!Directory.Exists(logDir))
    {
        Console.WriteLine("  No logs recorded yet.");
        return;
    }

    var categories = new Dictionary<string, int>();
    var processes = new Dictionary<string, int>();
    int totalCommands = 0;
    int successCount = 0;

    foreach (var file in Directory.GetFiles(logDir, "adb_log_*.jsonl"))
    {
        await foreach (var line in File.ReadLinesAsync(file))
        {
            try
            {
                var log = System.Text.Json.JsonSerializer.Deserialize<PhoenixGSM.AdbMonitor.Models.AdbCommandLog>(line);
                if (log == null) continue;

                totalCommands++;
                if (log.Success) successCount++;

                categories[log.Category] = categories.GetValueOrDefault(log.Category) + 1;
                processes[log.CallingProcess] = processes.GetValueOrDefault(log.CallingProcess) + 1;
            }
            catch { }
        }
    }

    Console.WriteLine($"\n  Total Commands : {totalCommands}");
    Console.WriteLine($"  Succeeded      : {successCount} | Failed: {totalCommands - successCount}");

    Console.WriteLine("\n  By Category:");
    foreach (var (cat, count) in categories.OrderByDescending(x => x.Value))
        Console.WriteLine($"    {cat,-20} {count,5} cmds");

    Console.WriteLine("\n  By Caller Process:");
    foreach (var (proc, count) in processes.OrderByDescending(x => x.Value))
        Console.WriteLine($"    {proc,-25} {count,5} cmds");
}

static void ShowHelp()
{
    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine(@"
+==========================================================+
|               PhoenixGSM — ADB Monitor                   |
|   Transparent ADB proxy to capture servicing commands    |
+==========================================================+");
    Console.ResetColor();
    Console.WriteLine(@"
  Usage:
    AdbMonitor --install <path>      Install proxy into ADB folder
    AdbMonitor --uninstall <path>    Restore original adb.exe
    AdbMonitor --logs                Show recorded log files
    AdbMonitor --stats               Show command statistics
    AdbMonitor --help                Show help menu

  How it works:
    1. Renames real adb.exe to adb_real.exe
    2. Places AdbMonitor as adb.exe in that directory
    3. Any servicing tool executing adb transparently logs all commands
    4. Logs stored at: %LOCALAPPDATA%\PhoenixGSM\Logs\ADB\
");
}
