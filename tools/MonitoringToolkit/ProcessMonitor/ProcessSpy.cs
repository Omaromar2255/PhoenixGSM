namespace PhoenixGSM.ProcessMonitor;

using System.Diagnostics;
using System.Text;
using System.Text.Json;
using PhoenixGSM.ProcessMonitor.Models;

/// <summary>
/// Process activity spy — tracks what tools do at the system level
/// </summary>
public class ProcessSpy : IDisposable
{
    private readonly string _targetProcessName;
    private readonly string _logDirectory;
    private readonly JsonSerializerOptions _jsonOptions;
    private readonly List<ProcessActivity> _activities = [];
    private CancellationTokenSource? _cts;
    private readonly HashSet<string> _loadedDlls = [];
    private readonly HashSet<string> _seenConnections = [];

    // Statistics
    private readonly Dictionary<string, int> _activityCounts = [];
    private int _totalActivities;

    private static readonly string[] IgnorePaths =
    [
        @"\Windows\System32\",
        @"\Windows\SysWOW64\",
        @"\Windows\Fonts\",
        @"\AppData\Local\Temp\",
        ".log", ".tmp"
    ];

    private static readonly string[] InterestingPaths =
    [
        "adb", "fastboot", "samsung", "odin", "frp",
        "unlock", "imei", "efs", "pit", "firmware",
        "driver", "usb", "serial", "com", "cert",
        "nv_data", "modem", "radio", ".bin", ".tar",
        ".md5", ".pit", ".cer", ".der", "flash"
    ];

    public ProcessSpy(string targetProcessName, string logDirectory)
    {
        _targetProcessName = targetProcessName.Replace(".exe", "");
        _logDirectory = logDirectory;
        _jsonOptions = new JsonSerializerOptions
        {
            WriteIndented = false,
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };
        Directory.CreateDirectory(_logDirectory);
    }

    /// <summary>
    /// Start comprehensive monitoring
    /// </summary>
    public async Task StartAsync()
    {
        _cts = new CancellationTokenSource();

        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($@"
+==========================================================+
|         Process Activity Spy — PhoenixGSM                |
+==========================================================+

  Target  : {_targetProcessName}
  Logs Dir: {_logDirectory}
  Started : {DateTime.Now:yyyy-MM-dd HH:mm:ss}
  
  Press Ctrl+C to stop and show summary report.
");
        Console.ResetColor();

        var process = await WaitForProcessAsync();
        if (process == null) return;

        LogActivity(new ProcessActivity
        {
            ProcessName = _targetProcessName,
            ProcessId = process.Id,
            ActivityType = ActivityTypes.ProcessStart,
            Details = $"Process started: {process.MainModule?.FileName ?? "unknown"}",
            Path = process.MainModule?.FileName ?? ""
        });

        var tasks = new List<Task>
        {
            MonitorChildProcessesAsync(process),
            MonitorFileSystemAsync(process),
            MonitorNetworkConnectionsAsync(process),
            MonitorLoadedModulesAsync(process),
            MonitorProcessExitAsync(process)
        };

        try
        {
            await Task.WhenAll(tasks);
        }
        catch (OperationCanceledException) { }

        PrintFinalReport();
    }

    private async Task<Process?> WaitForProcessAsync()
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write($"  [*] Waiting for {_targetProcessName} to start");

        while (!_cts!.Token.IsCancellationRequested)
        {
            var processes = Process.GetProcessesByName(_targetProcessName);
            if (processes.Length > 0)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"\n  [+] Target process found! PID: {processes[0].Id}");
                Console.ResetColor();
                return processes[0];
            }

            Console.Write(".");
            try { await Task.Delay(1000, _cts.Token); }
            catch (TaskCanceledException) { break; }
        }

        return null;
    }

    private async Task MonitorChildProcessesAsync(Process parent)
    {
        var knownChildren = new HashSet<int>();

        while (!_cts!.Token.IsCancellationRequested && !parent.HasExited)
        {
            try
            {
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        if (knownChildren.Contains(proc.Id)) continue;

                        var cmdLine = GetCommandLine(proc);
                        var procName = proc.ProcessName.ToLower();

                        if (procName is "adb" or "fastboot" or "cmd" or "powershell" ||
                            procName.Contains("samsung") || procName.Contains("odin"))
                        {
                            knownChildren.Add(proc.Id);

                            var activity = new ProcessActivity
                            {
                                ProcessName = _targetProcessName,
                                ProcessId = proc.Id,
                                ActivityType = ActivityTypes.ProcessStart,
                                Details = $"Child process: {proc.ProcessName}",
                                Path = proc.MainModule?.FileName ?? "",
                                Extra = new() { ["command_line"] = cmdLine ?? "" }
                            };

                            LogActivity(activity);

                            Console.ForegroundColor = ConsoleColor.Magenta;
                            Console.Write($"  [Subprocess] [{DateTime.Now:HH:mm:ss}] ");
                            Console.ForegroundColor = ConsoleColor.White;
                            Console.Write(proc.ProcessName);
                            if (!string.IsNullOrEmpty(cmdLine))
                            {
                                Console.ForegroundColor = ConsoleColor.DarkGray;
                                Console.Write($" -> {cmdLine[..Math.Min(cmdLine.Length, 100)]}");
                            }
                            Console.WriteLine();
                            Console.ResetColor();
                        }
                    }
                    catch { }
                }

                await Task.Delay(500, _cts.Token);
            }
            catch (TaskCanceledException) { break; }
            catch { }
        }
    }

    private async Task MonitorFileSystemAsync(Process process)
    {
        try
        {
            var workDir = Path.GetDirectoryName(process.MainModule?.FileName);
            if (string.IsNullOrEmpty(workDir)) return;

            using var watcher = new FileSystemWatcher(workDir)
            {
                IncludeSubdirectories = true,
                EnableRaisingEvents = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite |
                              NotifyFilters.CreationTime | NotifyFilters.Size
            };

            watcher.Created += (s, e) => OnFileEvent(e.FullPath, ActivityTypes.FileCreate, "Created");
            watcher.Changed += (s, e) => OnFileEvent(e.FullPath, ActivityTypes.FileWrite, "Modified");
            watcher.Deleted += (s, e) => OnFileEvent(e.FullPath, ActivityTypes.FileDelete, "Deleted");

            while (!_cts!.Token.IsCancellationRequested && !process.HasExited)
            {
                await Task.Delay(1000, _cts.Token);
            }
        }
        catch (TaskCanceledException) { }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.DarkYellow;
            Console.Error.WriteLine($"  [!] File watch warning: {ex.Message}");
            Console.ResetColor();
        }
    }

    private void OnFileEvent(string path, string type, string description)
    {
        if (IgnorePaths.Any(p => path.Contains(p, StringComparison.OrdinalIgnoreCase)))
            return;

        var isInteresting = InterestingPaths.Any(p =>
            path.Contains(p, StringComparison.OrdinalIgnoreCase));

        var activity = new ProcessActivity
        {
            ProcessName = _targetProcessName,
            ActivityType = type,
            Details = description,
            Path = path
        };

        LogActivity(activity);

        var color = isInteresting ? ConsoleColor.Yellow : ConsoleColor.DarkGray;
        var icon = type switch
        {
            ActivityTypes.FileCreate => "[+File]",
            ActivityTypes.FileWrite => "[*File]",
            ActivityTypes.FileDelete => "[-File]",
            _ => "[File]"
        };

        Console.ForegroundColor = color;
        Console.WriteLine($"  {icon} [{DateTime.Now:HH:mm:ss}] {description}: {Path.GetFileName(path)}");
        if (isInteresting)
        {
            Console.ForegroundColor = ConsoleColor.DarkYellow;
            Console.WriteLine($"     -> Critical Path: {path}");
        }
        Console.ResetColor();
    }

    private async Task MonitorNetworkConnectionsAsync(Process process)
    {
        while (!_cts!.Token.IsCancellationRequested && !process.HasExited)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "netstat",
                    Arguments = "-ano",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var netstat = Process.Start(psi);
                if (netstat != null)
                {
                    var output = await netstat.StandardOutput.ReadToEndAsync();
                    var lines = output.Split('\n')
                        .Where(l => l.Contains(process.Id.ToString()))
                        .Where(l => l.Contains("ESTABLISHED") || l.Contains("SYN_SENT"));

                    foreach (var line in lines)
                    {
                        var trimmed = line.Trim();
                        if (_seenConnections.Contains(trimmed)) continue;
                        _seenConnections.Add(trimmed);

                        var activity = new ProcessActivity
                        {
                            ProcessName = _targetProcessName,
                            ProcessId = process.Id,
                            ActivityType = ActivityTypes.NetworkConnect,
                            Details = trimmed,
                            Path = ExtractRemoteAddress(trimmed)
                        };

                        LogActivity(activity);

                        Console.ForegroundColor = ConsoleColor.Blue;
                        Console.Write($"  [Net] [{DateTime.Now:HH:mm:ss}] Connection: ");
                        Console.ForegroundColor = ConsoleColor.White;
                        Console.WriteLine(activity.Path);
                        Console.ResetColor();
                    }
                }

                await Task.Delay(3000, _cts.Token);
            }
            catch (TaskCanceledException) { break; }
            catch { }
        }
    }

    private async Task MonitorLoadedModulesAsync(Process process)
    {
        while (!_cts!.Token.IsCancellationRequested && !process.HasExited)
        {
            try
            {
                process.Refresh();
                foreach (ProcessModule module in process.Modules)
                {
                    var name = module.ModuleName ?? "";
                    if (_loadedDlls.Contains(name)) continue;
                    _loadedDlls.Add(name);

                    var path = module.FileName ?? "";
                    if (path.Contains(@"\Windows\", StringComparison.OrdinalIgnoreCase) &&
                        !InterestingPaths.Any(p => path.Contains(p, StringComparison.OrdinalIgnoreCase)))
                        continue;

                    var activity = new ProcessActivity
                    {
                        ProcessName = _targetProcessName,
                        ProcessId = process.Id,
                        ActivityType = ActivityTypes.DllLoad,
                        Details = $"Loaded DLL: {name}",
                        Path = path,
                        Extra = new()
                        {
                            ["version"] = module.FileVersionInfo.FileVersion ?? "",
                            ["size"] = module.ModuleMemorySize.ToString()
                        }
                    };

                    LogActivity(activity);

                    Console.ForegroundColor = ConsoleColor.DarkCyan;
                    Console.WriteLine($"  [DLL] [{DateTime.Now:HH:mm:ss}] {name} ({path})");
                    Console.ResetColor();
                }

                await Task.Delay(5000, _cts.Token);
            }
            catch (TaskCanceledException) { break; }
            catch { }
        }
    }

    private async Task MonitorProcessExitAsync(Process process)
    {
        try
        {
            await process.WaitForExitAsync(_cts!.Token);

            LogActivity(new ProcessActivity
            {
                ProcessName = _targetProcessName,
                ProcessId = process.Id,
                ActivityType = ActivityTypes.ProcessExit,
                Details = $"Process exited with code: {process.ExitCode}"
            });

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"\n  [-] Process terminated (Exit Code: {process.ExitCode})");
            Console.ResetColor();

            _cts.Cancel();
        }
        catch (TaskCanceledException) { }
    }

    private void LogActivity(ProcessActivity activity)
    {
        _activities.Add(activity);
        _totalActivities++;
        _activityCounts[activity.ActivityType] =
            _activityCounts.GetValueOrDefault(activity.ActivityType) + 1;

        var fileName = $"process_log_{_targetProcessName}_{DateTime.Now:yyyy-MM-dd}.jsonl";
        var filePath = Path.Combine(_logDirectory, fileName);
        var json = JsonSerializer.Serialize(activity, _jsonOptions) + Environment.NewLine;
        File.AppendAllText(filePath, json, Encoding.UTF8);
    }

    private void PrintFinalReport()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($@"

+==========================================================+
|               Final Monitoring Report                    |
+==========================================================+
  Target Process   : {_targetProcessName}
  Total Activities : {_totalActivities}
+----------------------------------------------------------+");
        Console.ResetColor();

        Console.WriteLine("\n  Activities by Type:");
        foreach (var (type, count) in _activityCounts.OrderByDescending(x => x.Value))
        {
            Console.WriteLine($"    * {type,-25} {count,5}");
        }

        var importantFiles = _activities
            .Where(a => a.ActivityType is ActivityTypes.FileCreate or ActivityTypes.FileWrite or ActivityTypes.FileRead)
            .Where(a => InterestingPaths.Any(p => a.Path.Contains(p, StringComparison.OrdinalIgnoreCase)))
            .Select(a => a.Path)
            .Distinct()
            .ToList();

        if (importantFiles.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n  [!] Important Files Identified:");
            foreach (var file in importantFiles)
                Console.WriteLine($"    -> {file}");
            Console.ResetColor();
        }

        var childProcesses = _activities
            .Where(a => a.ActivityType == ActivityTypes.ProcessStart && a.Details.Contains("Child process"))
            .ToList();

        if (childProcesses.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine("\n  [+] Spawned Child Processes:");
            foreach (var cp in childProcesses)
            {
                Console.WriteLine($"    -> {cp.Details}");
                if (cp.Extra.TryGetValue("command_line", out var cmd) && !string.IsNullOrEmpty(cmd))
                    Console.WriteLine($"       CMD: {cmd[..Math.Min(cmd.Length, 80)]}");
            }
            Console.ResetColor();
        }

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"\n  Logs saved to: {_logDirectory}");
        Console.ResetColor();
    }

    private static string? GetCommandLine(Process process)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "wmic",
                Arguments = $"process where processid={process.Id} get commandline /format:list",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            var output = p?.StandardOutput.ReadToEnd() ?? "";
            var line = output.Split('\n').FirstOrDefault(l => l.StartsWith("CommandLine="));
            return line?.Replace("CommandLine=", "").Trim();
        }
        catch { return null; }
    }

    private static string ExtractRemoteAddress(string netstatLine)
    {
        var parts = netstatLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return parts.Length >= 3 ? parts[2] : netstatLine;
    }

    public void Stop() => _cts?.Cancel();

    public void Dispose()
    {
        _cts?.Cancel();
        _cts?.Dispose();
    }
}
