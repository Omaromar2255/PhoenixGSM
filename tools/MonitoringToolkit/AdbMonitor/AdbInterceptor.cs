namespace PhoenixGSM.AdbMonitor;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using PhoenixGSM.AdbMonitor.Models;

/// <summary>
/// اعتراض وتسجيل أوامر ADB — يعمل كوسيط شفاف كامل لتيارات الإدخال والإخراج والملفات
/// Byte-Transparent Bidirectional ADB Interceptor & Forensic Artifact Capturer
/// 
/// المميزات:
/// 1. Zero-Latency Bidirectional Streaming (Stdin >> / Stdout <<)
/// 2. Real-time capture of interactive shell tokens, AuthKeys, and :>> commands
/// 3. Automatic Forensic Vault snapshotting for BOTH push and pull operations
/// 4. Named Pipe IPC to PhoenixOmniTrace (dotnet-diagnostic-usb-svc)
/// 5. Headless / Invisible execution (immune to Q-Unlocker ConsoleWindowClass killer)
/// </summary>
public class AdbInterceptor
{
    private readonly string _realAdbPath;
    private readonly string _logDirectory;
    private readonly string _vaultDirectory;
    private readonly JsonSerializerOptions _jsonOptions;

    private static readonly string[] KnownStagingDirs =
    [
        @"C:\Users\pc5\Desktop\mac\tmp",
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "mac", "tmp"),
        Path.GetTempPath(),
        Path.Combine(Path.GetTempPath(), "mac"),
        Path.Combine(Path.GetTempPath(), "adb")
    ];

    public AdbInterceptor(string realAdbPath, string logDirectory)
    {
        _realAdbPath = realAdbPath;
        _logDirectory = logDirectory;
        _vaultDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "PhoenixGSM", "Artifacts", "PushedFiles");

        _jsonOptions = new JsonSerializerOptions
        {
            WriteIndented = false,
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };

        try { Directory.CreateDirectory(_logDirectory); } catch { }
        try { Directory.CreateDirectory(_vaultDirectory); } catch { }
    }

    /// <summary>
    /// تنفيذ أمر ADB مع التسجيل والمراقبة والتمرير المباشر ثنائي الاتجاه
    /// </summary>
    public async Task<int> ExecuteAndLogAsync(string[] args)
    {
        var fullCommand = string.Join(" ", args);
        var category = AdbCategories.Categorize(fullCommand);
        var stopwatch = Stopwatch.StartNew();
        string caller = GetParentProcessName();
        int callerPid = GetParentProcessId();
        string serial = ExtractDeviceSerial(args);

        // طباعة الأمر في الكونسول إذا وجد
        PrintColoredCommand(fullCommand, category);

        // Vector A: Pre-Push Snapshotting (Capture local source file before tool deletes it)
        TrySnapshotPushArtifact(args, caller, callerPid, serial);

        // Execute with True Bidirectional Streaming
        var (exitCode, capturedStdout, capturedStderr, capturedStdin) = await RunRealAdbStreamingAsync(args, caller, callerPid, serial);
        stopwatch.Stop();

        // Vector B: Post-Pull Snapshotting (Capture downloaded file like /data/local/tmp/athun)
        TrySnapshotPullArtifact(args, caller, callerPid, serial);

        // إنشاء سجل تفصيلي للأمر مع التيارات
        var log = new AdbCommandLog
        {
            Timestamp = DateTime.Now,
            CallingProcess = caller,
            ProcessId = callerPid,
            Command = fullCommand,
            Arguments = args,
            Response = TruncateResponse(capturedStdout + (string.IsNullOrEmpty(capturedStderr) ? "" : $"\n[ERROR]: {capturedStderr}")),
            ExitCode = exitCode,
            DurationMs = stopwatch.ElapsedMilliseconds,
            Category = category,
            DeviceSerial = serial,
            Success = exitCode == 0
        };

        // حفظ السجل في JSONL
        await SaveLogAsync(log);

        // إرسال تقرير عبر Named Pipe إلى Phoenix Monitoring Studio
        BroadcastIpcEvent(log, capturedStdin, capturedStdout);

        // طباعة النتيجة
        PrintResult(log);

        return exitCode;
    }

    /// <summary>
    /// تشغيل adb الحقيقي بتمرير فوري للتيارات (Stdin / Stdout / Stderr) واعتراض الحزم
    /// </summary>
    private async Task<(int exitCode, string stdout, string stderr, string stdin)> RunRealAdbStreamingAsync(
        string[] args, string caller, int callerPid, string serial)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = _realAdbPath,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                RedirectStandardInput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            foreach (var arg in args)
                psi.ArgumentList.Add(arg);

            using var process = Process.Start(psi);
            if (process == null)
                return (-1, "", "Failed to start real ADB binary.", "");

            using var stdinMemory = new MemoryStream();
            using var stdoutMemory = new MemoryStream();
            using var stderrMemory = new MemoryStream();

            using var cts = new CancellationTokenSource();

            // 1. STDIN Stream: Forward caller stdin -> real adb stdin in real-time
            var stdinTask = Task.Run(async () =>
            {
                try
                {
                    using var inStream = Console.OpenStandardInput();
                    byte[] buffer = new byte[4096];
                    int read;

                    // Read chunks as they arrive from parent (e.g. AuthKey, AT commands, :>> )
                    while ((read = await inStream.ReadAsync(buffer, 0, buffer.Length, cts.Token).ConfigureAwait(false)) > 0)
                    {
                        stdinMemory.Write(buffer, 0, read);
                        await process.StandardInput.BaseStream.WriteAsync(buffer, 0, read, cts.Token).ConfigureAwait(false);
                        await process.StandardInput.BaseStream.FlushAsync(cts.Token).ConfigureAwait(false);

                        // Broadcast captured >> stream chunk
                        string inText = Encoding.UTF8.GetString(buffer, 0, read);
                        BroadcastStreamChunk(">>", inText, caller, callerPid, serial);
                    }
                }
                catch { }
                finally
                {
                    try { process.StandardInput.Close(); } catch { }
                }
            });

            // 2. STDOUT Stream: Forward real adb stdout -> caller stdout in real-time
            var stdoutTask = Task.Run(async () =>
            {
                try
                {
                    using var outStream = Console.OpenStandardOutput();
                    byte[] buffer = new byte[4096];
                    int read;

                    while ((read = await process.StandardOutput.BaseStream.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false)) > 0)
                    {
                        stdoutMemory.Write(buffer, 0, read);
                        await outStream.WriteAsync(buffer, 0, read).ConfigureAwait(false);
                        await outStream.FlushAsync().ConfigureAwait(false);

                        // Broadcast captured << stream chunk (e.g. Token AuthKey, prompts)
                        string outText = Encoding.UTF8.GetString(buffer, 0, read);
                        BroadcastStreamChunk("<<", outText, caller, callerPid, serial);
                    }
                }
                catch { }
            });

            // 3. STDERR Stream: Forward real adb stderr -> caller stderr in real-time
            var stderrTask = Task.Run(async () =>
            {
                try
                {
                    using var errStream = Console.OpenStandardError();
                    byte[] buffer = new byte[4096];
                    int read;

                    while ((read = await process.StandardError.BaseStream.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false)) > 0)
                    {
                        stderrMemory.Write(buffer, 0, read);
                        await errStream.WriteAsync(buffer, 0, read).ConfigureAwait(false);
                        await errStream.FlushAsync().ConfigureAwait(false);
                    }
                }
                catch { }
            });

            // Wait for real ADB process to complete
            await process.WaitForExitAsync().ConfigureAwait(false);
            cts.Cancel(); // Signal stdin loop to terminate if still waiting

            await Task.WhenAll(stdoutTask, stderrTask).ConfigureAwait(false);

            string finalStdout = Encoding.UTF8.GetString(stdoutMemory.ToArray());
            string finalStderr = Encoding.UTF8.GetString(stderrMemory.ToArray());
            string finalStdin = Encoding.UTF8.GetString(stdinMemory.ToArray());

            return (process.ExitCode, finalStdout, finalStderr, finalStdin);
        }
        catch (Exception ex)
        {
            return (-1, "", $"Exception: {ex.Message}", "");
        }
    }

    /// <summary>
    /// يلتقط فورياً الملف المرسل بالـ push ويحفظه في خزينة الأدلة
    /// </summary>
    private void TrySnapshotPushArtifact(string[] args, string caller, int pid, string serial)
    {
        try
        {
            int pushIdx = -1;
            for (int i = 0; i < args.Length; i++)
            {
                if (string.Equals(args[i], "push", StringComparison.OrdinalIgnoreCase)) { pushIdx = i; break; }
            }
            if (pushIdx < 0 || pushIdx + 1 >= args.Length) return;

            int srcIdx = pushIdx + 1;
            while (srcIdx < args.Length && args[srcIdx].StartsWith("-")) srcIdx++;
            if (srcIdx >= args.Length) return;

            string localSource = args[srcIdx].Trim('"', '\'');
            string remoteTarget = (srcIdx + 1 < args.Length) ? args[srcIdx + 1].Trim('"', '\'') : "/data/local/tmp/pushed_file";

            string resolved = ResolveLocalPath(localSource);
            if (File.Exists(resolved))
            {
                SaveToVault(resolved, remoteTarget, "PUSH", caller, pid, serial);
            }
        }
        catch { }
    }

    /// <summary>
    /// يلتقط فورياً الملف المسحوب بالـ pull ويحفظه في خزينة الأدلة بعد نزوله
    /// </summary>
    private void TrySnapshotPullArtifact(string[] args, string caller, int pid, string serial)
    {
        try
        {
            int pullIdx = -1;
            for (int i = 0; i < args.Length; i++)
            {
                if (string.Equals(args[i], "pull", StringComparison.OrdinalIgnoreCase)) { pullIdx = i; break; }
            }
            if (pullIdx < 0 || pullIdx + 1 >= args.Length) return;

            int remoteIdx = pullIdx + 1;
            while (remoteIdx < args.Length && args[remoteIdx].StartsWith("-")) remoteIdx++;
            if (remoteIdx >= args.Length) return;

            string remoteSource = args[remoteIdx].Trim('"', '\'');
            string localTarget = (remoteIdx + 1 < args.Length) ? args[remoteIdx + 1].Trim('"', '\'') : Path.GetFileName(remoteSource);

            string resolved = ResolveLocalPath(localTarget);
            if (File.Exists(resolved))
            {
                SaveToVault(resolved, remoteSource, "PULL", caller, pid, serial);
            }
        }
        catch { }
    }

    private string ResolveLocalPath(string path)
    {
        if (File.Exists(path)) return path;

        string fn = Path.GetFileName(path);
        foreach (var dir in KnownStagingDirs)
        {
            try
            {
                if (Directory.Exists(dir))
                {
                    string combined = Path.Combine(dir, fn);
                    if (File.Exists(combined)) return combined;
                }
            }
            catch { }
        }

        if (!Path.IsPathRooted(path))
        {
            string inTemp = Path.Combine(Path.GetTempPath(), path);
            if (File.Exists(inTemp)) return inTemp;

            string inCurrent = Path.Combine(Environment.CurrentDirectory, path);
            if (File.Exists(inCurrent)) return inCurrent;
        }

        return path;
    }

    private void SaveToVault(string filePath, string targetDevicePath, string operation, string caller, int pid, string serial)
    {
        try
        {
            byte[] bytes = File.ReadAllBytes(filePath);
            if (bytes.Length == 0) return;

            string sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
            string fileName = Path.GetFileName(filePath);
            string destFile = Path.Combine(_vaultDirectory, $"{sha256}_{fileName}");

            if (!File.Exists(destFile))
            {
                File.WriteAllBytes(destFile, bytes);
            }

            // Write Manifest
            string manifestPath = Path.Combine(_vaultDirectory, $"{sha256}_{fileName}.json");
            var manifest = new
            {
                FileName = fileName,
                TargetDevicePath = targetDevicePath,
                Operation = operation,
                FileSizeBytes = bytes.Length,
                Sha256 = sha256,
                Caller = caller,
                Pid = pid,
                DeviceSerial = serial,
                Timestamp = DateTime.UtcNow
            };
            File.WriteAllText(manifestPath, JsonSerializer.Serialize(manifest, _jsonOptions));
        }
        catch { }
    }

    /// <summary>
    /// بث فوري لأجزاء التدفق التفاعلي (>> / <<) عبر Named Pipe
    /// </summary>
    private static void BroadcastStreamChunk(string direction, string text, string caller, int pid, string serial)
    {
        if (string.IsNullOrWhiteSpace(text)) return;
        _ = Task.Run(async () =>
        {
            try
            {
                using var pipe = new NamedPipeClientStream(".", "dotnet-diagnostic-usb-svc", PipeDirection.Out);
                await pipe.ConnectAsync(50).ConfigureAwait(false);
                using var writer = new StreamWriter(pipe, Encoding.UTF8) { AutoFlush = true };

                var evt = new
                {
                    Event = "AdbStreamChunk",
                    Direction = direction,
                    Text = text.Trim(),
                    Caller = caller,
                    Pid = pid,
                    Serial = serial,
                    Timestamp = DateTime.UtcNow
                };
                await writer.WriteLineAsync(JsonSerializer.Serialize(evt)).ConfigureAwait(false);
            }
            catch { }
        });
    }

    private static void BroadcastIpcEvent(AdbCommandLog log, string stdin, string stdout)
    {
        _ = Task.Run(async () =>
        {
            try
            {
                using var pipe = new NamedPipeClientStream(".", "dotnet-diagnostic-usb-svc", PipeDirection.Out);
                await pipe.ConnectAsync(50).ConfigureAwait(false);
                using var writer = new StreamWriter(pipe, Encoding.UTF8) { AutoFlush = true };

                var evt = new
                {
                    Event = "AdbCommandLogged",
                    Command = log.Command,
                    Category = log.Category,
                    Caller = log.CallingProcess,
                    Pid = log.ProcessId,
                    Serial = log.DeviceSerial,
                    Success = log.Success,
                    DurationMs = log.DurationMs,
                    Stdin = stdin,
                    Stdout = stdout,
                    Timestamp = log.Timestamp
                };
                await writer.WriteLineAsync(JsonSerializer.Serialize(evt)).ConfigureAwait(false);
            }
            catch { }
        });
    }

    private async Task SaveLogAsync(AdbCommandLog log)
    {
        try
        {
            var fileName = $"adb_log_{DateTime.Now:yyyy-MM-dd}.jsonl";
            var filePath = Path.Combine(_logDirectory, fileName);
            var jsonLine = JsonSerializer.Serialize(log, _jsonOptions) + Environment.NewLine;
            await File.AppendAllTextAsync(filePath, jsonLine, Encoding.UTF8);
        }
        catch { }
    }

    private static string GetParentProcessName()
    {
        try
        {
            var parentId = GetParentProcessId();
            if (parentId > 0)
            {
                using var parent = Process.GetProcessById(parentId);
                return parent.ProcessName;
            }
        }
        catch { }
        return "GSM_Tool";
    }

    private static int GetParentProcessId()
    {
        try
        {
            // Windows basic parent query
            using var current = Process.GetCurrentProcess();
            return current.Id;
        }
        catch { return 0; }
    }

    private static string ExtractDeviceSerial(string[] args)
    {
        for (int i = 0; i < args.Length - 1; i++)
        {
            if (args[i] == "-s") return args[i + 1];
        }
        return "default";
    }

    private static string TruncateResponse(string response, int maxLength = 65536)
    {
        if (string.IsNullOrEmpty(response)) return "";
        return response.Length <= maxLength
            ? response.TrimEnd()
            : response[..maxLength].TrimEnd() + $"\n... [TRUNCATED: Showing {maxLength:N0} chars of {response.Length:N0} total]";
    }

    private static void PrintColoredCommand(string command, string category)
    {
        try
        {
            var originalColor = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Error.Write($"[{DateTime.Now:HH:mm:ss}] ");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Error.Write($"[{category}] ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Error.WriteLine(command);
            Console.ForegroundColor = originalColor;
        }
        catch { }
    }

    private static void PrintResult(AdbCommandLog log)
    {
        try
        {
            var originalColor = Console.ForegroundColor;
            Console.ForegroundColor = log.Success ? ConsoleColor.DarkGreen : ConsoleColor.DarkRed;
            Console.Error.Write($"  └─ ");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Error.WriteLine(
                $"{(log.Success ? "[OK]" : "[FAIL]")} {log.DurationMs}ms | " +
                $"Caller: {log.CallingProcess} | Device: {log.DeviceSerial}");
            Console.ForegroundColor = originalColor;
        }
        catch { }
    }

    /// <summary>
    /// تثبيت الوسيط الشفاف في مجلد مستهدف (مثل %TEMP% أو مجلد أداة معينة)
    /// </summary>
    public static void Install(string adbDirectory)
    {
        var adbPath = Path.Combine(adbDirectory, "adb.exe");
        var realAdbPath = Path.Combine(adbDirectory, "adb_real.exe");
        var monitorExe = Process.GetCurrentProcess().MainModule?.FileName;
        var monitorDir = Path.GetDirectoryName(monitorExe) ?? AppDomain.CurrentDomain.BaseDirectory;

        if (!File.Exists(adbPath))
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[!] adb.exe not found in: {adbDirectory}");
            Console.ResetColor();
            return;
        }

        if (File.Exists(realAdbPath))
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[!] Monitor is already installed. Use --uninstall first if needed.");
            Console.ResetColor();
            return;
        }

        File.Move(adbPath, realAdbPath);
        if (monitorExe != null)
        {
            File.Copy(monitorExe, adbPath, true);

            // Copy companion files (.dll, .runtimeconfig.json, .deps.json)
            string[] companions = ["AdbMonitor.dll", "AdbMonitor.runtimeconfig.json", "AdbMonitor.deps.json"];
            foreach (var comp in companions)
            {
                string src = Path.Combine(monitorDir, comp);
                if (File.Exists(src))
                {
                    string dst = Path.Combine(adbDirectory, comp);
                    File.Copy(src, dst, true);
                }
            }
        }

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("[+] Transparent ADB Proxy installed successfully!");
        Console.WriteLine($"    Real ADB   : {realAdbPath}");
        Console.WriteLine($"    Proxy Hook : {adbPath}");
        Console.ResetColor();
    }

    public static void Uninstall(string adbDirectory)
    {
        var adbPath = Path.Combine(adbDirectory, "adb.exe");
        var realAdbPath = Path.Combine(adbDirectory, "adb_real.exe");

        if (!File.Exists(realAdbPath))
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[!] Monitor is not installed.");
            Console.ResetColor();
            return;
        }

        if (File.Exists(adbPath)) File.Delete(adbPath);
        File.Move(realAdbPath, adbPath);

        string[] companions = ["AdbMonitor.dll", "AdbMonitor.runtimeconfig.json", "AdbMonitor.deps.json"];
        foreach (var comp in companions)
        {
            string dst = Path.Combine(adbDirectory, comp);
            if (File.Exists(dst)) { try { File.Delete(dst); } catch { } }
        }

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("[+] Monitor uninstalled and original adb.exe restored successfully.");
        Console.ResetColor();
    }
}
