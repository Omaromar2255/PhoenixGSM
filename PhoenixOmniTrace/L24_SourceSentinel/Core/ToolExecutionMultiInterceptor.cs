using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using PhoenixGSM.OmniTrace.Sensors;
using PhoenixOmniTrace.L24_SourceSentinel.Models;

namespace PhoenixOmniTrace.L24_SourceSentinel.Core;

/// <summary>
/// محرك الاعتراض المتعدد والمستقل لأوامر الأدوات قبل وأثناء التنفيذ (Multi-Vector Tool Command & Session Interceptor)
/// </summary>
public sealed class ToolExecutionMultiInterceptor : IDisposable
{
    private readonly ConcurrentDictionary<int, string> _trackedToolPids = new();
    private readonly ConcurrentDictionary<int, string> _seenChildProcessCmds = new();
    private readonly ConcurrentDictionary<string, DateTime> _dedupMap = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<FileSystemWatcher> _stagingWatchers = new();

    private CancellationTokenSource? _cts;
    private Task? _pebTreeTask;
    private Task? _consolePtyTask;
    private Task? _loopbackSocketTask;
    private Task? _namedPipeTask;
    private volatile bool _isRunning;
    private bool _isDisposed;

    public event Action<SourceTelemetryEvent>? OnToolCommandIntercepted;
    public event Action<int, string>? OnChildProcessRegistered;

    public bool IsEnabled { get; set; } = true;

    private static readonly string[] TargetCliBinaries =
    [
        "cmd", "powershell", "pwsh", "conhost", "openconsole",
        "adb", "fastboot", "fh_loader", "qsahara_server", "edl", "spd_dump",
        "irecovery", "ideviceinfo", "ideviceactivation", "idevice_id", "idevicepair",
        "idevicerestore", "idevicebackup2", "ideviceinstaller", "iproxy", "gaster",
        "python", "python3", "7z", "7za", "tar", "unzip", "lz4", "simg2img", "lpunpack",
        "openssl", "curl", "wget", "devcon", "pnputil", "filter-x64", "filter-x86"
    ];

    private static readonly Regex AdbSocketCommandRegex = new(
        @"^[0-9A-Fa-f]{4}(?:host|shell|exec|abb|abb_exec|sync|usb|reboot|remount|root|unroot|tcpip|forward|reverse|localabstract|localfilesystem|dev|jdwp|track-devices|version|kill)[^\x00]{0,400}",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public void RegisterToolProcess(int pid, string processName)
    {
        if (pid <= 0) return;
        _trackedToolPids[pid] = processName;
    }

    public static void PrepareToolLaunchEnvironment(ProcessStartInfo startInfo, string toolDirectory, string captureDirectory)
    {
        if (startInfo == null) return;
        try
        {
            if (!startInfo.UseShellExecute)
            {
                string traceLogDir = Path.Combine(captureDirectory, "ToolEnvLogs");
                Directory.CreateDirectory(traceLogDir);
                startInfo.EnvironmentVariables["ADB_TRACE"] = "all";
                startInfo.EnvironmentVariables["ANDROID_ADB_LOG_PATH"] = Path.Combine(traceLogDir, "adb_trace.log");
                startInfo.EnvironmentVariables["SSLKEYLOGFILE"] = Path.Combine(traceLogDir, "sslkeys.log");
            }
        }
        catch { }
    }

    public void Start()
    {
        if (_isRunning || _isDisposed) return;
        _isRunning = true;

        try { _cts?.Cancel(); _cts?.Dispose(); } catch { }
        _cts = new CancellationTokenSource();
        var token = _cts.Token;

        InitializePreExecutionStagingWatchers();

        _pebTreeTask = Task.Run(() => FastPebProcessTreeLoop(token), token);
        _consolePtyTask = Task.Run(() => InteractiveConsoleAndPtyLoop(token), token);
        _loopbackSocketTask = Task.Run(() => AdbAndUsbmuxLoopbackProbeLoop(token), token);
        _namedPipeTask = Task.Run(() => NamedPipeActivityScannerLoop(token), token);
    }

    public void Stop()
    {
        if (!_isRunning) return;
        _isRunning = false;

        try { _cts?.Cancel(); _cts?.Dispose(); } catch { }
        _cts = null;

        lock (_stagingWatchers)
        {
            foreach (var w in _stagingWatchers)
            {
                try { w.EnableRaisingEvents = false; w.Dispose(); } catch { }
            }
            _stagingWatchers.Clear();
        }
    }

    private async Task FastPebProcessTreeLoop(CancellationToken token)
    {
        while (!token.IsCancellationRequested && _isRunning)
        {
            if (!IsEnabled)
            {
                await Task.Delay(500, token).ConfigureAwait(false);
                continue;
            }

            try
            {
                var procs = Process.GetProcesses();
                foreach (var p in procs)
                {
                    if (token.IsCancellationRequested) break;
                    try
                    {
                        int pid = p.Id;
                        if (_seenChildProcessCmds.ContainsKey(pid)) continue;

                        string pName = p.ProcessName;
                        string pNameLower = pName.ToLowerInvariant();

                        bool isTargetCli = TargetCliBinaries.Any(b => pNameLower.Equals(b, StringComparison.OrdinalIgnoreCase) || pNameLower.StartsWith(b + ".", StringComparison.OrdinalIgnoreCase));
                        string? cmdLine = SmartFilePushArchiver.TryGetProcessCommandLineFast(pid, out int parentPid);

                        bool isChildOfTrackedTool = parentPid > 0 && (_trackedToolPids.ContainsKey(parentPid) || _seenChildProcessCmds.ContainsKey(parentPid));

                        if (!isChildOfTrackedTool && !isTargetCli)
                            continue;

                        if (string.IsNullOrWhiteSpace(cmdLine))
                        {
                            try { cmdLine = p.MainModule?.FileName ?? pName; } catch { cmdLine = pName; }
                        }

                        _seenChildProcessCmds[pid] = cmdLine;

                        if (isChildOfTrackedTool)
                        {
                            _trackedToolPids[pid] = pName;
                        }

                        if (pNameLower is "adb" or "fastboot" or "cmd" or "powershell" or "pwsh" or "python" or "fh_loader" or "qsahara_server" or "spd_dump" or "irecovery")
                        {
                            OnChildProcessRegistered?.Invoke(pid, pName + ".exe");
                        }

                        string trimmedCmd = cmdLine.Trim().Trim('"');
                        if (pNameLower == "conhost" || trimmedCmd.Equals(pName, StringComparison.OrdinalIgnoreCase) || trimmedCmd.EndsWith($"\\{pName}.exe", StringComparison.OrdinalIgnoreCase))
                            continue;

                        string decodedExtra = TryDecodePowerShellOrBase64(cmdLine);
                        string effectiveCmd = !string.IsNullOrWhiteSpace(decodedExtra) ? $"{cmdLine} | [Decoded]: {decodedExtra}" : cmdLine;

                        string savedFile = TryExtractAndArchiveFileFromCommandLine(cmdLine, pName);

                        string parentName = _trackedToolPids.TryGetValue(parentPid, out var pn) ? pn : $"PID_{parentPid}";
                        string category = ClassifyInterceptedCommand(pNameLower, effectiveCmd);

                        EmitInterceptedCommand(
                            pid,
                            SentinelStage.RawCommandExecution,
                            "PEB_FastCommandLineSniffer",
                            $"{parentName} -> {pName}.exe",
                            pName + ".exe",
                            category,
                            $"⚡ أمر منفذ من الأداة عبر [{pName}.exe]: {effectiveCmd}",
                            effectiveCmd,
                            savedFile);
                    }
                    catch { }
                    finally
                    {
                        p.Dispose();
                    }
                }
            }
            catch { }

            try { await Task.Delay(35, token).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }
    }

    private async Task InteractiveConsoleAndPtyLoop(CancellationToken token)
    {
        while (!token.IsCancellationRequested && _isRunning)
        {
            if (!IsEnabled)
            {
                await Task.Delay(800, token).ConfigureAwait(false);
                continue;
            }

            try
            {
                foreach (var kvp in _trackedToolPids.ToArray())
                {
                    if (token.IsCancellationRequested) break;
                    string procLower = kvp.Value.ToLowerInvariant();
                    if (procLower.Contains("cmd") || procLower.Contains("powershell") || procLower.Contains("adb") || procLower.Contains("python") || procLower.Contains("irecovery"))
                    {
                        ScanProcessSmallActiveIoBuffers(kvp.Key, kvp.Value);
                    }
                }
            }
            catch { }

            try { await Task.Delay(180, token).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }
    }

    private void ScanProcessSmallActiveIoBuffers(int pid, string procName)
    {
        IntPtr hProc = IntPtr.Zero;
        try
        {
            hProc = OpenProcess(0x0400 | 0x0010, false, pid);
            if (hProc == IntPtr.Zero) return;

            long addr = 0x10000;
            long maxAddr = Environment.Is64BitOperatingSystem ? 0x7FFFFFFEFFFFL : 0x7FFF0000L;
            uint mbiSize = (uint)System.Runtime.InteropServices.Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();
            byte[] buf = new byte[16384];
            int regionsScanned = 0;

            while (addr < maxAddr && regionsScanned < 180)
            {
                if (VirtualQueryEx(hProc, (IntPtr)addr, out var mbi, mbiSize) == 0) break;

                long regSize = mbi.RegionSize.ToInt64();
                if (mbi.State == 0x1000 && mbi.Type == 0x20000 && mbi.Protect == 0x04 && regSize is >= 4096 and <= 65536)
                {
                    regionsScanned++;
                    int toRead = (int)Math.Min(regSize, buf.Length);
                    if (ReadProcessMemory(hProc, mbi.BaseAddress, buf, toRead, out int read) && read > 8)
                    {
                        InspectInteractiveBufferForCommands(pid, procName, buf, read);
                    }
                }

                long next = mbi.BaseAddress.ToInt64() + Math.Max(regSize, 4096);
                if (next <= addr) break;
                addr = next;
            }
        }
        catch { }
        finally
        {
            if (hProc != IntPtr.Zero) CloseHandle(hProc);
        }
    }

    private void InspectInteractiveBufferForCommands(int pid, string procName, byte[] buf, int len)
    {
        string utf8 = Encoding.UTF8.GetString(buf, 0, len);
        foreach (Match m in AdbSocketCommandRegex.Matches(utf8))
        {
            string raw = m.Value.Trim();
            if (raw.Length > 6)
            {
                string cleanCmd = raw[4..].Trim();
                if (ForensicNoiseGate.IsCleanAscii(cleanCmd))
                {
                    EmitInterceptedCommand(
                        pid,
                        SentinelStage.RawCommandExecution,
                        "ADB_SmartSocket_PtyInterceptor",
                        $"{procName} (PID:{pid})",
                        "ADB SmartSocket / PTY Session",
                        "ADB / Interactive PTY Command",
                        $"⚡ أمر جلسة تفاعلية (ADB Socket/PTY) صادر من [{procName}]: {cleanCmd}",
                        cleanCmd);
                }
            }
        }
    }

    private void InitializePreExecutionStagingWatchers()
    {
        var dirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            Path.GetTempPath(),
            @"C:\Temp",
            @"C:\UnlockTool\Temp",
            @"C:\Windows\Temp"
        };

        foreach (var d in dirs)
        {
            TryAddStagingWatcher(d);
        }
    }

    public void AddToolStagingWatcher(string toolDir)
    {
        if (string.IsNullOrWhiteSpace(toolDir) || !Directory.Exists(toolDir)) return;
        TryAddStagingWatcher(toolDir);
    }

    private void TryAddStagingWatcher(string dir)
    {
        if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir)) return;
        try
        {
            var watcher = new FileSystemWatcher(dir)
            {
                IncludeSubdirectories = true,
                InternalBufferSize = 65536,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime
            };

            watcher.Created += OnStagedFileActivity;
            watcher.Changed += OnStagedFileActivity;
            watcher.Renamed += (s, e) => OnStagedFileActivity(s, e);
            watcher.EnableRaisingEvents = true;

            lock (_stagingWatchers)
            {
                _stagingWatchers.Add(watcher);
            }
        }
        catch { }
    }

    private void OnStagedFileActivity(object sender, FileSystemEventArgs e)
    {
        if (!IsEnabled || !_isRunning || string.IsNullOrWhiteSpace(e.FullPath)) return;
        if (e.FullPath.Contains("L24_SourceSentinel", StringComparison.OrdinalIgnoreCase) ||
            e.FullPath.Contains("CapturedFiles", StringComparison.OrdinalIgnoreCase) ||
            e.FullPath.Contains("CapturedArtifacts", StringComparison.OrdinalIgnoreCase))
            return;

        try
        {
            string ext = Path.GetExtension(e.FullPath).ToLowerInvariant();
            string name = Path.GetFileName(e.FullPath).ToLowerInvariant();

            if (ext is ".bat" or ".cmd" or ".ps1" or ".sh" or ".at" or ".seq" ||
                (ext == ".xml" && (name.Contains("rawprogram") || name.Contains("patch") || name.Contains("firehose"))))
            {
                string? content = TryReadTextShared(e.FullPath);
                if (!string.IsNullOrWhiteSpace(content))
                {
                    L24FileArchiver.TryArchiveDiscoveredFile(e.FullPath, "PreExec_ScriptHunter", out string savedScript, out _, out _);
                    string cleanPreview = content.Trim().Replace("\r\n", " ; ").Replace("\n", " ; ");
                    if (cleanPreview.Length > 320) cleanPreview = cleanPreview[..320] + "...";

                    EmitInterceptedCommand(
                        0,
                        SentinelStage.RawCommandExecution,
                        "PreExec_ScriptInterceptor",
                        "Tool Script Generator",
                        e.FullPath,
                        "Staged Script / Batch Execution",
                        $"📜 سكربت أوامر مرحلي ولدته الأداة للتنفيذ [{Path.GetFileName(e.FullPath)}]: {cleanPreview}",
                        cleanPreview,
                        savedScript);
                }
                return;
            }

            if (ext is ".bin" or ".da" or ".mbn" or ".elf" or ".img4" or ".im4p" or ".shsh2" or ".pit" or ".auth" or ".qcn" or ".xqcn" or ".pac" or ".ofp" or ".ops" ||
                name.Contains("preloader") || name.Contains("firehose") || name.Contains("loader") || name.Contains("ramdisk") || name.Contains("ibss") || name.Contains("ibec"))
            {
                if (L24FileArchiver.TryArchiveDiscoveredFile(e.FullPath, "PreExec_LoaderHunter", out string savedLoader, out long savedLen, out _))
                {
                    EmitInterceptedCommand(
                        0,
                        SentinelStage.LocalFilePreparation,
                        "PreExec_LoaderArchiver",
                        "Tool Loader Staging",
                        savedLoader,
                        "Boot Loader / Firmware File Access",
                        $"💾 تم اصطياد وحفظ ملف البوت/اللودر المستخدم فور تجهيزه: [{Path.GetFileName(e.FullPath)}] ({savedLen:N0} بايت) -> {savedLoader}",
                        e.FullPath,
                        savedLoader,
                        (int)Math.Min(savedLen, int.MaxValue));
                }
            }
        }
        catch { }
    }

    private async Task AdbAndUsbmuxLoopbackProbeLoop(CancellationToken token)
    {
        string lastAdbDevices = string.Empty;
        while (!token.IsCancellationRequested && _isRunning)
        {
            if (!IsEnabled)
            {
                await Task.Delay(1500, token).ConfigureAwait(false);
                continue;
            }

            try
            {
                using var client = new System.Net.Sockets.TcpClient();
                var connectTask = client.ConnectAsync(System.Net.IPAddress.Loopback, 5037);
                if (await Task.WhenAny(connectTask, Task.Delay(250, token)).ConfigureAwait(false) == connectTask && client.Connected)
                {
                    using var stream = client.GetStream();
                    byte[] req = Encoding.ASCII.GetBytes("000Chost:devices");
                    await stream.WriteAsync(req, 0, req.Length, token).ConfigureAwait(false);

                    byte[] respBuf = new byte[512];
                    int read = await stream.ReadAsync(respBuf, 0, respBuf.Length, token).ConfigureAwait(false);
                    if (read > 4)
                    {
                        string status = Encoding.ASCII.GetString(respBuf, 0, 4);
                        string payload = Encoding.UTF8.GetString(respBuf, 4, read - 4).Trim();
                        if (status == "OKAY" && !string.IsNullOrWhiteSpace(payload) && payload != lastAdbDevices)
                        {
                            lastAdbDevices = payload;
                            EmitInterceptedCommand(
                                0,
                                SentinelStage.PortAndDeviceRadar,
                                "AdbLoopback5037Watcher",
                                "ADB Server (127.0.0.1:5037)",
                                "TCP:5037",
                                "ADB Device Connected",
                                $"🤖 خادم ADB المحلي رصد جهازاً متصلاً: {payload.Replace('\n', ' ').Replace('\r', ' ')}",
                                $"adb devices -> {payload}");
                        }
                    }
                }
            }
            catch { }

            try { await Task.Delay(2000, token).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }
    }

    private async Task NamedPipeActivityScannerLoop(CancellationToken token)
    {
        var seenPipes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        while (!token.IsCancellationRequested && _isRunning)
        {
            if (!IsEnabled)
            {
                await Task.Delay(2000, token).ConfigureAwait(false);
                continue;
            }

            try
            {
                string[] pipes = Directory.GetFiles(@"\\.\pipe\");
                foreach (var pipe in pipes)
                {
                    string pName = Path.GetFileName(pipe);
                    if (seenPipes.Contains(pName)) continue;

                    string lower = pName.ToLowerInvariant();
                    if (lower.Contains("adb") || lower.Contains("unlock") || lower.Contains("chimera") ||
                        lower.Contains("mtk") || lower.Contains("brom") || lower.Contains("edl") ||
                        lower.Contains("qcom") || lower.Contains("odin") || lower.Contains("apple") ||
                        lower.Contains("conpty") || lower.Contains("msys") || lower.Contains("cygwin"))
                    {
                        seenPipes.Add(pName);
                        EmitInterceptedCommand(
                            0,
                            SentinelStage.PortAndDeviceRadar,
                            "NamedPipeRadar",
                            "Windows IPC Pipe",
                            pipe,
                            "IPC Pipe / PTY Channel Created",
                            $"🔗 إنشاء قناة اتصال داخلية / جلسة طرفية (Named Pipe / ConPTY): {pipe}",
                            pipe);
                    }
                }
            }
            catch { }

            try { await Task.Delay(1500, token).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }
    }

    private static string ClassifyInterceptedCommand(string procNameLower, string cmdLine)
    {
        string lower = $"{procNameLower} {cmdLine}".ToLowerInvariant();
        if (lower.Contains("fastboot")) return "Fastboot Command";
        if (lower.Contains("adb")) return "ADB / Interactive Shell";
        if (lower.Contains("fh_loader") || lower.Contains("qsahara") || lower.Contains("9008") || lower.Contains("firehose"))
            return "Qualcomm EDL / Sahara Execution";
        if (lower.Contains("mtk") || lower.Contains("brom") || lower.Contains("0e8d") || lower.Contains("da_"))
            return "MediaTek BROM / Service Execution";
        if (lower.Contains("irecovery") || lower.Contains("idevice") || lower.Contains("iproxy") || lower.Contains("gaster") || lower.Contains("ramdisk"))
            return "Apple iOS CLI Execution";
        if (lower.Contains("spd_dump") || lower.Contains("fdl"))
            return "Unisoc / SPD BSL Frame";
        if (lower.Contains("7z") || lower.Contains("tar") || lower.Contains("unzip") || lower.Contains("lz4") || lower.Contains("simg2img"))
            return "Archive / Unpack Execution";
        if (lower.Contains("openssl") || lower.Contains("decrypt"))
            return "Crypto / Decryption Execution";
        return "Tool Command Execution";
    }

    private static string TryDecodePowerShellOrBase64(string cmdLine)
    {
        try
        {
            var m = Regex.Match(cmdLine, @"-(?:enc|EncodedCommand)\s+([A-Za-z0-9+/=]{8,})", RegexOptions.IgnoreCase);
            if (m.Success)
            {
                byte[] bytes = Convert.FromBase64String(m.Groups[1].Value);
                return Encoding.Unicode.GetString(bytes).Trim();
            }

            var b64 = Regex.Match(cmdLine, @"echo\s+([A-Za-z0-9+/=]{16,})\s*\|\s*base64\s+-d", RegexOptions.IgnoreCase);
            if (b64.Success)
            {
                byte[] bytes = Convert.FromBase64String(b64.Groups[1].Value);
                return Encoding.UTF8.GetString(bytes).Trim();
            }
        }
        catch { }
        return string.Empty;
    }

    private static string TryExtractAndArchiveFileFromCommandLine(string cmdLine, string procName)
    {
        try
        {
            var pathMatches = Regex.Matches(cmdLine, @"([a-zA-Z]:\\[a-zA-Z0-9_\-\.\/\\ ]+\.(?:bin|da|auth|mbn|elf|img|img4|im4p|pit|ops|ofp|pac|qcn|xqcn|zip|7z|tar|xml|apk|sh))", RegexOptions.IgnoreCase);
            foreach (Match m in pathMatches)
            {
                string candidate = m.Groups[1].Value.Trim().Trim('"');
                if (L24FileArchiver.TryArchiveDiscoveredFile(candidate, $"CommandLineSniffer ({procName})", out string saved, out _, out _))
                {
                    return saved;
                }
            }
        }
        catch { }
        return string.Empty;
    }

    private static string? TryReadTextShared(string path)
    {
        for (int i = 0; i < 3; i++)
        {
            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                if (fs.Length <= 0 || fs.Length > 2 * 1024 * 1024) return null;
                using var sr = new StreamReader(fs, Encoding.UTF8);
                return sr.ReadToEnd();
            }
            catch { Thread.Sleep(15); }
        }
        return null;
    }

    private void EmitInterceptedCommand(
        int pid,
        SentinelStage stage,
        string apiName,
        string callerOrigin,
        string targetRes,
        string category,
        string description,
        string pureCommand,
        string savedFilePath = "",
        int payloadSizeOverride = 0)
    {
        string key = $"{stage}:{category}:{pureCommand}";
        DateTime now = DateTime.UtcNow;
        if (_dedupMap.TryGetValue(key, out var last) && (now - last).TotalSeconds < 1.5)
            return;
        _dedupMap[key] = now;

        byte[] rawBytes = Encoding.UTF8.GetBytes(pureCommand);
        OnToolCommandIntercepted?.Invoke(new SourceTelemetryEvent
        {
            ProcessId = pid,
            ThreadId = 0,
            Stage = stage,
            HookedApiName = apiName,
            CallerModuleOrigin = callerOrigin,
            TargetResource = targetRes,
            CommandCategory = category,
            DecodedCommandText = description,
            PureCommandText = pureCommand,
            SavedFilePath = savedFilePath,
            RawPayloadHex = Convert.ToHexString(rawBytes.AsSpan(0, Math.Min(rawBytes.Length, 256))),
            PayloadSize = payloadSizeOverride > 0 ? payloadSizeOverride : rawBytes.Length
        });
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    private struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    public void Dispose()
    {
        if (_isDisposed) return;
        _isDisposed = true;
        Stop();
    }
}
