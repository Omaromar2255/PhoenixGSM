using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using PhoenixOmniTrace.L24_SourceSentinel.Models;

namespace PhoenixOmniTrace.L24_SourceSentinel.Core;

/// <summary>
/// محرك الاعتراض المتعدد والمستقل لأوامر الأدوات قبل وأثناء التنفيذ (Multi-Vector Tool Command & Session Interceptor)
/// </summary>
public sealed partial class ToolExecutionMultiInterceptor : IDisposable
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

    public void Dispose()
    {
        if (_isDisposed) return;
        _isDisposed = true;
        Stop();
    }
}
