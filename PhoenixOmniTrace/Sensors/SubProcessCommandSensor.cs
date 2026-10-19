using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using PhoenixGSM.OmniTrace.Bus;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.Sensors;

/// <summary>
/// LAYER 18 — Sub-Process Execution Command Sensor
/// Captures commands in real-time via Kernel ETW ProcessStart (&lt; 1ms latency) when any child process
/// (such as adb.exe push, fastboot.exe, irecovery.exe) is executed, even when the USB Filter is OFF.
/// </summary>
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public sealed class SubProcessCommandSensor : IDisposable
{
    private readonly OmniTraceEventBus _bus;
    private TraceEventSession? _session;
    private bool _isRunning;
    private ulong _sequence;

    public bool IsRunning => _isRunning;

    public SubProcessCommandSensor(OmniTraceEventBus bus)
    {
        _bus = bus ?? throw new ArgumentNullException(nameof(bus));
    }

    public void Start()
    {
        if (_isRunning) return;
        _isRunning = true;
        StartEtwProcessWatcher();
    }

    public void Stop()
    {
        if (!_isRunning) return;
        _isRunning = false;
        try
        {
            if (_session != null)
            {
                _session.Stop();
                _session.Dispose();
                _session = null;
            }
        }
        catch { }
    }

    private void StartEtwProcessWatcher()
    {
        try
        {
            _session = new TraceEventSession("PhoenixOmniTrace_SubProcessSensor");
            _session.EnableKernelProvider(KernelTraceEventParser.Keywords.Process);

            _session.Source.Kernel.ProcessStart += OnProcessStarted;

            Task.Run(() => 
            {
                try { _session.Source.Process(); }
                catch { }
            });
        }
        catch 
        {
            // Fail-open: if ETW tracing fails, fallback sensors continue
        }
    }

    private static readonly HashSet<string> IgnoredNoiseProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "MicrosoftEdgeUpdate.exe", "GoogleUpdate.exe", "svchost.exe", "services.exe",
        "chrome.exe", "msedge.exe", "firefox.exe",
        "git.exe", "SearchHost.exe", "RuntimeBroker.exe", "taskhostw.exe", "WmiPrvSE.exe",
        "attrib.exe",
        "MicrosoftEdgeUpdate", "GoogleUpdate", "svchost", "services",
        "chrome", "msedge", "firefox",
        "git", "SearchHost", "RuntimeBroker", "taskhostw", "WmiPrvSE", "attrib",
        "WMIC"
    };

    private static bool IsNoiseProcess(string? nameOrPath)
    {
        if (string.IsNullOrWhiteSpace(nameOrPath)) return false;
        string fileName = System.IO.Path.GetFileName(nameOrPath.Trim());
        return IgnoredNoiseProcesses.Contains(fileName) || IgnoredNoiseProcesses.Contains(System.IO.Path.GetFileNameWithoutExtension(fileName));
    }

    private void OnProcessStarted(Microsoft.Diagnostics.Tracing.Parsers.Kernel.ProcessTraceData e)
    {
        try
        {
            string processName = e.ProcessName;
            int pid = e.ProcessID;
            int ppid = e.ParentID;
            string cmdLine = e.CommandLine;
            string executablePath = e.ImageFileName;
            
            if (string.IsNullOrWhiteSpace(executablePath))
                executablePath = processName;

            if (string.IsNullOrWhiteSpace(cmdLine))
                cmdLine = executablePath;

            string callerName = "CMD/User";
            try
            {
                var parentProc = Process.GetProcessById(ppid);
                callerName = parentProc.ProcessName;
            }
            catch { }

            bool isExplicitTargetTool = processName.Equals("adb", StringComparison.OrdinalIgnoreCase) ||
                                        processName.Equals("adb.exe", StringComparison.OrdinalIgnoreCase) ||
                                        processName.Equals("fastboot", StringComparison.OrdinalIgnoreCase) ||
                                        processName.Equals("fastboot.exe", StringComparison.OrdinalIgnoreCase);

            // Never drop adb.exe or fastboot.exe even if launched from explorer.exe or cmd.exe!
            if (!isExplicitTargetTool && (IsNoiseProcess(processName) || IsNoiseProcess(executablePath) || IsNoiseProcess(callerName)))
            {
                return;
            }

            string trimmedCmd = cmdLine.Trim(' ', '"');
            if (string.IsNullOrWhiteSpace(cmdLine) ||
                trimmedCmd.Equals(processName, StringComparison.OrdinalIgnoreCase) ||
                trimmedCmd.Equals(executablePath, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            ReportSubProcessCommandEvent(processName, pid, executablePath, cmdLine, ppid, callerName);
        }
        catch { }
    }

    private void ReportSubProcessCommandEvent(string processName, int pid, string executablePath, string commandLine, int ppid, string callerName)
    {
        ulong seq = Interlocked.Increment(ref _sequence);
        byte[] payload = Encoding.UTF8.GetBytes(commandLine);
        
        string operationType = "SubProcess Execution";

        var rawEvt = RawCaptureEvent.Create(
            sequence: seq,
            sensor: SensorType.Process,
            transport: TransportType.BULK,
            direction: PacketDirection.INTERNAL,
            device: "Host",
            session: $"{callerName}_{ppid}_to_{processName}_{pid}",
            iface: 0,
            endpoint: "SubProcess_Monitor",
            payload: payload,
            timestampSource: "SubProcessCommandSensor"
        );

        rawEvt.Metadata["ToolName"] = callerName;
        rawEvt.Metadata["ProcessId"] = pid.ToString();
        rawEvt.Metadata["ParentProcessId"] = ppid.ToString();
        rawEvt.Metadata["CommandLine"] = commandLine;
        rawEvt.Metadata["ExecutablePath"] = executablePath;
        rawEvt.Metadata["OperationType"] = operationType;
        
        _bus.Publish(rawEvt);

        var cmd = _bus.Correlation.Correlate(
            "SUBPROCESS_EXECUTION",
            KnownProtocol.InProcess,
            callerName,
            TransportType.BULK,
            "Host",
            $"{callerName}_{ppid}_to_{processName}_{pid}",
            PacketDirection.INTERNAL,
            [rawEvt.SequenceNumber],
            [rawEvt.PayloadHash],
            confidence: 1.0,
            suspectedPid: pid,
            suspectedToolName: callerName
        );

        cmd.Details["CommandLine"] = commandLine;
        cmd.Details["ExecutablePath"] = executablePath;
        cmd.Details["OperationType"] = operationType;
        cmd.Details["Caller"] = $"{callerName} (PID {ppid})";
        cmd.Details["PID"] = pid.ToString();
        cmd.Details["ParentPID"] = ppid.ToString();
        
        if (pid > 0) cmd.Attribution.ProcessId = pid;
        if (ppid > 0) cmd.Attribution.ParentProcessId = ppid;
        cmd.Attribution.ImageName = processName;
        cmd.Attribution.CommandLine = commandLine;

        _bus.ReportLogicalCommand(cmd);
    }

    public void Dispose()
    {
        Stop();
    }
}
