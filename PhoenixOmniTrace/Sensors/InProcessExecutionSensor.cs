using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using PhoenixGSM.OmniTrace.Bus;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.Sensors;

/// <summary>
/// Information model for an intercepted in-process GSM servicing tool operation.
/// </summary>
public sealed class InProcessOperationEvent
{
    public string ToolName { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public string OperationName { get; set; } = string.Empty;
    public string TargetDevice { get; set; } = string.Empty;
    public byte[] Payload { get; set; } = [];
    public Dictionary<string, string> Details { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string SourceTag { get; set; } = "IN-PROCESS";
}

/// <summary>
/// LAYER 3F — In-Process Servicing & Execution Sensor
/// Intercepts internal GSM repair operations executed directly in-process by tools
/// (e.g. direct WinUSB / AdbWinUsbApi calls, memory-staged routines, vendor DLL servicing)
/// that bypass external shells (cmd.exe / powershell.exe) completely.
/// Operates in fail-open mode with zero crash overhead.
/// </summary>
public sealed class InProcessExecutionSensor : IDisposable
{
    private readonly OmniTraceEventBus _bus;
    private readonly ConcurrentDictionary<string, DateTime> _dedupCache = new(StringComparer.OrdinalIgnoreCase);
    private bool _isRunning;
    private ulong _sequence;

    // Observability metrics
    private long _operationsCaptured;
    private long _bytesCaptured;

    public bool IsRunning => _isRunning;
    public long OperationsCaptured => Interlocked.Read(ref _operationsCaptured);
    public long BytesCaptured => Interlocked.Read(ref _bytesCaptured);

    public event Action<InProcessOperationEvent>? OnInProcessOperationCaptured;

    public InProcessExecutionSensor(OmniTraceEventBus bus)
    {
        _bus = bus ?? throw new ArgumentNullException(nameof(bus));
    }

    public void Start()
    {
        _isRunning = true;
    }

    public void Stop()
    {
        _isRunning = false;
        _dedupCache.Clear();
    }

    private static readonly HashSet<string> IgnoredNoiseProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "MicrosoftEdgeUpdate.exe", "GoogleUpdate.exe", "svchost.exe", "services.exe",
        "chrome.exe", "msedge.exe", "firefox.exe", "explorer.exe", "conhost.exe",
        "git.exe", "SearchHost.exe", "RuntimeBroker.exe", "taskhostw.exe", "WmiPrvSE.exe",
        "attrib.exe",
        "MicrosoftEdgeUpdate", "GoogleUpdate", "svchost", "services",
        "chrome", "msedge", "firefox", "explorer", "conhost",
        "git", "SearchHost", "RuntimeBroker", "taskhostw", "WmiPrvSE", "attrib",
        "WMIC", "Unknown Caller"
    };

    /// <summary>
    /// Ingests and attributes an in-process operation executed directly by a GSM tool.
    /// Emits both a RawCaptureEvent and a correlated LogicalCommandEvent (KnownProtocol.InProcess).
    /// </summary>
    public void IngestInProcessOperation(
        string toolName,
        int pid,
        string operationName,
        string targetDevice,
        byte[] payload,
        Dictionary<string, string>? details = null)
    {
        if (string.IsNullOrWhiteSpace(toolName)) toolName = "GSM_Tool.exe";
        string cleanTool = System.IO.Path.GetFileName(toolName.Trim());
        if (IgnoredNoiseProcesses.Contains(cleanTool) || IgnoredNoiseProcesses.Contains(System.IO.Path.GetFileNameWithoutExtension(cleanTool)))
        {
            return;
        }

        // Suppress dumb SUBPROCESS_EXECUTION events without actual command line
        if (operationName.Equals("SUBPROCESS_EXECUTION", StringComparison.OrdinalIgnoreCase))
        {
            bool hasValidCmd = details != null &&
                               details.TryGetValue("CommandLine", out var cLine) &&
                               !string.IsNullOrWhiteSpace(cLine) &&
                               !cLine.Trim().Equals(cleanTool, StringComparison.OrdinalIgnoreCase) &&
                               !cLine.Trim().Equals("SUBPROCESS_EXECUTION", StringComparison.OrdinalIgnoreCase);
            if (!hasValidCmd)
            {
                return;
            }
        }

        if (string.IsNullOrWhiteSpace(operationName)) operationName = "InProcess_Operation";
        if (string.IsNullOrWhiteSpace(targetDevice)) targetDevice = "Host";
        payload ??= [];

        // Deduplication: prevent identical bursts within 200ms
        string payloadHash = payload.Length > 0
            ? Convert.ToHexString(SHA256.HashData(payload))[..16]
            : "EMPTY";
        string dedupKey = $"{cleanTool}:{pid}:{operationName}:{payloadHash}";
        DateTime now = DateTime.UtcNow;

        if (_dedupCache.TryGetValue(dedupKey, out var exp) && now < exp)
        {
            return;
        }
        _dedupCache[dedupKey] = now.AddMilliseconds(200);

        if (_dedupCache.Count > 500)
        {
            foreach (var kvp in _dedupCache)
            {
                if (now > kvp.Value) _dedupCache.TryRemove(kvp.Key, out _);
            }
        }

        Interlocked.Increment(ref _operationsCaptured);
        Interlocked.Add(ref _bytesCaptured, payload.Length);

        var opEvt = new InProcessOperationEvent
        {
            ToolName = toolName,
            ProcessId = pid,
            OperationName = operationName,
            TargetDevice = targetDevice,
            Payload = payload,
            Details = details != null ? new Dictionary<string, string>(details, StringComparer.OrdinalIgnoreCase) : [],
            Timestamp = now,
            SourceTag = "IN-PROCESS"
        };

        OnInProcessOperationCaptured?.Invoke(opEvt);

        // 1. Publish RawCaptureEvent
        ulong seq = Interlocked.Increment(ref _sequence);
        var rawEvt = RawCaptureEvent.Create(
            sequence: seq,
            sensor: SensorType.Process,
            transport: TransportType.BULK,
            direction: PacketDirection.INTERNAL,
            device: targetDevice,
            session: $"{toolName}_{pid}",
            iface: 0,
            endpoint: operationName,
            payload: payload.Length > 0 ? payload : Encoding.UTF8.GetBytes(operationName),
            timestampSource: "InProcessExecutionSensor"
        );

        rawEvt.Metadata["ToolName"] = toolName;
        rawEvt.Metadata["ProcessId"] = pid.ToString();
        rawEvt.Metadata["Operation"] = operationName;
        rawEvt.Metadata["TargetDevice"] = targetDevice;
        rawEvt.Metadata["ExecutionType"] = "InProcessDirect";
        rawEvt.Metadata["SourceTag"] = "IN-PROCESS";

        if (details != null)
        {
            foreach (var kvp in details)
            {
                rawEvt.Metadata[kvp.Key] = kvp.Value;
            }
        }

        _bus.Publish(rawEvt);

        // 2. Correlate and Report LogicalCommandEvent directly
        var cmd = _bus.Correlation.Correlate(
            operationName,
            KnownProtocol.InProcess,
            toolName,
            TransportType.BULK,
            targetDevice,
            $"{toolName}_{pid}",
            PacketDirection.INTERNAL,
            [rawEvt.SequenceNumber],
            [rawEvt.PayloadHash],
            confidence: 1.0,
            suspectedPid: pid,
            suspectedToolName: toolName
        );

        cmd.Details["ExecutionType"] = "InProcessDirect";
        cmd.Details["TargetDevice"] = targetDevice;
        if (details != null)
        {
            foreach (var kvp in details)
            {
                cmd.Details[kvp.Key] = kvp.Value;
            }
        }

        if (pid > 0) cmd.Attribution.ProcessId = pid;
        cmd.Attribution.ImageName = toolName;

        _bus.ReportLogicalCommand(cmd);
    }

    /// <summary>
    /// Helper simulation method for automated verification and test pipelines.
    /// </summary>
    public void SimulateOperation(
        string toolName,
        int pid,
        string operationName,
        string targetDevice = "Qualcomm HS-USB QDLoader 9008",
        byte[]? payload = null,
        Dictionary<string, string>? details = null)
    {
        IngestInProcessOperation(toolName, pid, operationName, targetDevice, payload ?? [], details);
    }

    public void Dispose()
    {
        Stop();
    }
}
