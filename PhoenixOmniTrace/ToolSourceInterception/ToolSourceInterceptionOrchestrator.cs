using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using PhoenixGSM.OmniTrace.Bus;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.ToolSourceInterception;

/// <summary>
/// Autonomous Multi-Mode Tool-Source Command Interception Orchestrator.
/// Discovers active GSM tools and captures commands from the tools themselves
/// across MTP, MTK BROM, Samsung Odin, and Serial Port modes.
/// المنظم المركزي لطبقة التقاط الأوامر من مصدر الأدوات والبرامج
/// </summary>
public sealed class ToolSourceInterceptionOrchestrator : IDisposable
{
    private static readonly string[] KnownToolKeywords =
    [
        "unlocktool", "chimera", "miracle", "dftpro", "pandora", "z3x", "octoplus",
        "samfw", "odin", "3utools", "miflash", "qfil", "spflash", "flashtool", "umt",
        "hydra", "easyjtag", "cheetah", "tft", "sigmakey", "dc-unlocker", "cm2",
        "medusa", "ufi", "mrt", "trtools", "qcfire", "globalunlocker", "nck"
    ];

    private readonly OmniTraceEventBus? _bus;
    private readonly ToolSourceApiHookEngine _hookEngine;
    private readonly ToolSourceEtwFallbackSensor _etwSensor;
    private readonly ToolSourceAutoLogger _autoLogger;
    private readonly ConcurrentDictionary<int, string> _discoveredTools = new();

    private CancellationTokenSource? _cts;
    private Task? _discoveryTask;
    private long _idCounter;
    private ulong _rawSequence;
    private bool _isRunning;

    public ToolSourceAutoLogger AutoLogger => _autoLogger;
    public bool IsRunning => _isRunning;

    // Real-Time Counters
    public int TotalCapturedCount { get; private set; }
    public int MtpCount { get; private set; }
    public int MtkCount { get; private set; }
    public int OdinCount { get; private set; }
    public int PortCount { get; private set; }
    public int UniversalCount { get; private set; }

    public event Action<ToolSourceCommandRecord>? OnCommandCaptured;

    public ToolSourceInterceptionOrchestrator(OmniTraceEventBus? bus = null, string? customLogDir = null)
    {
        _bus = bus;
        _hookEngine = new ToolSourceApiHookEngine();
        _etwSensor = new ToolSourceEtwFallbackSensor(_hookEngine);
        _autoLogger = new ToolSourceAutoLogger(customLogDir);

        _hookEngine.OnCommandCaptured += HandleCapturedRecord;
    }

    public void Start()
    {
        if (_isRunning) return;
        _isRunning = true;
        _cts = new CancellationTokenSource();

        _hookEngine.Start();
        _etwSensor.Start();

        _discoveryTask = Task.Run(() => ToolDiscoveryLoop(_cts.Token), _cts.Token);
    }

    public void Stop()
    {
        if (!_isRunning) return;
        _isRunning = false;
        _cts?.Cancel();

        _etwSensor.Stop();
        _hookEngine.Stop();
        _autoLogger.Flush();
        _discoveredTools.Clear();
    }

    /// <summary>
    /// Explicitly inject a command from external sources (e.g. testing or driver correlators).
    /// </summary>
    public ToolSourceCommandRecord IngestCommand(
        int pid,
        int parentPid,
        string toolName,
        string apiName,
        string endpoint,
        byte[] payload)
    {
        return _hookEngine.IngestApiCall(pid, parentPid, toolName, apiName, endpoint, payload);
    }

    private void HandleCapturedRecord(ToolSourceCommandRecord record)
    {
        record.Id = Interlocked.Increment(ref _idCounter);

        // Update mode counters
        TotalCapturedCount++;
        switch (record.Mode)
        {
            case ToolSourceMode.Mtp: MtpCount++; break;
            case ToolSourceMode.MtkBrom: MtkCount++; break;
            case ToolSourceMode.SamsungOdin: OdinCount++; break;
            case ToolSourceMode.SerialPort: PortCount++; break;
            default: UniversalCount++; break;
        }

        // 1. Auto-save to disk
        _autoLogger.Enqueue(record);

        // 2. Dispatch to subscribers
        OnCommandCaptured?.Invoke(record);

        // 3. Dispatch to OmniTrace EventBus if connected
        if (_bus != null)
        {
            DispatchToBus(record);
        }
    }

    private void DispatchToBus(ToolSourceCommandRecord record)
    {
        if (_bus == null) return;

        ulong seq = Interlocked.Increment(ref _rawSequence);
        byte[] payload = record.RawPayload ?? Encoding.UTF8.GetBytes(record.PureCommand);

        var raw = RawCaptureEvent.Create(
            sequence: seq,
            sensor: SensorType.Process,
            transport: TransportType.BULK,
            direction: PacketDirection.HOST_TO_DEVICE,
            device: record.TargetEndpoint,
            session: $"{record.ToolName}_{record.ProcessId}_{record.ModeName}",
            iface: 0,
            endpoint: record.InterceptMechanism,
            payload: payload,
            timestampSource: "ToolSourceInterception"
        );

        raw.Metadata["ToolName"] = record.ToolName;
        raw.Metadata["ProcessId"] = record.ProcessId.ToString();
        raw.Metadata["Mode"] = record.ModeName;
        raw.Metadata["PureCommand"] = record.PureCommand;
        raw.Metadata["RiskLevel"] = record.RiskLevel;
        raw.Metadata["SourceTag"] = "TOOL-SOURCE";

        _bus.Publish(raw);

        var logical = new LogicalCommandEvent
        {
            Command = record.PureCommand,
            Protocol = record.Mode switch
            {
                ToolSourceMode.MtkBrom => KnownProtocol.MtkBrom,
                ToolSourceMode.SamsungOdin => KnownProtocol.SamsungOdin,
                ToolSourceMode.SerialPort => KnownProtocol.SerialAt,
                ToolSourceMode.Mtp => KnownProtocol.Mtp,
                _ => KnownProtocol.HostCommand
            },
            Service = record.ToolName,
            Transport = TransportType.BULK,
            DeviceIdentity = record.TargetEndpoint,
            SessionIdentity = record.ToolName,
            Direction = PacketDirection.HOST_TO_DEVICE,
            Confidence = 1.0,
            Timestamp = record.Timestamp
        };

        logical.Details["Mode"] = record.ModeName;
        logical.Details["InterceptMechanism"] = record.InterceptMechanism;
        logical.Details["TechnicalDetails"] = record.TechnicalDetails;
        logical.Details["RiskLevel"] = record.RiskLevel;
        logical.Details["Caller"] = $"{record.ToolName} (PID {record.ProcessId})";

        logical.Attribution.ProcessId = record.ProcessId;
        logical.Attribution.ImageName = record.ToolName;

        _bus.ReportLogicalCommand(logical);
    }

    private async Task ToolDiscoveryLoop(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                var processes = Process.GetProcesses();
                foreach (var p in processes)
                {
                    try
                    {
                        string name = p.ProcessName.ToLowerInvariant();
                        bool isTool = KnownToolKeywords.Any(k => name.Contains(k));
                        if (isTool && !_discoveredTools.ContainsKey(p.Id))
                        {
                            string exeName = p.ProcessName + ".exe";
                            _discoveredTools[p.Id] = exeName;
                            _hookEngine.RegisterToolProcess(p.Id, exeName);
                            _etwSensor.RegisterTargetPid(p.Id, exeName);
                        }
                    }
                    catch { }
                    finally
                    {
                        p.Dispose();
                    }
                }

                // Clean up terminated processes
                var dead = _discoveredTools.Keys.Where(pid =>
                {
                    try
                    {
                        using var proc = Process.GetProcessById(pid);
                        return proc.HasExited;
                    }
                    catch { return true; }
                }).ToList();

                foreach (var d in dead)
                {
                    _discoveredTools.TryRemove(d, out _);
                    _hookEngine.UnregisterToolProcess(d);
                    _etwSensor.UnregisterTargetPid(d);
                }

                await Task.Delay(2000, token);
            }
            catch (OperationCanceledException) { break; }
            catch { await Task.Delay(3000, token); }
        }
    }

    public void Dispose()
    {
        Stop();
        _autoLogger.Dispose();
        _hookEngine.Dispose();
        _etwSensor.Dispose();
    }
}
