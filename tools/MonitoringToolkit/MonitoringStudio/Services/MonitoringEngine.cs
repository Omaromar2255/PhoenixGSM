using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using PhoenixGSM.MonitoringStudio.Models;
using PhoenixGSM.UsbMonitor;
using PhoenixGSM.UsbMonitor.Models;
using PhoenixGSM.UsbMonitor.Protocol;
using PhoenixGSM.UsbMonitorDiscovery;
using PhoenixGSM.UsbMonitorDiscovery.Models;
using System.Diagnostics.Eventing.Reader;
using System.Management;

namespace PhoenixGSM.MonitoringStudio.Services;

/// <summary>
/// Unified Multi-Layer Monitoring Engine.
/// Coordinates Kernel USB driver capture, PnP topology, WMI &amp; Security 4688 process tracing,
/// ADB proxy logging, Serial/COM ports, and the Phoenix Omni-Trace engine fabric.
/// </summary>
public partial class MonitoringEngine : IDisposable
{
    private readonly UsbDriverClient _driverClient = new();
    private readonly AdbProtocolParser _adbParser = new();
    private readonly UsbScanner _usbScanner = new();
    private PhoenixGSM.OmniTrace.Service.PhoenixOmniTraceService? _omniService;

    private CancellationTokenSource? _cts;
    private Task? _driverLoopTask;
    private Task? _topologyLoopTask;
    private Task? _processLoopTask;
    private Task? _adbLogWatcherTask;
    private Task? _serialWatcherTask;
    private PhoenixGSM.OmniTrace.Commands.UniversalToolCommandInterceptor? _fallbackToolInterceptor;

    private int _eventIdCounter = 0;
    private readonly HashSet<int> _knownToolPids = [];
    private readonly HashSet<string> _knownComPorts = [];
    private readonly HashSet<string> _seenDeviceInstances = [];
    private long _lastAdbLogFileOffset = 0;
    private string? _activeAdbLogFile = null;

    public event Action<LiveEventItem>? OnEventReceived;
    public event Action<PhoenixGSM.OmniTrace.TechnicianAudit.TechnicianAuditRecord>? OnTechnicianAuditCaptured;
    public event Action<PhoenixGSM.OmniTrace.ToolSourceInterception.ToolSourceCommandRecord>? OnToolSourceCommandCaptured;
    public event Action<List<UsbDeviceInfo>>? OnTopologyChanged;
    public event Action<string[]>? OnComPortsChanged;
    public event Action<List<string>>? OnToolsChanged;
    public event Action<bool, string>? OnDriverStatusChanged;

    public PhoenixGSM.OmniTrace.Service.PhoenixOmniTraceService? OmniService => _omniService;
    public PhoenixGSM.OmniTrace.TechnicianAudit.TechnicianPhoneCommandAuditLayer? TechnicianAuditLayer => _omniService?.TechnicianAuditLayer;
    public PhoenixGSM.OmniTrace.ToolSourceInterception.ToolSourceInterceptionOrchestrator? ToolSourceOrchestrator => _omniService?.ToolSourceOrchestrator;

    private bool _isTechnicianAuditEnabled = false;
    public bool IsTechnicianAuditEnabled
    {
        get => _omniService?.TechnicianAuditEnabled ?? _isTechnicianAuditEnabled;
        set
        {
            _isTechnicianAuditEnabled = value;
            if (_omniService != null)
            {
                _omniService.TechnicianAuditEnabled = value;
            }
        }
    }

    public bool CaptureDeviceResponses
    {
        get => _omniService?.CaptureDeviceResponses ?? false;
        set
        {
            if (_omniService != null)
            {
                _omniService.CaptureDeviceResponses = value;
            }
        }
    }

    public bool IsRunning { get; private set; }
    public bool IsDriverConnected => _driverClient.IsDriverAvailable();

    // Granular Sensor Capture Flags
    public bool IsUsbMonitoringEnabled { get; set; } = true;
    public bool IsAdbMonitoringEnabled { get; set; } = true;
    public bool IsSerialMonitoringEnabled { get; set; } = true;
    public bool IsProcessMonitoringEnabled { get; set; } = true;
    public bool IsUrlMonitoringEnabled { get; set; } = false;
    public bool IsTempAtMonitoringEnabled { get; set; } = true;
    public bool IsAppleMonitoringEnabled { get; set; } = true;
    public bool IsArtifactVaultEnabled { get; set; } = true;
    public bool IsMtpMonitoringEnabled { get; set; } = true;
    public bool IsCmdMonitoringEnabled { get; set; } = true;
    public bool IsShellMonitoringEnabled { get; set; } = true;
    public bool IsToolSourceMonitoringEnabled { get; set; } = true;

    public void Start()
    {
        if (IsRunning) return;
        IsRunning = true;
        _cts = new CancellationTokenSource();
        var token = _cts.Token;

        // 0. Initialize per-session CapturedArtifacts folder immediately so file archiving works even if USB Filter is OFF!
        string sessionFolder = _smartFileArchiver.StartNewSession();
        _smartFileArchiver.OnFileArchivedAsync -= EmitCapturedPushedFile;
        _smartFileArchiver.OnFileArchivedAsync += EmitCapturedPushedFile;

        // 1. Phoenix Omni-Trace Engine & IPC Server (Universal Interceptors, Bus & Sensors)
        try
        {
            _omniService = new PhoenixGSM.OmniTrace.Service.PhoenixOmniTraceService();
            _omniService.EventBus.OnLogicalCommand += HandleOmniCommand;
            _omniService.EventBus.OnRawCaptured += HandleOmniRaw;
            _omniService.NetworkSensor.OnUrlCaptured += HandleNetworkUrlCaptured;
            _omniService.ClipboardSensor.OnUrlCaptured += HandleNetworkUrlCaptured;
            _omniService.TempFileSensor.OnTempFileAtCaptured += HandleTempFileAtCaptured;
            _omniService.InProcessSensor.OnInProcessOperationCaptured += HandleInProcessCaptured;
            _omniService.ArtifactSensor.OnArtifactCaptured += HandleArtifactCaptured;
            _omniService.ToolSessionSensor.OnToolSessionCaptured += HandleToolSessionCaptured;
            _omniService.TechnicianAuditLayer.OnCommandAudited += HandleTechnicianAudit;
            _omniService.ToolSourceOrchestrator.OnCommandCaptured += HandleToolSourceCommandCaptured;
            _omniService.CommandLineSniffer.OnProcessCommandCaptured += (_, cmdInfo) =>
            {
                if (!string.IsNullOrWhiteSpace(cmdInfo.CommandLine) &&
                    cmdInfo.CommandLine.Contains("push", StringComparison.OrdinalIgnoreCase))
                {
                    _smartFileArchiver.NotifyAdbPushCommandLine(cmdInfo.CommandLine, cmdInfo.ProcessId, 0, null, IsDriverConnected);
                }
            };
            _omniService.TechnicianAuditEnabled = _isTechnicianAuditEnabled;
            _omniService.Start();
        }
        catch { }

        // 2. USB Kernel Driver Packet Capture Loop
        _driverLoopTask = Task.Run(() => DriverCaptureLoop(token), token);

        // 3. USB Physical Topology Watcher Loop (Immediate detection of plugged phones)
        _topologyLoopTask = Task.Run(() => TopologyWatcherLoop(token), token);

        // 4. Real-Time Universal Tool Command Interception & Fail-Open Fallback
        StartProcessTraceWatcher();
        StartSecurityAuditWatcher();

        // 5. GSM Repair Process Watcher Loop
        _processLoopTask = Task.Run(() => ProcessWatcherLoop(token), token);

        // 6. ADB Transparent Proxy Log Watcher Loop
        _adbLogWatcherTask = Task.Run(() => AdbLogWatcherLoop(token), token);

        // 7. Serial / COM Ports Watcher Loop
        _serialWatcherTask = Task.Run(() => SerialWatcherLoop(token), token);

        EmitEvent(new LiveEventItem
        {
            Category = EventSourceCategory.UsbDriver,
            SourceTag = "SYSTEM",
            Protocol = "ENGINE",
            Command = "STARTED",
            Summary = $"Unified Multi-Layer Monitoring Engine started (Session Folder: CapturedArtifacts/{_smartFileArchiver.CurrentSessionFolderName}).",
            AdditionalDetails = $"Zero-CMD dependency active. Session Folder: {sessionFolder}"
        });
    }

    public void Stop()
    {
        if (!IsRunning) return;
        IsRunning = false;
        _cts?.Cancel();
        _driverClient.Dispose();
        StopProcessTraceWatcher();
        StopSecurityAuditWatcher();

        try
        {
            if (_omniService != null)
            {
                _omniService.ArtifactSensor.OnArtifactCaptured -= HandleArtifactCaptured;
                _omniService.InProcessSensor.OnInProcessOperationCaptured -= HandleInProcessCaptured;
                _omniService.TempFileSensor.OnTempFileAtCaptured -= HandleTempFileAtCaptured;
                _omniService.NetworkSensor.OnUrlCaptured -= HandleNetworkUrlCaptured;
                _omniService.ClipboardSensor.OnUrlCaptured -= HandleNetworkUrlCaptured;
                _omniService.TechnicianAuditLayer.OnCommandAudited -= HandleTechnicianAudit;
                _omniService.ToolSourceOrchestrator.OnCommandCaptured -= HandleToolSourceCommandCaptured;
                _omniService.Stop();
                _omniService.Dispose();
                _omniService = null;
            }
        }
        catch { }
        EmitEvent(new LiveEventItem
        {
            Category = EventSourceCategory.UsbDriver,
            SourceTag = "SYSTEM",
            Protocol = "ENGINE",
            Command = "STOPPED",
            Summary = "Monitoring Engine paused by user."
        });
    }

    private void HandleTechnicianAudit(PhoenixGSM.OmniTrace.TechnicianAudit.TechnicianAuditRecord record)
    {
        OnTechnicianAuditCaptured?.Invoke(record);
    }

    private void HandleToolSourceCommandCaptured(PhoenixGSM.OmniTrace.ToolSourceInterception.ToolSourceCommandRecord record)
    {
        OnToolSourceCommandCaptured?.Invoke(record);

        EmitEvent(new LiveEventItem
        {
            Timestamp = record.Timestamp,
            Category = EventSourceCategory.ToolSource,
            SourceTag = $"SRC-{record.ModeName}",
            Direction = "HOST->DEV",
            EndpointOrTarget = record.TargetEndpoint,
            Protocol = record.ModeName,
            Command = record.PureCommand,
            Summary = $"[{record.ToolName}] {record.PureCommand} -> {record.TargetEndpoint} ({record.PayloadSize}B) [{record.InterceptMechanism}]",
            RawPayload = record.RawPayload,
            PayloadAscii = record.TechnicalDetails,
            PayloadHex = record.PayloadHex,
            AdditionalDetails = record.TechnicalDetails
        });
    }

    private void EmitEvent(LiveEventItem item)
    {
        // Granular Sensor Capture Filter
        if (!IsUsbMonitoringEnabled && item.Category == EventSourceCategory.UsbDriver) return;
        if (!IsAdbMonitoringEnabled && item.Category == EventSourceCategory.AdbProxy) return;
        if (!IsSerialMonitoringEnabled && item.Category == EventSourceCategory.SerialPort) return;
        if (!IsProcessMonitoringEnabled && item.Category == EventSourceCategory.Process) return;
        if (!IsUrlMonitoringEnabled && item.Category == EventSourceCategory.NetworkUrl) return;
        if (!IsTempAtMonitoringEnabled && item.Category == EventSourceCategory.TempFileAt) return;
        if (!IsAppleMonitoringEnabled && item.Category == EventSourceCategory.AppleIos) return;
        if (!IsArtifactVaultEnabled && item.Category == EventSourceCategory.ArtifactVault) return;
        if (!IsMtpMonitoringEnabled && item.Category == EventSourceCategory.Mtp) return;
        if (!IsCmdMonitoringEnabled && item.Category == EventSourceCategory.Cmd) return;
        if (!IsShellMonitoringEnabled && item.Category == EventSourceCategory.Shell) return;
        if (!IsToolSourceMonitoringEnabled && item.Category == EventSourceCategory.ToolSource) return;

        item.Id = Interlocked.Increment(ref _eventIdCounter);
        OnEventReceived?.Invoke(item);
    }

    public void Dispose()
    {
        Stop();
    }
}
