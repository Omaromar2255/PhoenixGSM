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
/// Coordinates Kernel USB driver capture, PnP topology, WMI & Security 4688 process tracing,
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

    public PhoenixGSM.OmniTrace.TechnicianAudit.TechnicianPhoneCommandAuditLayer? TechnicianAuditLayer => _omniService?.TechnicianAuditLayer;
    public PhoenixGSM.OmniTrace.ToolSourceInterception.ToolSourceInterceptionOrchestrator? ToolSourceOrchestrator => _omniService?.ToolSourceOrchestrator;

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

    public void Start()
    {
        if (IsRunning) return;
        IsRunning = true;
        _cts = new CancellationTokenSource();
        var token = _cts.Token;

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
            Summary = "Unified Multi-Layer Monitoring Engine started (Real-Time Process, USB & Omni-Trace Active).",
            AdditionalDetails = "Zero-CMD dependency active. Phoenix Omni-Trace transport-agnostic engine active."
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

    private void HandleOmniCommand(PhoenixGSM.OmniTrace.Models.LogicalCommandEvent cmd)
    {
        bool isStreamIn = cmd.Command.StartsWith("<<");
        bool isStreamOut = cmd.Command.StartsWith(">>");

        string evidenceHashes = string.Join(", ", cmd.EvidenceHashes.Select(h => h.Length > 8 ? h[..8] : h));

        EventSourceCategory category;
        if (cmd.Details.TryGetValue("Category", out var customCatStr) &&
            Enum.TryParse<EventSourceCategory>(customCatStr, true, out var parsedCat))
        {
            category = parsedCat;
        }
        else
        {
            category = cmd.Protocol switch
            {
                PhoenixGSM.OmniTrace.Models.KnownProtocol.SerialAt when cmd.Transport == PhoenixGSM.OmniTrace.Models.TransportType.FILE => EventSourceCategory.TempFileAt,
                PhoenixGSM.OmniTrace.Models.KnownProtocol.SerialAt => EventSourceCategory.SerialPort,
                PhoenixGSM.OmniTrace.Models.KnownProtocol.Mtp or PhoenixGSM.OmniTrace.Models.KnownProtocol.Ptp => EventSourceCategory.Mtp,
                PhoenixGSM.OmniTrace.Models.KnownProtocol.MtkBrom or PhoenixGSM.OmniTrace.Models.KnownProtocol.MtkDa => EventSourceCategory.MediaTek,
                PhoenixGSM.OmniTrace.Models.KnownProtocol.SpreadtrumFdl => EventSourceCategory.UnisocSpd,
                PhoenixGSM.OmniTrace.Models.KnownProtocol.QualcommSahara or PhoenixGSM.OmniTrace.Models.KnownProtocol.QualcommFirehose => EventSourceCategory.QualcommEdl,
                PhoenixGSM.OmniTrace.Models.KnownProtocol.HostCommand => EventSourceCategory.Cmd,
                PhoenixGSM.OmniTrace.Models.KnownProtocol.InProcess => EventSourceCategory.InProcess,
                PhoenixGSM.OmniTrace.Models.KnownProtocol.AppleUsbmuxd or
                PhoenixGSM.OmniTrace.Models.KnownProtocol.AppleLockdown or
                PhoenixGSM.OmniTrace.Models.KnownProtocol.AppleRecovery or
                PhoenixGSM.OmniTrace.Models.KnownProtocol.AppleDfu or
                PhoenixGSM.OmniTrace.Models.KnownProtocol.AppleRamdiskSsh or
                PhoenixGSM.OmniTrace.Models.KnownProtocol.ApplePurpleDiag => EventSourceCategory.AppleIos,
                _ => EventSourceCategory.AdbProxy
            };
        }

        string sourceTag;
        if (cmd.Details.TryGetValue("SourceTag", out var customTag) && !string.IsNullOrWhiteSpace(customTag))
        {
            sourceTag = customTag;
        }
        else
        {
            sourceTag = cmd.Protocol switch
            {
                PhoenixGSM.OmniTrace.Models.KnownProtocol.SerialAt when cmd.Transport == PhoenixGSM.OmniTrace.Models.TransportType.FILE => "TEMP-AT",
                PhoenixGSM.OmniTrace.Models.KnownProtocol.SerialAt => "SERIAL-AT",
                PhoenixGSM.OmniTrace.Models.KnownProtocol.Mtp or PhoenixGSM.OmniTrace.Models.KnownProtocol.Ptp => "MTP",
                PhoenixGSM.OmniTrace.Models.KnownProtocol.MtkBrom => "MTK-BROM",
                PhoenixGSM.OmniTrace.Models.KnownProtocol.MtkDa => "MTK-DA",
                PhoenixGSM.OmniTrace.Models.KnownProtocol.SpreadtrumFdl => "SPD-FDL",
                PhoenixGSM.OmniTrace.Models.KnownProtocol.QualcommSahara => "EDL-SAHARA",
                PhoenixGSM.OmniTrace.Models.KnownProtocol.QualcommFirehose => "EDL-FIREHOSE",
                PhoenixGSM.OmniTrace.Models.KnownProtocol.AppleUsbmuxd => "APPLE-MUX",
                PhoenixGSM.OmniTrace.Models.KnownProtocol.AppleLockdown => "APPLE-LOCK",
                PhoenixGSM.OmniTrace.Models.KnownProtocol.AppleRecovery => "APPLE-REC",
                PhoenixGSM.OmniTrace.Models.KnownProtocol.AppleDfu => "APPLE-DFU",
                PhoenixGSM.OmniTrace.Models.KnownProtocol.AppleRamdiskSsh => "APPLE-SSH",
                PhoenixGSM.OmniTrace.Models.KnownProtocol.ApplePurpleDiag => "APPLE-DIAG",
                PhoenixGSM.OmniTrace.Models.KnownProtocol.HostCommand => "CMD/SHELL",
                PhoenixGSM.OmniTrace.Models.KnownProtocol.InProcess => "IN-PROCESS",
                _ when isStreamOut => "STREAM >>",
                _ when isStreamIn => "STREAM <<",
                _ => "OMNITRACE"
            };
        }

        string endpointOrTarget;
        if (!string.IsNullOrEmpty(cmd.Service) && 
            (cmd.Service.Contains("/data/local/tmp") || cmd.Service.Contains("athun") || cmd.Service.Contains("trd") || cmd.Service.Contains("su") || cmd.Service.Contains("chmod")))
        {
            // Direct attribution to the targeted ELF binary / shell command
            endpointOrTarget = cmd.Service.StartsWith("shell:", StringComparison.OrdinalIgnoreCase)
                ? cmd.Service["shell:".Length..].Trim()
                : (cmd.Service.StartsWith("exec:", StringComparison.OrdinalIgnoreCase)
                    ? cmd.Service["exec:".Length..].Trim()
                    : cmd.Service.Trim());
        }
        else if (cmd.Protocol == PhoenixGSM.OmniTrace.Models.KnownProtocol.Mtp)
        {
            endpointOrTarget = "MTP / Media Device";
        }
        else if (cmd.Protocol is PhoenixGSM.OmniTrace.Models.KnownProtocol.MtkBrom or PhoenixGSM.OmniTrace.Models.KnownProtocol.MtkDa)
        {
            endpointOrTarget = cmd.Details.TryGetValue("Chipset", out var cs) ? cs : (!string.IsNullOrEmpty(cmd.DeviceIdentity) ? cmd.DeviceIdentity : "MediaTek Device");
        }
        else if (cmd.Protocol == PhoenixGSM.OmniTrace.Models.KnownProtocol.SpreadtrumFdl)
        {
            endpointOrTarget = cmd.Details.TryGetValue("ChipVersion", out var cv) ? cv : (!string.IsNullOrEmpty(cmd.DeviceIdentity) ? cmd.DeviceIdentity : "Unisoc / Spreadtrum");
        }
        else if (cmd.Protocol is PhoenixGSM.OmniTrace.Models.KnownProtocol.QualcommSahara or PhoenixGSM.OmniTrace.Models.KnownProtocol.QualcommFirehose)
        {
            endpointOrTarget = cmd.Details.TryGetValue("MemoryType", out var mt) ? $"Qualcomm 9008 ({mt})" : (!string.IsNullOrEmpty(cmd.DeviceIdentity) ? cmd.DeviceIdentity : "Qualcomm EDL (9008)");
        }
        else if (cmd.Protocol == PhoenixGSM.OmniTrace.Models.KnownProtocol.SerialAt)
        {
            if (cmd.Transport == PhoenixGSM.OmniTrace.Models.TransportType.FILE)
            {
                if (!string.IsNullOrEmpty(cmd.SessionIdentity) && cmd.SessionIdentity.StartsWith("TEMP_AT_", StringComparison.OrdinalIgnoreCase))
                {
                    endpointOrTarget = cmd.SessionIdentity["TEMP_AT_".Length..];
                }
                else
                {
                    endpointOrTarget = Path.GetFileName(cmd.DeviceIdentity);
                }
            }
            else if (!string.IsNullOrEmpty(cmd.SessionIdentity) && cmd.SessionIdentity.StartsWith("SERIAL_", StringComparison.OrdinalIgnoreCase))
            {
                endpointOrTarget = cmd.SessionIdentity["SERIAL_".Length..];
            }
            else if (!string.IsNullOrEmpty(cmd.DeviceIdentity) && cmd.DeviceIdentity.StartsWith("SERIAL\\", StringComparison.OrdinalIgnoreCase))
            {
                endpointOrTarget = cmd.DeviceIdentity["SERIAL\\".Length..];
            }
            else
            {
                endpointOrTarget = !string.IsNullOrEmpty(cmd.SessionIdentity) ? cmd.SessionIdentity : cmd.DeviceIdentity;
            }
        }
        else if (cmd.Details.TryGetValue("Caller", out var caller) && !string.IsNullOrWhiteSpace(caller))
        {
            endpointOrTarget = caller;
        }
        else
        {
            endpointOrTarget = string.IsNullOrEmpty(cmd.SessionIdentity) ? cmd.DeviceIdentity : $"{cmd.DeviceIdentity}:{cmd.SessionIdentity}";
        }

        string dir;
        if (cmd.Transport == PhoenixGSM.OmniTrace.Models.TransportType.FILE)
        {
            dir = "FILE >>";
        }
        else if (isStreamOut)
        {
            dir = ">>";
        }
        else if (isStreamIn)
        {
            dir = "<<";
        }
        else
        {
            dir = cmd.Direction == PhoenixGSM.OmniTrace.Models.PacketDirection.HOST_TO_DEVICE ? "OUT" : "IN";
        }

        string proto = cmd.Details.TryGetValue("ProtocolName", out var pName) && !string.IsNullOrWhiteSpace(pName)
            ? pName
            : (cmd.Transport == PhoenixGSM.OmniTrace.Models.TransportType.FILE
                ? "STAGED-AT"
                : ((isStreamOut || isStreamIn) ? "SUB-STREAM" : cmd.Protocol.ToString().ToUpperInvariant()));

        string summary;
        if (cmd.Details.TryGetValue("Summary", out var customSummary) && !string.IsNullOrWhiteSpace(customSummary))
        {
            summary = customSummary;
        }
        else if (cmd.Transport == PhoenixGSM.OmniTrace.Models.TransportType.FILE)
        {
            summary = $"[{cmd.Attribution?.ImageName ?? "Tool.exe"}] Staged AT: {cmd.Command}";
        }
        else if (isStreamOut || isStreamIn)
        {
            summary = $"[{sourceTag}] [{endpointOrTarget}] {cmd.Command}";
        }
        else
        {
            summary = $"[{cmd.Protocol}] {cmd.Command} ({cmd.Confidence:P0} conf)";
        }

        string payloadAscii;
        string additionalDetails;
        if (cmd.Details.TryGetValue("TechnicalDetails", out var customDetails) && !string.IsNullOrWhiteSpace(customDetails))
        {
            payloadAscii = customDetails;
            additionalDetails = customDetails;
        }
        else if (cmd.Transport == PhoenixGSM.OmniTrace.Models.TransportType.FILE)
        {
            payloadAscii = $"Staged AT Command: {cmd.Command}\nCreator: {cmd.Attribution?.ImageName ?? "Tool.exe"} (PID {cmd.Attribution?.ProcessId})\nSource File: {cmd.DeviceIdentity}\nService: {cmd.Service}\nConfidence: {cmd.Confidence:P2}\nTarget Hint: USB Modem Interface";
            additionalDetails = $"Active Target: {endpointOrTarget}\nService: {cmd.Service}\nDirection: {dir}\nTimestamp: {cmd.Timestamp:O}\nEvidence Packets: {cmd.RawEvidenceSequences.Count}\nEvidence Hashes: {string.Join(", ", cmd.EvidenceHashes)}";
        }
        else
        {
            payloadAscii = $"Command / Stream: {cmd.Command}\nTarget / Service: {cmd.Service}\nDevice: {cmd.DeviceIdentity}\nConfidence: {cmd.Confidence:P2}\nHashes: {evidenceHashes}";
            additionalDetails = $"Active Target: {endpointOrTarget}\nService: {cmd.Service}\nDirection: {dir}\nTimestamp: {cmd.Timestamp:O}\nEvidence Packets: {cmd.RawEvidenceSequences.Count}\nEvidence Hashes: {string.Join(", ", cmd.EvidenceHashes)}";
        }

        byte[] payloadBytes = cmd.Details.TryGetValue("CommandLine", out var rawCmd) && !string.IsNullOrWhiteSpace(rawCmd)
            ? Encoding.UTF8.GetBytes(rawCmd)
            : Encoding.UTF8.GetBytes(cmd.Command);

        // Check for URLs inside command-line executions
        if (cmd.Details.TryGetValue("CommandLine", out var cliText) && !string.IsNullOrWhiteSpace(cliText))
        {
            string exePath = cmd.Details.TryGetValue("ExecutablePath", out var ep) ? ep : "";
            string caller = cmd.Details.TryGetValue("Caller", out var c) ? c : "";
            CheckAndEmitUrls(cliText, exePath, caller, cmd.Timestamp.UtcDateTime);
        }

        // Apple iproxy notification
        if (cmd.Service.Equals("iproxy.exe", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                int.TryParse(cmd.Details.TryGetValue("PID", out var p) ? p : "0", out int iproxyPid);
                _omniService?.RamdiskWatcher.OnIproxyLaunched(iproxyPid, 0,
                    cmd.Details.TryGetValue("CommandLine", out var cl) ? cl : "",
                    cmd.Details.TryGetValue("Caller", out var cal) ? cal : "",
                    cmd.Details.TryGetValue("ExecutablePath", out var ep2) ? ep2 : "");
            }
            catch { }
        }

        EmitEvent(new LiveEventItem
        {
            Timestamp = cmd.Timestamp.UtcDateTime,
            Category = category,
            SourceTag = sourceTag,
            Direction = dir,
            EndpointOrTarget = endpointOrTarget,
            Protocol = proto,
            Command = cmd.Command,
            Summary = summary,
            RawPayload = payloadBytes,
            PayloadAscii = payloadAscii,
            PayloadHex = LiveEventItem.FormatHexDump(payloadBytes),
            AdditionalDetails = additionalDetails
        });
    }

    public bool SendAtCommandToPort(string portName, string command, out string error)
    {
        if (_omniService?.SerialSensor != null)
        {
            return _omniService.SerialSensor.SendAtCommandToPort(portName, command, out error);
        }
        error = "OmniTrace Serial Sensor is not running.";
        return false;
    }

    public bool SendAtCommandToAnyPort(string command, out string error)
    {
        if (_omniService?.SerialSensor != null)
        {
            return _omniService.SerialSensor.SendAtCommandToAnyPort(command, out error);
        }
        error = "OmniTrace Serial Sensor is not running.";
        return false;
    }

    public string[] GetAvailableComPorts()
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // 1. From SerialPortSensor active monitored ports
        if (_omniService?.SerialSensor != null)
        {
            foreach (var p in _omniService.SerialSensor.MonitoredPortNames)
            {
                if (!string.IsNullOrWhiteSpace(p)) result.Add(p);
            }
        }

        // 2. From Known COM ports tracked by watcher
        lock (_knownComPorts)
        {
            foreach (var p in _knownComPorts)
            {
                if (!string.IsNullOrWhiteSpace(p)) result.Add(p);
            }
        }

        // 3. From system SerialPort.GetPortNames() directly
        try
        {
            foreach (var p in System.IO.Ports.SerialPort.GetPortNames())
            {
                if (!string.IsNullOrWhiteSpace(p)) result.Add(p);
            }
        }
        catch { }

        // Sort ports prioritizing modem / cellular ports
        return result.OrderByDescending(p =>
        {
            var desc = GetPortDescription(p) ?? "";
            bool isModem = desc.Contains("modem", StringComparison.OrdinalIgnoreCase) ||
                           desc.Contains("samsung", StringComparison.OrdinalIgnoreCase) ||
                           desc.Contains("qualcomm", StringComparison.OrdinalIgnoreCase) ||
                           desc.Contains("mediatek", StringComparison.OrdinalIgnoreCase) ||
                           desc.Contains("diag", StringComparison.OrdinalIgnoreCase);
            return isModem ? 1 : 0;
        }).ThenBy(p => p).ToArray();
    }

    public string? GetPortDescription(string portName)
    {
        if (_omniService?.SerialSensor != null)
        {
            var desc = _omniService.SerialSensor.GetPortDescription(portName);
            if (!string.IsNullOrEmpty(desc)) return desc;
        }
        return null;
    }

    // Granular Sensor Capture Flags (تشغيل/إيقاف كل مجس على حدة)
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

    private void HandleNetworkUrlCaptured(PhoenixGSM.OmniTrace.Sensors.CapturedUrlInfo urlInfo)
    {
        if (!IsUrlMonitoringEnabled) return;

        bool isDns = urlInfo.SourceTag.Equals("DNS-QUERY", StringComparison.OrdinalIgnoreCase);
        bool isClipboard = urlInfo.SourceTag.Equals("CLIPBOARD", StringComparison.OrdinalIgnoreCase);
        bool isConn = urlInfo.SourceTag.Equals("NET-CONN", StringComparison.OrdinalIgnoreCase);
        bool isRawHttp = urlInfo.SourceTag.Equals("RAW-HTTP", StringComparison.OrdinalIgnoreCase);
        bool isTlsSni = urlInfo.SourceTag.Equals("TLS-SNI", StringComparison.OrdinalIgnoreCase);

        string fileName = Path.GetFileName(urlInfo.PathAndQuery.Split('?')[0]);
        string cmd;
        string summary;
        string dir;

        if (isDns)
        {
            cmd = "DNS LOOKUP";
            summary = $"[{urlInfo.ProcessName}] DNS: {urlInfo.Host}";
            dir = "DNS";
        }
        else if (isClipboard)
        {
            cmd = string.IsNullOrWhiteSpace(fileName) ? "COPIED LINK" : $"LINK: {fileName}";
            summary = $"[{urlInfo.ProcessName}] {urlInfo.Url}";
            dir = "CLIP";
        }
        else if (isRawHttp)
        {
            cmd = $"{urlInfo.Method} (HTTP)";
            summary = $"[{urlInfo.ProcessName}] {urlInfo.Method} {urlInfo.Url}";
            dir = "HTTP >>";
        }
        else if (isTlsSni)
        {
            cmd = "HTTPS (TLS)";
            summary = $"[{urlInfo.ProcessName}] HTTPS Handshake -> {urlInfo.Host}";
            dir = "TLS >>";
        }
        else if (isConn)
        {
            cmd = $"{urlInfo.Method} {urlInfo.RemotePort}";
            summary = $"[{urlInfo.ProcessName}] Connect -> {urlInfo.Host}:{urlInfo.RemotePort} ({urlInfo.Scheme})";
            dir = "NET >>";
        }
        else
        {
            cmd = string.IsNullOrWhiteSpace(fileName) ? $"{urlInfo.Method} REQ" : $"DOWNLOAD: {fileName}";
            summary = $"[{urlInfo.ProcessName}] {urlInfo.Method} {urlInfo.Url}";
            dir = "WEB >>";
        }

        string target = !string.IsNullOrEmpty(urlInfo.RemoteEndpoint) ? urlInfo.RemoteEndpoint : urlInfo.Host;

        EmitEvent(new LiveEventItem
        {
            Timestamp = urlInfo.Timestamp,
            Category = EventSourceCategory.NetworkUrl,
            SourceTag = urlInfo.SourceTag,
            Direction = dir,
            EndpointOrTarget = target,
            Protocol = isDns ? "DNS" : urlInfo.Scheme,
            Command = cmd,
            Summary = summary,
            RawPayload = Encoding.UTF8.GetBytes(urlInfo.Url),
            PayloadAscii = $"Captured Network / Connection Event:\nURL: {urlInfo.Url}\nTarget Host: {urlInfo.Host}\nResource Path: {urlInfo.PathAndQuery}\nCaller Process: {urlInfo.ProcessName} (PID {urlInfo.ProcessId})\nMethod / Action: {urlInfo.Method}\nLayer Source: {urlInfo.SourceTag}\nRemote Endpoint: {target}\nTimestamp: {urlInfo.Timestamp:O}",
            PayloadHex = LiveEventItem.FormatHexDump(Encoding.UTF8.GetBytes(urlInfo.Url)),
            AdditionalDetails = $"Captured Network / Connection Event:\nCaller Process: {urlInfo.ProcessName} (PID {urlInfo.ProcessId})\nFull URL / Target: {urlInfo.Url}\nTarget Host: {urlInfo.Host}\nResource: {urlInfo.PathAndQuery}\nInterception Layer: ({urlInfo.SourceTag})\nRemote Endpoint: {target}"
        });
    }

    private void HandleTempFileAtCaptured(PhoenixGSM.OmniTrace.Sensors.TempFileAtEvent fileAt)
    {
        if (!IsTempAtMonitoringEnabled) return;
        string cmdPreview = fileAt.AtCommands.Count > 0 
            ? fileAt.AtCommands[0] 
            : (fileAt.IsBinaryPayload ? $"[STAGED-PAYLOAD: {fileAt.FileName}]" : "AT SCRIPT");
        if (fileAt.AtCommands.Count > 1)
        {
            cmdPreview += $" (+{fileAt.AtCommands.Count - 1} more)";
        }

        string summary = fileAt.IsBinaryPayload
            ? $"[{fileAt.ProcessName}] Staged payload: {fileAt.FileName} ({fileAt.FileSize:N0}B) -> {fileAt.TargetHint}"
            : $"[{fileAt.ProcessName}] Staged {fileAt.AtCommands.Count} AT cmd(s) in {fileAt.FileName} -> {fileAt.TargetHint}";

        var sb = new StringBuilder();
        sb.AppendLine($"Staged File: {fileAt.FilePath}");
        sb.AppendLine($"Size: {fileAt.FileSize:N0} bytes");
        sb.AppendLine($"Creator Process: {fileAt.ProcessName} (PID: {fileAt.ProcessId})");
        sb.AppendLine($"Target Interface: {fileAt.TargetHint}");
        if (fileAt.AtCommands.Count > 0)
        {
            sb.AppendLine($"Extracted Commands / Signatures ({fileAt.AtCommands.Count}):");
            for (int i = 0; i < fileAt.AtCommands.Count; i++)
            {
                sb.AppendLine($"  [{i + 1}] {fileAt.AtCommands[i]}");
            }
        }
        if (!string.IsNullOrWhiteSpace(fileAt.RawContent) && !fileAt.IsBinaryPayload)
        {
            sb.AppendLine();
            sb.AppendLine("=== Full Staged File Content (Un-truncated) ===");
            sb.AppendLine(fileAt.RawContent);
        }
        else if (fileAt.IsBinaryPayload)
        {
            if (!string.IsNullOrWhiteSpace(fileAt.RawContent))
            {
                sb.AppendLine();
                sb.AppendLine("=== Staged Binary Metadata ===");
                sb.AppendLine(fileAt.RawContent);
            }

            if (fileAt.RawBytes != null && fileAt.RawBytes.Length > 0)
            {
                var carvedStrings = PhoenixGSM.OmniTrace.Sensors.TempFileAtSensor.ExtractPrintableStrings(fileAt.RawBytes);
                if (carvedStrings.Count > 0)
                {
                    sb.AppendLine();
                    sb.AppendLine($"=== Extracted Printable Strings & Script Fragments ({carvedStrings.Count:N0} strings found) ===");
                    for (int i = 0; i < carvedStrings.Count; i++)
                    {
                        sb.AppendLine($"  [{i + 1}] {carvedStrings[i]}");
                    }
                }
            }
        }

        EmitEvent(new LiveEventItem
        {
            Timestamp = fileAt.Timestamp,
            Category = EventSourceCategory.TempFileAt,
            SourceTag = fileAt.SourceTag,
            Direction = "FILE >>",
            EndpointOrTarget = fileAt.FileName,
            Protocol = fileAt.IsBinaryPayload ? "STAGED-PAYLOAD" : "STAGED-AT",
            Command = cmdPreview,
            Summary = summary,
            RawPayload = fileAt.RawBytes,
            PayloadAscii = sb.ToString(),
            PayloadHex = LiveEventItem.FormatHexDump(fileAt.RawBytes),
            AdditionalDetails = $"Captured Staged Temp File:\nCreator: {fileAt.ProcessName} (PID {fileAt.ProcessId})\nPath: {fileAt.FilePath}\nCommands Extracted: {fileAt.AtCommands.Count}\nInterception Layer: Filesystem / Temp Interceptor (Layer 3E)\nDestination: {fileAt.TargetHint}\nBinary Payload: {fileAt.IsBinaryPayload}"
        });
    }

    private void HandleInProcessCaptured(PhoenixGSM.OmniTrace.Sensors.InProcessOperationEvent inProc)
    {
        var sb = new StringBuilder();
        sb.AppendLine("In-Process GSM Tool Servicing Operation:");
        sb.AppendLine($"Tool: {inProc.ToolName} (PID {inProc.ProcessId})");
        sb.AppendLine($"Operation: {inProc.OperationName}");
        sb.AppendLine($"Target Device: {inProc.TargetDevice}");
        sb.AppendLine($"Payload Size: {inProc.Payload.Length} bytes");
        if (inProc.Details != null && inProc.Details.Count > 0)
        {
            sb.AppendLine("Details:");
            foreach (var kvp in inProc.Details)
            {
                sb.AppendLine($"  {kvp.Key}: {kvp.Value}");
            }
        }

        EmitEvent(new LiveEventItem
        {
            Timestamp = inProc.Timestamp,
            Category = EventSourceCategory.InProcess,
            SourceTag = inProc.SourceTag,
            Direction = "INTERNAL",
            EndpointOrTarget = inProc.TargetDevice,
            Protocol = "IN-PROCESS",
            Command = inProc.OperationName,
            Summary = $"[{inProc.ToolName}] {inProc.OperationName} -> {inProc.TargetDevice}",
            RawPayload = inProc.Payload,
            PayloadAscii = sb.ToString(),
            PayloadHex = LiveEventItem.FormatHexDump(inProc.Payload),
            AdditionalDetails = sb.ToString()
        });
    }

    private void HandleToolSessionCaptured(PhoenixGSM.OmniTrace.Sensors.GsmToolSessionEvent toolEvt)
    {
        var category = Enum.TryParse<EventSourceCategory>(toolEvt.Category, true, out var cat) ? cat : EventSourceCategory.MediaTek;
        byte[] payloadBytes = Encoding.UTF8.GetBytes(toolEvt.TechnicalDetails);

        EmitEvent(new LiveEventItem
        {
            Timestamp = toolEvt.Timestamp,
            Category = category,
            SourceTag = toolEvt.SourceTag,
            Direction = "HOST->DEV",
            EndpointOrTarget = toolEvt.TargetDevice,
            Protocol = toolEvt.Protocol.ToString().ToUpperInvariant(),
            Command = toolEvt.OperationName,
            Summary = toolEvt.FormattedSummary,
            RawPayload = payloadBytes,
            PayloadAscii = toolEvt.TechnicalDetails,
            PayloadHex = LiveEventItem.FormatHexDump(payloadBytes),
            AdditionalDetails = toolEvt.TechnicalDetails
        });
    }

    private void HandleOmniRaw(PhoenixGSM.OmniTrace.Models.RawCaptureEvent raw)
    {
        if (raw.Sensor == PhoenixGSM.OmniTrace.Models.SensorType.VirtualProxy) return;
        if (raw.Metadata != null && raw.Metadata.TryGetValue("Source", out var src) && src == "KernelDriver") return;
        if (raw.Sensor == PhoenixGSM.OmniTrace.Models.SensorType.USB) return;
        if (raw.Sensor == PhoenixGSM.OmniTrace.Models.SensorType.Network) return; // Handled with richer metadata via HandleNetworkUrlCaptured
        if (raw.Sensor == PhoenixGSM.OmniTrace.Models.SensorType.FileSystem) return; // Handled with richer metadata via HandleTempFileAtCaptured
        if (raw.Direction == PhoenixGSM.OmniTrace.Models.PacketDirection.INTERNAL) return; // Handled via HandleInProcessCaptured
        if (raw.Metadata != null && raw.Metadata.TryGetValue("ExecutionType", out var execType) && execType == "InProcessDirect") return;

        // Discard 0-byte transfer tokens that flood the UI with empty polling noise
        if (raw.RawPayload == null || raw.RawPayload.Length == 0) return;

        var category = raw.Sensor switch
        {
            PhoenixGSM.OmniTrace.Models.SensorType.Serial => EventSourceCategory.SerialPort,
            PhoenixGSM.OmniTrace.Models.SensorType.Process => EventSourceCategory.Process,
            PhoenixGSM.OmniTrace.Models.SensorType.VirtualProxy => EventSourceCategory.AdbProxy,
            PhoenixGSM.OmniTrace.Models.SensorType.FileSystem => EventSourceCategory.TempFileAt,
            _ => EventSourceCategory.UsbDriver
        };

        string dir = raw.Direction == PhoenixGSM.OmniTrace.Models.PacketDirection.HOST_TO_DEVICE ? "OUT" : "IN";
        string target;
        if (raw.Sensor == PhoenixGSM.OmniTrace.Models.SensorType.Serial)
        {
            target = !string.IsNullOrEmpty(raw.Endpoint) ? raw.Endpoint : raw.DeviceIdentity;
        }
        else
        {
            target = string.IsNullOrEmpty(raw.DeviceIdentity) || raw.DeviceIdentity.Equals("USB_UNKNOWN", StringComparison.OrdinalIgnoreCase)
                ? (raw.Metadata != null && raw.Metadata.TryGetValue("ProcessName", out var proc) ? $"{proc}:{raw.Endpoint}" : $"USB:{raw.Endpoint}")
                : $"{raw.DeviceIdentity}:{raw.Endpoint}";
        }

        EmitEvent(new LiveEventItem
        {
            Category = category,
            SourceTag = $"OMNI-{raw.Sensor}",
            Direction = dir,
            EndpointOrTarget = target,
            Protocol = raw.Transport.ToString().ToUpperInvariant(),
            Command = $"RAW #{raw.SequenceNumber}",
            Summary = $"{raw.Sensor} transfer ({raw.Length}B, SHA: {(raw.PayloadHash.Length > 8 ? raw.PayloadHash[..8] : raw.PayloadHash)})",
            RawPayload = raw.RawPayload,
            PayloadAscii = Encoding.UTF8.GetString(raw.RawPayload),
            PayloadHex = LiveEventItem.FormatHexDump(raw.RawPayload),
            AdditionalDetails = $"Sensor: {raw.Sensor}\nTransport: {raw.Transport}\nHash: {raw.PayloadHash}\nSession: {raw.SessionIdentity}"
        });
    }

    private void HandleArtifactCaptured(PhoenixGSM.OmniTrace.Models.PushedArtifactInfo artifact)
    {
        if (!IsArtifactVaultEnabled) return;
        var sb = new StringBuilder();
        sb.AppendLine("Pushed Artifact Intercepted & Retained in Vault:");
        sb.AppendLine($"File Name: {artifact.FileName}");
        sb.AppendLine($"Classification: {artifact.FileClassification} ({artifact.MagicDescription})");
        sb.AppendLine($"Target Device Path: {artifact.TargetDevicePath}");
        if (!string.IsNullOrEmpty(artifact.LocalSourcePath))
        {
            sb.AppendLine($"Host Source Path: {artifact.LocalSourcePath}");
        }
        sb.AppendLine($"File Size: {artifact.FileSizeBytes:N0} bytes");
        sb.AppendLine($"SHA-256: {artifact.Sha256}");
        sb.AppendLine($"MD5: {artifact.Md5}");
        sb.AppendLine($"Vault Storage: {artifact.VaultFilePath}");
        sb.AppendLine($"Vault Manifest: {artifact.VaultManifestPath}");
        sb.AppendLine($"Is Exploit/Executable: {artifact.IsExecutableOrExploit}");
        sb.AppendLine($"Deduplicated: {artifact.IsDeduplicated}");
        sb.AppendLine($"Capture Vector: {artifact.SourceVector}");
        sb.AppendLine($"Attributed Tool: {artifact.ProcessName} (PID {artifact.ProcessId})");
        if (artifact.Attributes.Count > 0)
        {
            sb.AppendLine("Metadata Attributes:");
            foreach (var kvp in artifact.Attributes)
            {
                sb.AppendLine($"  {kvp.Key}: {kvp.Value}");
            }
        }

        // Retrieve actual file bytes for zero-loss content & strings inspection
        byte[]? fileBytes = artifact.RawBytes;
        if (fileBytes == null || fileBytes.Length == 0)
        {
            try
            {
                if (File.Exists(artifact.VaultFilePath))
                {
                    fileBytes = File.ReadAllBytes(artifact.VaultFilePath);
                }
                else if (!string.IsNullOrEmpty(artifact.LocalSourcePath) && File.Exists(artifact.LocalSourcePath))
                {
                    fileBytes = File.ReadAllBytes(artifact.LocalSourcePath);
                }
            }
            catch { }
        }

        if (fileBytes != null && fileBytes.Length > 0)
        {
            bool isBinary = PhoenixGSM.OmniTrace.Sensors.TempFileAtSensor.IsBinaryBuffer(fileBytes);
            if (!isBinary)
            {
                string text = PhoenixGSM.OmniTrace.Sensors.TempFileAtSensor.DecodeText(fileBytes);
                sb.AppendLine();
                sb.AppendLine("=== Full Staged File Content (Un-truncated) ===");
                sb.AppendLine(text);
            }
            else
            {
                var carvedStrings = PhoenixGSM.OmniTrace.Sensors.TempFileAtSensor.ExtractPrintableStrings(fileBytes);
                if (carvedStrings.Count > 0)
                {
                    sb.AppendLine();
                    sb.AppendLine($"=== Extracted Printable Strings & Script Fragments ({carvedStrings.Count:N0} strings found) ===");
                    for (int i = 0; i < carvedStrings.Count; i++)
                    {
                        sb.AppendLine($"  [{i + 1}] {carvedStrings[i]}");
                    }
                }
            }
        }

        string sizeStr = artifact.FileSizeBytes < 1024
            ? $"{artifact.FileSizeBytes} B"
            : (artifact.FileSizeBytes < 1048576
                ? $"{artifact.FileSizeBytes / 1024.0:F1} KB"
                : $"{artifact.FileSizeBytes / 1048576.0:F2} MB");

        string cmdPreview = $"VAULT-SAVE {artifact.FileName}";
        string summary = $"[ARTIFACT VAULT] {artifact.FileName} ({sizeStr}) -> {artifact.TargetDevicePath} [{artifact.MagicDescription}]";

        byte[] payloadBytes = fileBytes ?? Encoding.UTF8.GetBytes(sb.ToString());

        EmitEvent(new LiveEventItem
        {
            Timestamp = artifact.Timestamp,
            Category = EventSourceCategory.ArtifactVault,
            SourceTag = "ARTIFACT-VAULT",
            Direction = "PUSH >>",
            EndpointOrTarget = artifact.TargetDevicePath,
            Protocol = "VAULT-ADB",
            Command = cmdPreview,
            Summary = summary,
            RawPayload = payloadBytes,
            PayloadAscii = sb.ToString(),
            PayloadHex = LiveEventItem.FormatHexDump(payloadBytes),
            AdditionalDetails = sb.ToString()
        });
    }

    public void Dispose()
    {
        Stop();
    }
}
