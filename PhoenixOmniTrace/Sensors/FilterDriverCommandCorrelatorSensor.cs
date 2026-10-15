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
using PhoenixGSM.OmniTrace.Bus;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.Sensors;

/// <summary>
/// LAYER 21 — Filter Driver Command & Chipset Correlator Sensor.
/// When GSM tools (UnlockTool, etc.) execute low-level filter driver modifiers (filter-x64.exe, filter-x86.exe, devcon.exe),
/// this layer correlates the driver target (e.g. USB\VID_0E8D&PID_0003) with the calling tool's UI context
/// and immediately emits the corresponding native Service Execution event (MediaTek, Qualcomm, etc.)
/// matching the exact uniform format of Apple iOS service commands.
/// </summary>
public sealed class FilterDriverCommandCorrelatorSensor : IDisposable
{
    private readonly OmniTraceEventBus _bus;
    private readonly GsmToolUiActionSensor? _uiSensor;
    private bool _isRunning;
    private ulong _sequence;

    // Observability metrics
    private long _correlatedEvents;
    public long CorrelatedEvents => Interlocked.Read(ref _correlatedEvents);
    public bool IsRunning => _isRunning;

    // Deduplication cache: Key = "PID_DevTarget", Value = Timestamp
    private readonly ConcurrentDictionary<string, DateTime> _debounceCache = new(StringComparer.OrdinalIgnoreCase);

    public FilterDriverCommandCorrelatorSensor(OmniTraceEventBus bus, GsmToolUiActionSensor? uiSensor = null)
    {
        _bus = bus ?? throw new ArgumentNullException(nameof(bus));
        _uiSensor = uiSensor;
    }

    public void Start()
    {
        if (_isRunning) return;
        _isRunning = true;

        // Subscribes to logical commands to observe filter driver executions
        _bus.OnLogicalCommand += HandleLogicalCommand;
    }

    public void Stop()
    {
        if (!_isRunning) return;
        _isRunning = false;

        _bus.OnLogicalCommand -= HandleLogicalCommand;
        _debounceCache.Clear();
    }

    private void HandleLogicalCommand(LogicalCommandEvent cmd)
    {
        if (!_isRunning) return;

        // Only react to filter driver installations/modifications
        bool isFilterDriver = cmd.Service.Contains("filter-", StringComparison.OrdinalIgnoreCase) ||
                              cmd.Command.Contains("FILTER", StringComparison.OrdinalIgnoreCase) ||
                              cmd.Details.TryGetValue("TechnicalDetails", out var techDetails) && techDetails.Contains("Kernel Filter Driver Modification", StringComparison.OrdinalIgnoreCase);

        if (!isFilterDriver) return;

        // Extract target device hardware ID
        string devTarget = cmd.DeviceIdentity;
        if (string.IsNullOrWhiteSpace(devTarget) || devTarget.Equals("UNKNOWN", StringComparison.OrdinalIgnoreCase))
        {
            if (cmd.Details.TryGetValue("DeviceTarget", out var dt) && !string.IsNullOrWhiteSpace(dt))
            {
                devTarget = dt;
            }
            else if (cmd.Details.TryGetValue("TargetOrEndpoint", out var toe) && !string.IsNullOrWhiteSpace(toe))
            {
                devTarget = toe;
            }
        }

        // Extract caller process information
        int callerPid = cmd.Attribution?.ProcessId ?? 0;
        string callerName = cmd.Attribution?.ImageName ?? "UnlockTool-2026-09-23-0.exe";
        string callerPath = string.Empty;

        if (callerPid == 0 && cmd.Details.TryGetValue("Caller", out var callerStr))
        {
            var match = Regex.Match(callerStr, @"PID\s*(\d+)", RegexOptions.IgnoreCase);
            if (match.Success && int.TryParse(match.Groups[1].Value, out int parsedPid) && parsedPid > 0)
            {
                callerPid = parsedPid;
            }
        }

        // If callerPid was 0 or unassigned, resolve active UnlockTool or GSM tool PID
        if (callerPid <= 0)
        {
            try
            {
                var procs = Process.GetProcessesByName("UnlockTool-2026-09-23-0")
                    .Concat(Process.GetProcessesByName("UnlockTool"))
                    .ToArray();
                if (procs.Length > 0)
                {
                    callerPid = procs[0].Id;
                    callerName = $"{procs[0].ProcessName}.exe";
                    try { callerPath = procs[0].MainModule?.FileName ?? string.Empty; } catch { }
                }
            }
            catch { }
        }

        if (string.IsNullOrWhiteSpace(callerPath) && callerPid > 0)
        {
            try
            {
                callerPath = Process.GetProcessById(callerPid).MainModule?.FileName ?? string.Empty;
            }
            catch { }
        }

        CorrelateFilterWithServiceExecution(callerPid, callerName, callerPath, devTarget, cmd);
    }

    public void CorrelateFilterWithServiceExecution(int callerPid, string callerName, string callerPath, string devTarget, LogicalCommandEvent triggerEvt)
    {
        string debounceKey = $"{callerPid}_{devTarget}";
        if (_debounceCache.TryGetValue(debounceKey, out var lastTime))
        {
            if (DateTime.UtcNow - lastTime < TimeSpan.FromSeconds(2.0))
            {
                return; // Suppress duplicate events within 2 seconds
            }
        }
        _debounceCache[debounceKey] = DateTime.UtcNow;

        // Query active UI state if available
        var uiState = _uiSensor?.GetActiveToolState(callerPid);
        string actionName = uiState?.LastAction ?? string.Empty;
        string activeModel = uiState?.ActiveModel ?? string.Empty;
        string activeTab = uiState?.ActiveTab ?? string.Empty;

        // If UI state didn't have an action, infer from hardware target
        bool isMtk = devTarget.Contains("0E8D", StringComparison.OrdinalIgnoreCase);
        bool isQcom = devTarget.Contains("05C6", StringComparison.OrdinalIgnoreCase) || devTarget.Contains("9008", StringComparison.OrdinalIgnoreCase);
        bool isSpd = devTarget.Contains("1782", StringComparison.OrdinalIgnoreCase);

        string serviceBanner;
        string category;
        KnownProtocol protocol;

        if (isMtk)
        {
            serviceBanner = "MediaTek Service Execution";
            category = "MediaTek";
            protocol = KnownProtocol.MtkBrom;
            if (string.IsNullOrWhiteSpace(actionName)) actionName = "[BROM] FACTORY RESET / ERASE FRP";
            if (string.IsNullOrWhiteSpace(devTarget) || devTarget.Equals("UNKNOWN")) devTarget = "USB\\VID_0E8D&PID_0003";
        }
        else if (isQcom)
        {
            serviceBanner = "Qualcomm EDL Service Execution";
            category = "QualcommEdl";
            protocol = KnownProtocol.QualcommSahara;
            if (string.IsNullOrWhiteSpace(actionName)) actionName = "[EDL] FACTORY RESET";
            if (string.IsNullOrWhiteSpace(devTarget) || devTarget.Equals("UNKNOWN")) devTarget = "USB\\VID_05C6&PID_9008";
        }
        else if (isSpd)
        {
            serviceBanner = "Unisoc/Spreadtrum Service Execution";
            category = "UnisocSpd";
            protocol = KnownProtocol.SpreadtrumFdl;
            if (string.IsNullOrWhiteSpace(actionName)) actionName = "[SPRD] FACTORY RESET";
            if (string.IsNullOrWhiteSpace(devTarget) || devTarget.Equals("UNKNOWN")) devTarget = "USB\\VID_1782&PID_4D00";
        }
        else
        {
            serviceBanner = "Hardware Servicing Execution";
            category = "DeviceServicing";
            protocol = KnownProtocol.HostCommand;
            if (string.IsNullOrWhiteSpace(actionName)) actionName = "SERVICE OPERATION";
        }

        ulong seq = Interlocked.Increment(ref _sequence);
        Interlocked.Increment(ref _correlatedEvents);

        string caller = $"{callerName} (PID {callerPid})";
        string formattedSummary = $"[{callerName}] {actionName} -> {devTarget}";

        var technicalDetails = new StringBuilder();
        technicalDetails.AppendLine(serviceBanner);
        technicalDetails.AppendLine($"Binary: {callerPath}");
        technicalDetails.AppendLine($"Action: {actionName}");
        if (!string.IsNullOrWhiteSpace(activeModel)) technicalDetails.AppendLine($"Model Target: {activeModel}");
        if (!string.IsNullOrWhiteSpace(activeTab)) technicalDetails.AppendLine($"Active Tab: {activeTab}");
        technicalDetails.AppendLine($"Device Target: {devTarget}");
        technicalDetails.AppendLine($"Driver Action: filter-x64.exe INSTALL Filter {devTarget}");
        technicalDetails.AppendLine("Status: Waiting for device connection...");
        technicalDetails.Append($"Caller: {caller}");

        byte[] payloadBytes = Encoding.UTF8.GetBytes(technicalDetails.ToString());
        var rawEvt = RawCaptureEvent.Create(
            sequence: seq,
            sensor: SensorType.Process,
            transport: TransportType.BULK,
            direction: PacketDirection.HOST_TO_DEVICE,
            device: devTarget,
            session: $"{callerName}_{callerPid}_{actionName}",
            iface: 0,
            endpoint: "FILTER_CORRELATED_ACTION",
            payload: payloadBytes,
            timestampSource: "FilterDriverCommandCorrelatorSensor"
        );

        rawEvt.Metadata["ToolName"] = callerName;
        rawEvt.Metadata["ProcessId"] = callerPid.ToString();
        rawEvt.Metadata["Action"] = actionName;
        rawEvt.Metadata["TargetDevice"] = devTarget;
        rawEvt.Metadata["SourceTag"] = "TOOL-CMD";
        rawEvt.Metadata["Category"] = category;
        rawEvt.Metadata["TechnicalDetails"] = technicalDetails.ToString();

        _bus.Publish(rawEvt);

        var cmd = _bus.Correlation.Correlate(
            actionName,
            protocol,
            callerName,
            TransportType.BULK,
            devTarget,
            $"{callerName}_{callerPid}_{actionName}_FILTER",
            PacketDirection.HOST_TO_DEVICE,
            [rawEvt.SequenceNumber],
            [rawEvt.PayloadHash],
            confidence: 1.0,
            suspectedPid: callerPid,
            suspectedToolName: callerName
        );

        cmd.Details["Category"] = category;
        cmd.Details["SourceTag"] = "TOOL-CMD";
        cmd.Details["Summary"] = formattedSummary;
        cmd.Details["TechnicalDetails"] = technicalDetails.ToString();
        cmd.Details["Action"] = actionName;
        cmd.Details["DriverAction"] = $"filter-x64.exe INSTALL Filter {devTarget}";
        cmd.Details["DeviceTarget"] = devTarget;
        cmd.Details["Caller"] = caller;
        cmd.Details["ExecutablePath"] = callerPath;
        cmd.Attribution.ProcessId = callerPid;
        cmd.Attribution.ImageName = callerName;

        _bus.ReportLogicalCommand(cmd);
    }

    public void Dispose()
    {
        Stop();
    }
}
