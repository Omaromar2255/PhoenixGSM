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
/// Event model for live GSM tool session operations (UnlockTool, etc.)
/// </summary>
public sealed class GsmToolSessionEvent
{
    public string ToolName { get; set; } = string.Empty;
    public string ExecutablePath { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public string OperationName { get; set; } = string.Empty;
    public string Stage { get; set; } = string.Empty;
    public string TargetDevice { get; set; } = string.Empty;
    public string PortOrEndpoint { get; set; } = string.Empty;
    public string ChipsetOrHardware { get; set; } = string.Empty;
    public string RawLogText { get; set; } = string.Empty;
    public string FormattedSummary { get; set; } = string.Empty;
    public string TechnicalDetails { get; set; } = string.Empty;
    public string Category { get; set; } = "MediaTek";
    public KnownProtocol Protocol { get; set; } = KnownProtocol.MtkBrom;
    public string SourceTag { get; set; } = "TOOL-LIVE";
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// LAYER 20 — GSM Tool Live Execution & Session Stream Sensor
/// Captures commands directly from GSM servicing tools (UnlockTool, Chimera, etc.)
/// in real time, EVEN BEFORE physical device connection (e.g. while scanning or waiting for BROM),
/// and throughout the complete handshake, auth bypass, DA boot, FRP, and flashing stages.
/// Matches the exact style of process execution interception without relying on child CLI binaries.
/// </summary>
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public sealed class GsmToolSessionStreamSensor : IDisposable
{
    private readonly OmniTraceEventBus _bus;
    private readonly ConcurrentDictionary<string, long> _fileOffsets = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DateTime> _seenActionDeduplication = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<FileSystemWatcher> _watchers = [];
    private CancellationTokenSource? _cts;
    private Task? _pollingTask;
    private bool _isRunning;
    private ulong _sequence;

    // Observability metrics
    private long _sessionsCaptured;
    private long _eventsEmitted;

    public bool IsRunning => _isRunning;
    public long SessionsCaptured => Interlocked.Read(ref _sessionsCaptured);
    public long EventsEmitted => Interlocked.Read(ref _eventsEmitted);

    public event Action<GsmToolSessionEvent>? OnToolSessionCaptured;

    public GsmToolSessionStreamSensor(OmniTraceEventBus bus)
    {
        _bus = bus ?? throw new ArgumentNullException(nameof(bus));
    }

    private DateTime _sensorStartTimeUtc = DateTime.UtcNow;

    public void Start()
    {
        if (_isRunning) return;
        _isRunning = true;
        _sensorStartTimeUtc = DateTime.UtcNow.AddSeconds(-2);
        _cts = new CancellationTokenSource();

        InitializeWatchers();
        _pollingTask = Task.Run(() => PollingLoop(_cts.Token), _cts.Token);
    }

    public void Stop()
    {
        if (!_isRunning) return;
        _isRunning = false;
        _cts?.Cancel();

        foreach (var watcher in _watchers)
        {
            try
            {
                watcher.EnableRaisingEvents = false;
                watcher.Dispose();
            }
            catch { }
        }
        _watchers.Clear();
        _fileOffsets.Clear();
    }

    private void InitializeWatchers()
    {
        // 1. Target primary GSM tool log roots
        var candidateRoots = new List<string>();

        // Standard UnlockTool log path
        if (Directory.Exists(@"C:\UnlockTool\Logs"))
        {
            candidateRoots.Add(@"C:\UnlockTool\Logs");
        }

        // Search any drive or user documents for UnlockTool roots
        string docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        string userUnlockTool = Path.Combine(docs, "UnlockTool");
        if (Directory.Exists(userUnlockTool))
        {
            candidateRoots.Add(userUnlockTool);
        }

        foreach (var root in candidateRoots.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                var watcher = new FileSystemWatcher(root)
                {
                    IncludeSubdirectories = true,
                    Filter = "*.*",
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size
                };

                watcher.Created += (s, e) => ProcessLogFile(e.FullPath);
                watcher.Changed += (s, e) => ProcessLogFile(e.FullPath);
                watcher.EnableRaisingEvents = true;
                _watchers.Add(watcher);
            }
            catch { }
        }
    }

    private async Task PollingLoop(CancellationToken token)
    {
        // Initial scan of today's latest files
        ScanActiveLogDirectories();

        while (!token.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(500, token);
                ScanActiveLogDirectories();
            }
            catch (OperationCanceledException) { break; }
            catch { await Task.Delay(1000, token); }
        }
    }

    private void ScanActiveLogDirectories()
    {
        try
        {
            if (Directory.Exists(@"C:\UnlockTool\Logs"))
            {
                var todayDirs = Directory.GetDirectories(@"C:\UnlockTool\Logs");
                foreach (var dir in todayDirs)
                {
                    var files = Directory.GetFiles(dir, "*.htm");
                    foreach (var f in files)
                    {
                        ProcessLogFile(f);
                    }
                }
            }
        }
        catch { }
    }

    public void ProcessLogFile(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath)) return;
        if (!filePath.EndsWith(".htm", StringComparison.OrdinalIgnoreCase) &&
            !filePath.EndsWith(".log", StringComparison.OrdinalIgnoreCase) &&
            !filePath.EndsWith(".txt", StringComparison.OrdinalIgnoreCase)) return;

        try
        {
            var fileInfo = new FileInfo(filePath);
            if (fileInfo.LastWriteTimeUtc < _sensorStartTimeUtc) return;

            long lastOffset = _fileOffsets.GetOrAdd(filePath, 0);
            if (fileInfo.Length <= lastOffset && lastOffset > 0) return;

            string newContent;
            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                if (fs.Length <= lastOffset && lastOffset > 0) return;
                fs.Seek(lastOffset, SeekOrigin.Begin);
                using (var reader = new StreamReader(fs, Encoding.UTF8))
                {
                    newContent = reader.ReadToEnd();
                }
                _fileOffsets[filePath] = fs.Position;
            }

            if (string.IsNullOrWhiteSpace(newContent)) return;

            ParseAndDispatchSessionContent(filePath, newContent);
        }
        catch { }
    }

    private void ParseAndDispatchSessionContent(string filePath, string content)
    {
        // Strip HTML tags for clean text extraction
        string cleanText = Regex.Replace(content, @"<[^>]+>", "\n");
        string[] lines = cleanText.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
                                  .Select(l => l.Trim())
                                  .Where(l => !string.IsNullOrWhiteSpace(l))
                                  .ToArray();

        if (lines.Length == 0) return;

        // Resolve active caller process (UnlockTool of any version date)
        string callerName = "UnlockTool.exe";
        string callerPath = @"C:\UnlockTool\UnlockTool.exe";
        int callerPid = 0;

        try
        {
            var unlockProcs = Process.GetProcesses()
                .Where(p => p.ProcessName.StartsWith("UnlockTool", StringComparison.OrdinalIgnoreCase))
                .ToArray();

            if (unlockProcs.Length > 0)
            {
                callerPid = unlockProcs[0].Id;
                callerName = $"{unlockProcs[0].ProcessName}.exe";
                try { callerPath = unlockProcs[0].MainModule?.FileName ?? callerPath; } catch { }
            }
            foreach (var p in unlockProcs) p.Dispose();
        }
        catch { }

        // Extract Operation Title from file name or header
        string opName = Path.GetFileNameWithoutExtension(filePath);
        var matchDate = Regex.Match(opName, @"\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}_(.*)");
        if (matchDate.Success)
        {
            opName = matchDate.Groups[1].Value.Trim();
        }

        // Categorize protocol and service
        string category = "MediaTek";
        KnownProtocol protocol = KnownProtocol.MtkBrom;
        string serviceBanner = "MediaTek Service Execution";

        if (opName.Contains("BOOT DEVICE", StringComparison.OrdinalIgnoreCase) ||
            cleanText.Contains("BOOTROM", StringComparison.OrdinalIgnoreCase) ||
            cleanText.Contains("0E8D:0003", StringComparison.OrdinalIgnoreCase) ||
            cleanText.Contains("MT6", StringComparison.OrdinalIgnoreCase) ||
            cleanText.Contains("MT8", StringComparison.OrdinalIgnoreCase))
        {
            category = "MediaTek";
            protocol = KnownProtocol.MtkBrom;
            serviceBanner = "MediaTek BROM Service Execution";
        }
        else if (opName.Contains("ODIN", StringComparison.OrdinalIgnoreCase) ||
                 opName.Contains("DOWNLOAD", StringComparison.OrdinalIgnoreCase))
        {
            category = "Samsung";
            protocol = KnownProtocol.SamsungOdin;
            serviceBanner = "Samsung Odin / Download Mode Service Execution";
        }
        else if (opName.Contains("FRP", StringComparison.OrdinalIgnoreCase) ||
                 opName.Contains("FACTORY RESET", StringComparison.OrdinalIgnoreCase))
        {
            category = "MediaTek";
            protocol = KnownProtocol.MtkBrom;
            serviceBanner = "MediaTek Flash / Reset Service Execution";
        }
        else if (opName.Contains("RAMDISK", StringComparison.OrdinalIgnoreCase) ||
                 opName.Contains("APPLE", StringComparison.OrdinalIgnoreCase))
        {
            category = "AppleIos";
            protocol = KnownProtocol.AppleRecovery;
            serviceBanner = "Apple iOS Service Execution";
        }

        // Extract critical telemetry tokens
        string targetDevice = "USB\\VID_0E8D&PID_0003";
        string port = "";
        string hardware = "";
        string security = "";
        string meid = "";
        string model = "";
        var stages = new List<string>();

        foreach (var line in lines)
        {
            if (line.Contains("BOOTROM:0E8D:0003", StringComparison.OrdinalIgnoreCase) ||
                line.Contains("0E8D:0003", StringComparison.OrdinalIgnoreCase))
            {
                targetDevice = "USB\\VID_0E8D&PID_0003 (BOOTROM)";
            }

            var comMatch = Regex.Match(line, @"(COM\d+)", RegexOptions.IgnoreCase);
            if (comMatch.Success) port = comMatch.Groups[1].Value.ToUpperInvariant();

            if (line.StartsWith("Hardware :", StringComparison.OrdinalIgnoreCase) ||
                line.StartsWith("Hardware:", StringComparison.OrdinalIgnoreCase))
            {
                hardware = line.Replace("Hardware :", "").Replace("Hardware:", "").Trim();
            }

            if (line.StartsWith("Security Config :", StringComparison.OrdinalIgnoreCase) ||
                line.StartsWith("Security:", StringComparison.OrdinalIgnoreCase))
            {
                security = line.Replace("Security Config :", "").Replace("Security:", "").Trim();
            }

            if (line.StartsWith("MEID :", StringComparison.OrdinalIgnoreCase))
            {
                meid = line.Replace("MEID :", "").Trim();
            }

            if (line.StartsWith("Model Name :", StringComparison.OrdinalIgnoreCase) ||
                line.StartsWith("Model Number :", StringComparison.OrdinalIgnoreCase))
            {
                model = line.Replace("Model Name :", "").Replace("Model Number :", "").Trim();
            }

            // Capture critical stage milestones
            if (line.Contains("Waiting for device", StringComparison.OrdinalIgnoreCase)) stages.Add("Waiting for Device");
            if (line.Contains("Bypassing authentication", StringComparison.OrdinalIgnoreCase)) stages.Add("Authentication Bypass (SLA/DAA)");
            if (line.Contains("Handshaking", StringComparison.OrdinalIgnoreCase)) stages.Add("BROM Handshake Sync");
            if (line.Contains("Sending Download-Agent", StringComparison.OrdinalIgnoreCase)) stages.Add("Download-Agent (DA) Stage 1");
            if (line.Contains("Booting device", StringComparison.OrdinalIgnoreCase)) stages.Add("DA Boot Sequence");
            if (line.Contains("Reading partition info", StringComparison.OrdinalIgnoreCase)) stages.Add("Partition Table Analysis");
            if (line.Contains("Reading device info", StringComparison.OrdinalIgnoreCase)) stages.Add("Device Info Extraction");
            if (line.Contains("Erasing all", StringComparison.OrdinalIgnoreCase)) stages.Add("Wiping Data / Factory Reset");
            if (line.Contains("Entering download mode", StringComparison.OrdinalIgnoreCase)) stages.Add("Switching to Download Mode");
        }

        string activeStage = stages.Count > 0 ? string.Join(" -> ", stages) : "Active Execution";
        string targetDesc = !string.IsNullOrEmpty(port) ? $"{targetDevice} ({port})" : targetDevice;
        if (!string.IsNullOrEmpty(model)) targetDesc += $" [{model}]";

        // Build technical details matching user's exact specification
        var detailsSb = new StringBuilder();
        detailsSb.AppendLine(serviceBanner);
        detailsSb.AppendLine($"Binary: {callerPath}");
        detailsSb.AppendLine($"Action: {opName}");
        if (!string.IsNullOrEmpty(activeStage))
        {
            detailsSb.AppendLine($"Stage: {activeStage}");
        }
        detailsSb.AppendLine($"Device Target: {targetDesc}");
        if (!string.IsNullOrEmpty(hardware))
        {
            detailsSb.AppendLine($"Hardware: {hardware} {(string.IsNullOrEmpty(security) ? "" : $"({security})")}".Trim());
        }
        if (!string.IsNullOrEmpty(meid))
        {
            detailsSb.AppendLine($"MEID: {meid}");
        }
        detailsSb.Append($"Caller: {callerName} (PID {callerPid})");

        string technicalDetails = detailsSb.ToString();

        // Deduplication to prevent spamming identical stages within 1.5 seconds
        string dedupKey = $"{callerPid}:{opName}:{activeStage}:{targetDesc}";
        DateTime now = DateTime.UtcNow;
        if (_seenActionDeduplication.TryGetValue(dedupKey, out var lastTime) && (now - lastTime).TotalSeconds < 1.5)
        {
            return;
        }
        _seenActionDeduplication[dedupKey] = now;

        Interlocked.Increment(ref _sessionsCaptured);
        Interlocked.Increment(ref _eventsEmitted);

        var sessionEvt = new GsmToolSessionEvent
        {
            ToolName = callerName,
            ExecutablePath = callerPath,
            ProcessId = callerPid,
            OperationName = opName,
            Stage = activeStage,
            TargetDevice = targetDesc,
            PortOrEndpoint = port,
            ChipsetOrHardware = hardware,
            RawLogText = cleanText,
            FormattedSummary = $"[{callerName}] {opName} -> {targetDesc} ({activeStage})",
            TechnicalDetails = technicalDetails,
            Category = category,
            Protocol = protocol,
            SourceTag = "TOOL-LIVE",
            Timestamp = now
        };

        OnToolSessionCaptured?.Invoke(sessionEvt);

        // 1. Publish RawCaptureEvent for evidentiary integrity
        ulong seq = Interlocked.Increment(ref _sequence);
        byte[] payloadBytes = Encoding.UTF8.GetBytes(technicalDetails);
        var rawEvt = RawCaptureEvent.Create(
            sequence: seq,
            sensor: SensorType.Process,
            transport: TransportType.BULK,
            direction: PacketDirection.HOST_TO_DEVICE,
            device: targetDesc,
            session: $"{callerName}_{callerPid}_{opName}",
            iface: 0,
            endpoint: "TOOL_SESSION",
            payload: payloadBytes,
            timestampSource: "GsmToolSessionStreamSensor"
        );

        rawEvt.Metadata["ToolName"] = callerName;
        rawEvt.Metadata["ProcessId"] = callerPid.ToString();
        rawEvt.Metadata["Operation"] = opName;
        rawEvt.Metadata["TargetDevice"] = targetDesc;
        rawEvt.Metadata["Stage"] = activeStage;
        rawEvt.Metadata["SourceTag"] = "TOOL-LIVE";
        rawEvt.Metadata["TechnicalDetails"] = technicalDetails;

        _bus.Publish(rawEvt);

        // 2. Correlate and Report LogicalCommandEvent to Omnibus
        var cmd = _bus.Correlation.Correlate(
            opName,
            protocol,
            callerName,
            TransportType.BULK,
            targetDesc,
            $"{callerName}_{callerPid}_{opName}",
            PacketDirection.HOST_TO_DEVICE,
            [rawEvt.SequenceNumber],
            [rawEvt.PayloadHash],
            confidence: 1.0,
            suspectedPid: callerPid,
            suspectedToolName: callerName
        );

        cmd.Details["Category"] = category;
        cmd.Details["SourceTag"] = "TOOL-LIVE";
        cmd.Details["Summary"] = sessionEvt.FormattedSummary;
        cmd.Details["TechnicalDetails"] = technicalDetails;
        cmd.Details["Operation"] = opName;
        cmd.Details["Stage"] = activeStage;
        cmd.Details["DeviceTarget"] = targetDesc;
        cmd.Details["Caller"] = $"{callerName} (PID {callerPid})";
        cmd.Attribution.ProcessId = callerPid;
        cmd.Attribution.ImageName = callerName;

        _bus.ReportLogicalCommand(cmd);
    }

    public void Dispose()
    {
        Stop();
    }
}
