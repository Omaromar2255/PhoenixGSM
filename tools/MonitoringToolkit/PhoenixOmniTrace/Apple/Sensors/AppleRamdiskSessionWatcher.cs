using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using PhoenixGSM.OmniTrace.Apple.Models;
using PhoenixGSM.OmniTrace.Bus;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.Apple.Sensors;

/// <summary>
/// Dedicated real-time sensor that tracks Apple Ramdisk SSH servicing sessions.
/// When an iproxy process (e.g., iproxy.exe 2222:22) is launched by a GSM servicing tool,
/// this sensor immediately tracks the parent tool's workspace, staged bash scripts,
/// live filesystem operations (summary.txt, activation tickets, plists), and SSH socket activity.
/// </summary>
public sealed class AppleRamdiskSessionWatcher : IDisposable
{
    private readonly OmniTraceEventBus _bus;
    private readonly ConcurrentDictionary<string, FileSystemWatcher> _activeWatchers = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, byte> _seenArtifacts = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, byte> _seenSummaryLines = new(StringComparer.OrdinalIgnoreCase);
    private ulong _sequenceCounter = 800000;

    public AppleRamdiskSessionWatcher(OmniTraceEventBus bus)
    {
        _bus = bus;
    }

    /// <summary>
    /// Invoked when iproxy.exe is detected by process monitoring.
    /// </summary>
    public void OnIproxyLaunched(int iproxyPid, int callerPid, string cmdLine, string callerPath, string? iproxyPath = null)
    {
        string callerName = Path.GetFileName(callerPath);
        string? callerDir = !string.IsNullOrWhiteSpace(callerPath) && (Directory.Exists(callerPath) || File.Exists(callerPath))
            ? (Directory.Exists(callerPath) ? callerPath : Path.GetDirectoryName(callerPath))
            : null;

        // Try getting parent process executable path if callerDir is null
        if (string.IsNullOrWhiteSpace(callerDir) && callerPid > 0)
        {
            try
            {
                var proc = System.Diagnostics.Process.GetProcessById(callerPid);
                string? pPath = proc.MainModule?.FileName;
                if (!string.IsNullOrWhiteSpace(pPath))
                {
                    callerPath = pPath;
                    callerDir = Path.GetDirectoryName(pPath);
                    callerName = Path.GetFileName(pPath);
                }
            }
            catch { }
        }

        // Parse tunnel ports (e.g. 2222:22 or 2222 22)
        int localPort = 2222;
        int remotePort = 22;
        var portMatch = Regex.Match(cmdLine, @"(\d{2,5})[:\s](\d{1,5})");
        if (portMatch.Success)
        {
            int.TryParse(portMatch.Groups[1].Value, out localPort);
            int.TryParse(portMatch.Groups[2].Value, out remotePort);
        }

        // 1. Emit SSH Ramdisk Tunnel Initialization
        EmitLogicalCommand(
            operation: "Ramdisk:TunnelStarted",
            summary: $"[iOS RAMDISK SSH] Tunnel Established: 127.0.0.1:{localPort} -> Device:{remotePort} (Caller: {callerName}, PID {callerPid})",
            details: new Dictionary<string, string>
            {
                ["LocalPort"] = localPort.ToString(),
                ["RemotePort"] = remotePort.ToString(),
                ["CallerProcess"] = callerName,
                ["CallerPid"] = callerPid.ToString(),
                ["CallerPath"] = callerPath,
                ["IproxyPid"] = iproxyPid.ToString(),
                ["CommandLine"] = cmdLine
            }
        );

        // 2. Resolve directories to inspect: caller directory + iproxy tool directory hierarchy
        var dirsToScan = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrWhiteSpace(callerDir) && Directory.Exists(callerDir))
        {
            dirsToScan.Add(callerDir);
        }

        if (!string.IsNullOrWhiteSpace(iproxyPath) && File.Exists(iproxyPath))
        {
            var cur = Path.GetDirectoryName(iproxyPath);
            while (!string.IsNullOrWhiteSpace(cur) && Directory.Exists(cur))
            {
                dirsToScan.Add(cur);
                var p = Directory.GetParent(cur);
                if (p == null || p.FullName == cur || p.FullName.Length <= 3)
                {
                    if (p != null && Directory.Exists(p.FullName)) dirsToScan.Add(p.FullName);
                    break;
                }
                cur = p.FullName;
            }
        }

        foreach (var dir in dirsToScan)
        {
            InspectStagedScripts(dir, callerName);
            InspectExistingArtifacts(dir, callerName);
            AttachWorkspaceWatcher(dir, callerName);
        }

        // 3. Track active TCP socket to localPort in background
        _ = Task.Run(() => TrackSshConnectionAsync(callerPid, localPort, callerName));
    }

    private void InspectStagedScripts(string rootDir, string callerName)
    {
        try
        {
            if (!Directory.Exists(rootDir)) return;
            foreach (var shFile in Directory.GetFiles(rootDir, "*.sh", SearchOption.AllDirectories))
            {
                string fname = Path.GetFileName(shFile);
                if (_seenArtifacts.TryAdd(shFile, 1))
                {
                    ParseAndEmitScript(shFile, fname, callerName);
                }
            }
        }
        catch { }
    }

    private void InspectExistingArtifacts(string rootDir, string callerName)
    {
        try
        {
            if (!Directory.Exists(rootDir)) return;
            foreach (var sumFile in Directory.GetFiles(rootDir, "*summary*.txt", SearchOption.AllDirectories))
            {
                ParseSummaryFile(sumFile, callerName);
            }
            foreach (var plFile in Directory.GetFiles(rootDir, "*.plist", SearchOption.AllDirectories))
            {
                HandleFileChange(plFile, callerName);
            }
        }
        catch { }
    }

    private void ParseAndEmitScript(string filePath, string fileName, string callerName)
    {
        try
        {
            string[] lines = File.ReadAllLines(filePath);
            var mountSteps = new List<string>();

            foreach (var line in lines)
            {
                string tr = line.Trim();
                if (tr.StartsWith("#") || string.IsNullOrWhiteSpace(tr)) continue;

                if (tr.Contains("mount_apfs") || tr.Contains("mount_hfs") || tr.Contains("seputil") ||
                    tr.Contains("nvram") || tr.Contains("FairPlay") || tr.Contains("commcenter") ||
                    tr.Contains("activation_record") || tr.Contains("IC-Info"))
                {
                    mountSteps.Add(tr);
                }
            }

            if (mountSteps.Count > 0)
            {
                string preview = string.Join(" | ", mountSteps.Take(5));
                EmitLogicalCommand(
                    operation: $"Ramdisk:ScriptStaged:{fileName}",
                    summary: $"[iOS RAMDISK SSH] Staged Script ({fileName}): {mountSteps.Count} critical device commands identified",
                    details: new Dictionary<string, string>
                    {
                        ["ScriptFile"] = filePath,
                        ["Caller"] = callerName,
                        ["IdentifiedCommands"] = string.Join("\n", mountSteps),
                        ["CommandPreview"] = preview
                    }
                );
            }
        }
        catch { }
    }

    private void AttachWorkspaceWatcher(string callerDir, string callerName)
    {
        if (_activeWatchers.ContainsKey(callerDir)) return;

        try
        {
            var watcher = new FileSystemWatcher(callerDir)
            {
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime | NotifyFilters.Size,
                EnableRaisingEvents = true
            };

            watcher.Created += (s, e) => HandleFileChange(e.FullPath, callerName);
            watcher.Changed += (s, e) => HandleFileChange(e.FullPath, callerName);

            _activeWatchers[callerDir] = watcher;
        }
        catch { }
    }

    private void HandleFileChange(string fullPath, string callerName)
    {
        try
        {
            string fileName = Path.GetFileName(fullPath);

            // 1. Live Summary Log parser (summary.txt)
            if (fileName.Equals("summary.txt", StringComparison.OrdinalIgnoreCase))
            {
                ParseSummaryFile(fullPath, callerName);
                return;
            }

            // 2. Activation and bypass artifacts
            if (fileName.EndsWith(".plist", StringComparison.OrdinalIgnoreCase) ||
                fileName.EndsWith(".sisv", StringComparison.OrdinalIgnoreCase) ||
                fileName.EndsWith(".tsv", StringComparison.OrdinalIgnoreCase))
            {
                if (fileName.Contains("activation", StringComparison.OrdinalIgnoreCase) ||
                    fileName.Contains("data_ark", StringComparison.OrdinalIgnoreCase) ||
                    fileName.Contains("commcenter", StringComparison.OrdinalIgnoreCase) ||
                    fileName.Contains("IC-Info", StringComparison.OrdinalIgnoreCase) ||
                    fileName.Contains("purplebuddy", StringComparison.OrdinalIgnoreCase) ||
                    fileName.Contains("MobileGestalt", StringComparison.OrdinalIgnoreCase) ||
                    fileName.Contains("disabled", StringComparison.OrdinalIgnoreCase))
                {
                    string key = $"{fullPath}:{new FileInfo(fullPath).Length}";
                    if (_seenArtifacts.TryAdd(key, 1))
                    {
                        long len = new FileInfo(fullPath).Length;
                        EmitLogicalCommand(
                            operation: $"Ramdisk:TicketArtifact:{fileName}",
                            summary: $"[iOS RAMDISK SSH] Activation Artifact: {fileName} ({len} bytes staged/restored)",
                            details: new Dictionary<string, string>
                            {
                                ["File"] = fullPath,
                                ["Artifact"] = fileName,
                                ["Size"] = $"{len} bytes",
                                ["Caller"] = callerName
                            }
                        );
                    }
                }
            }
        }
        catch { }
    }

    private void ParseSummaryFile(string summaryPath, string callerName)
    {
        try
        {
            if (!File.Exists(summaryPath)) return;
            string[] lines = File.ReadAllLines(summaryPath);

            foreach (var line in lines)
            {
                string tr = line.Trim();
                if (tr.StartsWith("+") || tr.StartsWith("OK:") || tr.Contains("verified") || tr.Contains("patched") || tr.Contains("applied"))
                {
                    string dedupeKey = $"{summaryPath}:{tr}";
                    if (_seenSummaryLines.TryAdd(dedupeKey, 1))
                    {
                        EmitLogicalCommand(
                            operation: "Ramdisk:StepCompleted",
                            summary: $"[iOS RAMDISK SSH] Operation Complete: {tr.TrimStart('+', ' ')}",
                            details: new Dictionary<string, string>
                            {
                                ["SummaryLine"] = tr,
                                ["SummaryFile"] = summaryPath,
                                ["Caller"] = callerName
                            }
                        );
                    }
                }
            }
        }
        catch { }
    }

    private async Task TrackSshConnectionAsync(int callerPid, int port, string callerName)
    {
        bool wasConnected = false;
        var start = DateTime.UtcNow;

        for (int i = 0; i < 60; i++)
        {
            await Task.Delay(1000).ConfigureAwait(false);
            bool isConnectedNow = IsTcpPortActive(port);

            if (isConnectedNow && !wasConnected)
            {
                wasConnected = true;
                EmitLogicalCommand(
                    operation: "Ramdisk:SSHConnected",
                    summary: $"[iOS RAMDISK SSH] Active SSH Client Connection Established on 127.0.0.1:{port} by {callerName}",
                    details: new Dictionary<string, string>
                    {
                        ["Port"] = port.ToString(),
                        ["Caller"] = callerName,
                        ["State"] = "ESTABLISHED"
                    }
                );
            }
            else if (!isConnectedNow && wasConnected)
            {
                var duration = DateTime.UtcNow - start;
                EmitLogicalCommand(
                    operation: "Ramdisk:SSHClosed",
                    summary: $"[iOS RAMDISK SSH] SSH Session Finished on port {port} (Total Duration: {duration.TotalSeconds:F1}s)",
                    details: new Dictionary<string, string>
                    {
                        ["Port"] = port.ToString(),
                        ["Caller"] = callerName,
                        ["DurationSeconds"] = duration.TotalSeconds.ToString("F1")
                    }
                );
                break;
            }
        }
    }

    private static bool IsTcpPortActive(int port)
    {
        try
        {
            var ipProps = IPGlobalProperties.GetIPGlobalProperties();
            var connections = ipProps.GetActiveTcpConnections();
            return connections.Any(c => c.LocalEndPoint.Port == port || c.RemoteEndPoint.Port == port);
        }
        catch
        {
            return false;
        }
    }

    private void EmitLogicalCommand(string operation, string summary, Dictionary<string, string> details)
    {
        ulong seq = Interlocked.Increment(ref _sequenceCounter);
        var cmd = _bus.Correlation.Correlate(
            commandText: summary,
            protocol: KnownProtocol.AppleRamdiskSsh,
            service: "ramdisk-ssh",
            transport: TransportType.TCP,
            device: "APPLE_RAMDISK_DEVICE",
            session: "RAMDISK_SESS_01",
            direction: PacketDirection.BIDIRECTIONAL,
            rawEvidenceSequences: [seq],
            evidenceHashes: [Guid.NewGuid().ToString("N")[..8]],
            confidence: 0.99
        );

        cmd.Details["AppleMode"] = AppleDeviceMode.RamdiskSsh.ToString();
        cmd.Details["AppleCategory"] = "RamdiskSSH";
        cmd.Details["AppleOperation"] = operation;
        foreach (var kvp in details) cmd.Details[kvp.Key] = kvp.Value;

        _bus.ReportLogicalCommand(cmd);
    }

    public void Dispose()
    {
        foreach (var kvp in _activeWatchers)
        {
            try { kvp.Value.Dispose(); } catch { }
        }
        _activeWatchers.Clear();
    }
}
