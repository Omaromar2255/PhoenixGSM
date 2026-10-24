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
using PhoenixGSM.OmniTrace.Sensors;

namespace PhoenixGSM.OmniTrace.Apple.Sensors;

/// <summary>
/// Dedicated real-time sensor & automatic file archiver for Apple iOS servicing sessions:
/// - Tracks Ramdisk SSH (`iproxy`, `plink`, `ssh`, `scp`), DFU/iBoot (`irecovery`, `gaster`), and GUI tools (`UnlockTool`, `3uTools`, `Broque`, `iRemoval`).
/// - Automatically saves all Apple Activation Tickets (`activation_record.plist`, `IC-Info.sisv`, `commcenter.plist`, `data_ark.plist`),
///   MDM/Bypass profiles (`CloudConfigurationDetails.plist`), Keychains (`keychain-2.db`), SHSH blobs (`.shsh2`),
///   and Bootchain/Ramdisk files (`.im4p`, `.img4`, `iBSS`, `iBEC`, `ramdisk.dmg`, `Pongo.bin`) directly into
///   the shared session directory (`CapturedArtifacts\Session_yyyy-MM-dd_HH-mm-ss`).
/// </summary>
public sealed class AppleRamdiskSessionWatcher : IDisposable
{
    private readonly OmniTraceEventBus _bus;
    private readonly ConcurrentDictionary<string, FileSystemWatcher> _activeWatchers = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, byte> _seenArtifacts = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, byte> _seenSummaryLines = new(StringComparer.OrdinalIgnoreCase);
    private ulong _sequenceCounter = 800000;

    private static readonly HashSet<string> AppleArchivableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".plist", ".sisv", ".sidb", ".sido", ".tsv", ".shsh", ".shsh2",
        ".im4p", ".img4", ".dfu", ".dmg", ".sh", ".tar", ".gz", ".deb",
        ".ipa", ".mobileconfig", ".cert", ".pem", ".der", ".db", ".bin"
    };

    private static readonly string[] AppleImportantFileKeywords =
    [
        "activation", "IC-Info", "commcenter", "data_ark", "purplebuddy", "MobileGestalt",
        "CloudConfiguration", "disabled", "keychain", "LockoutState", "FairPlay", "wildcard",
        "iBSS", "iBEC", "DeviceTree", "ramdisk", "kernelcache", "sep-firmware", "trustcache",
        "bootlogo", "Pongo", "checkra1n", "palera1n", "shsh", "BuildManifest", "Restore"
    ];

    public AppleRamdiskSessionWatcher(OmniTraceEventBus bus)
    {
        _bus = bus;
        InitializeDefaultAppleWatchDirs();
    }

    private void InitializeDefaultAppleWatchDirs()
    {
        try
        {
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string[] defaultDirs =
            [
                Path.GetTempPath(),
                @"C:\UnlockTool\Temp",
                @"C:\UnlockTool\DataFiles\Apple",
                @"C:\3uTools",
                Path.Combine(userProfile, ".ssh"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Apple\Lockdown")
            ];

            foreach (string dir in defaultDirs)
            {
                if (Directory.Exists(dir))
                {
                    AttachWorkspaceWatcher(dir, "AppleMonitor");
                }
            }
        }
        catch { }
    }

    /// <summary>
    /// Invoked when iproxy.exe or any Apple CLI/GUI tool is detected by process monitoring.
    /// </summary>
    public void OnIproxyLaunched(int iproxyPid, int callerPid, string cmdLine, string callerPath, string? iproxyPath = null)
    {
        string callerName = Path.GetFileName(callerPath);
        string? callerDir = !string.IsNullOrWhiteSpace(callerPath) && (Directory.Exists(callerPath) || File.Exists(callerPath))
            ? (Directory.Exists(callerPath) ? callerPath : Path.GetDirectoryName(callerPath))
            : null;

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

        int localPort = 2222;
        int remotePort = 22;
        var portMatch = Regex.Match(cmdLine, @"(\d{2,5})[:\s](\d{1,5})");
        if (portMatch.Success)
        {
            int.TryParse(portMatch.Groups[1].Value, out localPort);
            int.TryParse(portMatch.Groups[2].Value, out remotePort);
        }

        EmitLogicalCommand(
            operation: "Ramdisk:TunnelStarted",
            summary: $"[iOS RAMDISK SSH] Tunnel Established: 127.0.0.1:{localPort} -> Device:{remotePort} (Caller: {callerName}, PID {callerPid})",
            direction: PacketDirection.HOST_TO_DEVICE,
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
            InspectStagedScripts(dir, callerName, callerPid);
            InspectExistingArtifacts(dir, callerName, callerPid);
            AttachWorkspaceWatcher(dir, callerName);
        }

        _ = Task.Run(() => TrackSshConnectionAsync(callerPid, localPort, callerName));
    }

    private void InspectStagedScripts(string rootDir, string callerName, int callerPid)
    {
        try
        {
            if (!Directory.Exists(rootDir)) return;
            foreach (var shFile in Directory.GetFiles(rootDir, "*.sh", SearchOption.AllDirectories))
            {
                string fname = Path.GetFileName(shFile);
                if (_seenArtifacts.TryAdd(shFile, 1))
                {
                    ArchiveAppleFileToSharedSession(shFile, callerPid, callerName, "Apple Ramdisk Staged Script");
                    ParseAndEmitScript(shFile, fname, callerName);
                }
            }
        }
        catch { }
    }

    private void InspectExistingArtifacts(string rootDir, string callerName, int callerPid)
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
                HandleFileChange(plFile, callerName, callerPid);
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
                    tr.Contains("activation_record") || tr.Contains("IC-Info") || tr.Contains("CloudConfiguration") ||
                    tr.Contains("keychain") || tr.Contains("purplebuddy") || tr.Contains("chflags"))
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
                    direction: PacketDirection.HOST_TO_DEVICE,
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

    public void AttachWorkspaceWatcher(string callerDir, string callerName)
    {
        if (string.IsNullOrWhiteSpace(callerDir) || !Directory.Exists(callerDir)) return;
        if (callerDir.Contains("CapturedArtifacts", StringComparison.OrdinalIgnoreCase)) return;
        if (_activeWatchers.ContainsKey(callerDir)) return;

        try
        {
            var watcher = new FileSystemWatcher(callerDir)
            {
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime | NotifyFilters.Size,
                EnableRaisingEvents = true
            };

            watcher.Created += (s, e) => HandleFileChange(e.FullPath, callerName, 0);
            watcher.Changed += (s, e) => HandleFileChange(e.FullPath, callerName, 0);

            _activeWatchers[callerDir] = watcher;
        }
        catch { }
    }

    private void HandleFileChange(string fullPath, string callerName, int callerPid)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(fullPath) || fullPath.Contains("CapturedArtifacts", StringComparison.OrdinalIgnoreCase))
                return;

            string fileName = Path.GetFileName(fullPath);
            string ext = Path.GetExtension(fullPath);

            if (fileName.Equals("summary.txt", StringComparison.OrdinalIgnoreCase))
            {
                ParseSummaryFile(fullPath, callerName);
                return;
            }

            if (!AppleArchivableExtensions.Contains(ext)) return;

            bool isImportantAppleArtifact = AppleImportantFileKeywords.Any(k =>
                fileName.Contains(k, StringComparison.OrdinalIgnoreCase) ||
                fullPath.Contains(k, StringComparison.OrdinalIgnoreCase));

            if (!isImportantAppleArtifact && !ext.Equals(".shsh2", StringComparison.OrdinalIgnoreCase) &&
                !ext.Equals(".im4p", StringComparison.OrdinalIgnoreCase) &&
                !ext.Equals(".img4", StringComparison.OrdinalIgnoreCase) &&
                !ext.Equals(".sisv", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            var fi = new FileInfo(fullPath);
            if (!fi.Exists || fi.Length <= 0) return;

            string key = $"{fullPath}:{fi.Length}";
            if (_seenArtifacts.TryAdd(key, 1))
            {
                string savedBanner = ArchiveAppleFileToSharedSession(fullPath, callerPid, callerName, "Apple Artifact Auto-Archiver");

                EmitLogicalCommand(
                    operation: $"Apple:ArtifactSaved:{fileName}",
                    summary: $"[iOS ARTIFACT SAVED] {fileName} ({fi.Length:N0} bytes) {savedBanner}",
                    direction: PacketDirection.HOST_TO_DEVICE,
                    details: new Dictionary<string, string>
                    {
                        ["File"] = fullPath,
                        ["Artifact"] = fileName,
                        ["Size"] = $"{fi.Length:N0} bytes",
                        ["Caller"] = callerName,
                        ["SharedSessionVault"] = SmartFilePushArchiver.ActiveSessionDirectory
                    }
                );
            }
        }
        catch { }
    }

    /// <summary>
    /// Saves any Apple servicing file (Activation record, IC-Info.sisv, SHSH2, IM4P/IMG4, Ramdisk, etc.)
    /// into the unified `CapturedArtifacts\Session_...` directory shared with ADB and Layer 24.
    /// </summary>
    public static string ArchiveAppleFileToSharedSession(string filePath, int processId, string callerName, string originLabel)
    {
        try
        {
            if (SmartFilePushArchiver.ArchiveL24ExtractedOrUsedFile(
                    filePath,
                    fallbackBytes: null,
                    processId: processId,
                    callerOrigin: $"{callerName} ({originLabel})",
                    out var saved) && saved != null)
            {
                return $"-> [Saved: CapturedArtifacts\\{saved.SessionFolderName}\\{saved.SavedFileName}]";
            }
        }
        catch { }
        return string.Empty;
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
                            summary: $"[iOS RAMDISK RSP] Phone Operation Result: {tr.TrimStart('+', ' ')}",
                            direction: PacketDirection.DEVICE_TO_HOST,
                            details: new Dictionary<string, string>
                            {
                                ["SummaryLine"] = tr,
                                ["SummaryFile"] = summaryPath,
                                ["Caller"] = callerName,
                                ["IsResponse"] = "true"
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
                    direction: PacketDirection.HOST_TO_DEVICE,
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
                    direction: PacketDirection.DEVICE_TO_HOST,
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

    private void EmitLogicalCommand(string operation, string summary, PacketDirection direction, Dictionary<string, string> details)
    {
        ulong seq = Interlocked.Increment(ref _sequenceCounter);
        var cmd = _bus.Correlation.Correlate(
            commandText: summary,
            protocol: KnownProtocol.AppleRamdiskSsh,
            service: "ramdisk-ssh",
            transport: TransportType.TCP,
            device: "APPLE_RAMDISK_DEVICE",
            session: "RAMDISK_SESS_01",
            direction: direction,
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
