using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using PhoenixGSM.OmniTrace.Bus;
using PhoenixGSM.OmniTrace.Decoders;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.Sensors;

/// <summary>
/// LAYER 12 — ADB Push Artifact & Exploit Interception Sensor
/// Dual-Vector Capture Architecture:
///   Vector A: Pre-Push Host Snapshotting (microsecond snapshot with non-exclusive FileShare before tool deletes %TEMP% binaries)
///   Vector B: In-Flight ADB Sync Protocol Wire Reassembly (reconstructs files pushed directly from memory / in-process tools)
/// Includes CAS SHA-256 deduplication and deep content analysis (ELF/DEX/APK/scripts).
/// </summary>
public sealed class AdbPushArtifactSensor : IDisposable
{
    private readonly OmniTraceEventBus _bus;
    private readonly AdbPushArtifactVault _vault;
    private readonly AdbSyncStreamReconstructor _reconstructor;
    private readonly ConcurrentDictionary<string, DateTime> _recentlyCaptured = new(StringComparer.OrdinalIgnoreCase);

    private readonly List<FileSystemWatcher> _directoryWatchers = [];
    private static readonly string[] KnownStagingDirectories =
    [
        @"C:\Users\pc5\Desktop\mac\tmp",
        @"C:\Users\pc5\Desktop\mac",
        @"C:\Users\pc5\Desktop\tools",
        @"C:\Temp",
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "mac", "tmp"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "mac"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "tools"),
        Path.GetTempPath(),
        Path.Combine(Path.GetTempPath(), "mac"),
        Path.Combine(Path.GetTempPath(), "adb")
    ];

    private bool _isRunning;
    private long _capturedFilesCount;
    private long _totalBytesCaptured;

    public AdbPushArtifactVault Vault => _vault;
    public AdbSyncStreamReconstructor Reconstructor => _reconstructor;
    public bool IsRunning => _isRunning;
    public long CapturedFilesCount => Interlocked.Read(ref _capturedFilesCount);
    public long TotalBytesCaptured => Interlocked.Read(ref _totalBytesCaptured);

    public event Action<PushedArtifactInfo>? OnArtifactCaptured;

    public AdbPushArtifactSensor(OmniTraceEventBus bus, string? customVaultDir = null)
    {
        _bus = bus ?? throw new ArgumentNullException(nameof(bus));
        _vault = new AdbPushArtifactVault(customVaultDir);
        _reconstructor = new AdbSyncStreamReconstructor(_vault);
    }

    public void Start()
    {
        if (_isRunning) return;
        _isRunning = true;
        _bus.OnLogicalCommand += HandleLogicalCommand;
        ScanKnownStagingDirectories();
        StartDirectoryWatchers();
    }

    public void Stop()
    {
        if (!_isRunning) return;
        _isRunning = false;
        _bus.OnLogicalCommand -= HandleLogicalCommand;
        _recentlyCaptured.Clear();
        StopDirectoryWatchers();
    }

    /// <summary>
    /// Processes incoming ADB wire payload on a "sync:" channel (Vector B).
    /// </summary>
    public bool ProcessSyncWirePayload(
        uint channelId,
        byte[] payload,
        string procName,
        int pid,
        string deviceSerial,
        out PushedArtifactInfo? completedArtifact)
    {
        completedArtifact = null;
        if (!_isRunning) return false;

        if (_reconstructor.ProcessSyncPayload(channelId, payload, procName, pid, deviceSerial, out completedArtifact) && completedArtifact != null)
        {
            RecordCapturedArtifact(completedArtifact);
            return true;
        }

        return false;
    }

    /// <summary>
    /// Handles correlated logical commands from the event bus (Vector A: Host Pre-Push Snapshot).
    /// </summary>
    private void HandleLogicalCommand(LogicalCommandEvent cmd)
    {
        if (!_isRunning) return;

        string text = cmd.Command;
        if (cmd.Details.TryGetValue("CommandLine", out var fullCmd) && !string.IsNullOrWhiteSpace(fullCmd))
        {
            text = fullCmd;
        }

        if (TryParseAdbPushCommand(text, out string localSource, out string remoteTarget))
        {
            // Resolve relative paths if necessary (e.g. search staging dirs, %TEMP% or current directory)
            string resolvedPath = ResolveLocalFilePath(localSource);

            int pid = cmd.Attribution?.ProcessId ?? 0;
            string procName = cmd.Attribution?.ImageName ?? (!string.IsNullOrWhiteSpace(cmd.Service) ? cmd.Service : "GSM_Tool.exe");
            string serial = cmd.DeviceIdentity ?? "";

            var artifact = _vault.TryCaptureLocalFile(resolvedPath, remoteTarget, procName, pid, serial);
            if (artifact != null)
            {
                RecordCapturedArtifact(artifact);
            }
        }
        else if (TryParseAdbPullCommand(text, out string remotePull, out string localPull))
        {
            // Vector C: Post-Pull Host Interception (pulls like /data/local/tmp/athun)
            int pid = cmd.Attribution?.ProcessId ?? 0;
            string procName = cmd.Attribution?.ImageName ?? (!string.IsNullOrWhiteSpace(cmd.Service) ? cmd.Service : "GSM_Tool.exe");
            string serial = cmd.DeviceIdentity ?? "";

            _ = Task.Run(async () =>
            {
                for (int i = 0; i < 20; i++)
                {
                    await Task.Delay(250);
                    string resolvedPull = ResolveLocalFilePath(localPull);
                    string checkPath = File.Exists(resolvedPull) ? resolvedPull : (File.Exists(localPull) ? localPull : "");
                    if (!string.IsNullOrEmpty(checkPath))
                    {
                        var artifact = _vault.TryCaptureLocalFile(
                            checkPath, remotePull, procName, pid, serial,
                            new Dictionary<string, string> { ["Direction"] = "PULL", ["TargetDevicePath"] = remotePull });
                        if (artifact != null)
                        {
                            RecordCapturedArtifact(artifact);
                            break;
                        }
                    }
                }
            });
        }
    }

    /// <summary>
    /// Internal record, emit and bus correlate helper for captured artifacts.
    /// </summary>
    private void RecordCapturedArtifact(PushedArtifactInfo artifact)
    {
        Interlocked.Increment(ref _capturedFilesCount);
        Interlocked.Add(ref _totalBytesCaptured, artifact.FileSizeBytes);

        // Prevent notification flooding if identical file is pushed within 500ms
        string key = $"{artifact.Sha256}:{artifact.TargetDevicePath}";
        DateTime now = DateTime.UtcNow;
        if (_recentlyCaptured.TryGetValue(key, out var exp) && now < exp)
        {
            return;
        }
        _recentlyCaptured[key] = now.AddMilliseconds(500);

        // Clean up expired keys if cache exceeds 1000 items
        if (_recentlyCaptured.Count > 1000)
        {
            foreach (var kvp in _recentlyCaptured)
            {
                if (now > kvp.Value) _recentlyCaptured.TryRemove(kvp.Key, out _);
            }
        }

        // Fire sensor event
        OnArtifactCaptured?.Invoke(artifact);

        // Report correlated event to EventBus for live feed and logging
        string sizeStr = FormatBytes(artifact.FileSizeBytes);
        string shortSha = artifact.Sha256.Length > 8 ? artifact.Sha256[..8] : artifact.Sha256;
        var busCmd = _bus.Correlation.Correlate(
            $"[ARTIFACT VAULT] Intercepted pushed file: {artifact.FileName} ({sizeStr}) -> {artifact.TargetDevicePath} [{artifact.MagicDescription} | SHA: {shortSha}]",
            KnownProtocol.ADB,
            artifact.SourceVector == "HostPrePush" ? "adb:push" : "sync:send",
            TransportType.BULK,
            artifact.DeviceSerial,
            artifact.SourceVector,
            PacketDirection.HOST_TO_DEVICE,
            [],
            [artifact.Sha256],
            confidence: 1.0,
            suspectedPid: artifact.ProcessId,
            suspectedToolName: artifact.ProcessName
        );

        busCmd.Details["VaultFilePath"] = artifact.VaultFilePath;
        busCmd.Details["VaultManifestPath"] = artifact.VaultManifestPath;
        busCmd.Details["Sha256"] = artifact.Sha256;
        busCmd.Details["Md5"] = artifact.Md5;
        busCmd.Details["Classification"] = artifact.FileClassification.ToString();
        busCmd.Details["IsExploitOrExecutable"] = artifact.IsExecutableOrExploit ? "True" : "False";
        busCmd.Details["SourceVector"] = artifact.SourceVector;
        busCmd.Details["TargetDevicePath"] = artifact.TargetDevicePath;
        if (!string.IsNullOrEmpty(artifact.LocalSourcePath))
        {
            busCmd.Details["LocalSourcePath"] = artifact.LocalSourcePath;
        }

        _bus.ReportLogicalCommand(busCmd);
    }

    /// <summary>
    /// Parses host command lines to detect "adb push" or "push" syntax and extracts local source and remote target.
    /// </summary>
    public static bool TryParseAdbPushCommand(string commandLine, out string localPath, out string targetPath)
    {
        localPath = string.Empty;
        targetPath = string.Empty;

        if (string.IsNullOrWhiteSpace(commandLine)) return false;

        // Must contain "push" (case-insensitive) as a whole word
        if (!Regex.IsMatch(commandLine, @"\bpush\b", RegexOptions.IgnoreCase)) return false;

        var tokens = TokenizeCommandLine(commandLine);
        int pushIdx = -1;
        for (int i = 0; i < tokens.Count; i++)
        {
            if (string.Equals(tokens[i], "push", StringComparison.OrdinalIgnoreCase))
            {
                pushIdx = i;
                break;
            }
        }

        if (pushIdx < 0) return false;

        // Skip any flags after push (e.g. -p, -a, -z, --sync)
        int argStart = pushIdx + 1;
        while (argStart < tokens.Count && tokens[argStart].StartsWith("-"))
        {
            argStart++;
        }

        if (argStart < tokens.Count)
        {
            localPath = tokens[argStart].Trim('"', '\'');
            if (argStart + 1 < tokens.Count)
            {
                targetPath = tokens[argStart + 1].Trim('"', '\'');
            }
            else
            {
                string fn = Path.GetFileName(localPath);
                targetPath = "/data/local/tmp/" + (string.IsNullOrWhiteSpace(fn) ? "pushed_file" : fn);
            }

            return !string.IsNullOrWhiteSpace(localPath);
        }

        return false;
    }

    /// <summary>
    /// Parses host command lines to detect "adb pull" or "pull" syntax and extracts remote source and local target.
    /// </summary>
    public static bool TryParseAdbPullCommand(string commandLine, out string remotePath, out string localPath)
    {
        remotePath = string.Empty;
        localPath = string.Empty;

        if (string.IsNullOrWhiteSpace(commandLine)) return false;

        if (!Regex.IsMatch(commandLine, @"\bpull\b", RegexOptions.IgnoreCase)) return false;

        var tokens = TokenizeCommandLine(commandLine);
        int pullIdx = -1;
        for (int i = 0; i < tokens.Count; i++)
        {
            if (string.Equals(tokens[i], "pull", StringComparison.OrdinalIgnoreCase))
            {
                pullIdx = i;
                break;
            }
        }

        if (pullIdx < 0) return false;

        int argStart = pullIdx + 1;
        while (argStart < tokens.Count && tokens[argStart].StartsWith("-"))
        {
            argStart++;
        }

        if (argStart < tokens.Count)
        {
            remotePath = tokens[argStart].Trim('"', '\'');
            if (argStart + 1 < tokens.Count)
            {
                localPath = tokens[argStart + 1].Trim('"', '\'');
            }
            else
            {
                string fn = Path.GetFileName(remotePath);
                localPath = Path.Combine(Environment.CurrentDirectory, string.IsNullOrWhiteSpace(fn) ? "pulled_file" : fn);
            }

            return !string.IsNullOrWhiteSpace(remotePath);
        }

        return false;
    }

    /// <summary>
    /// Resolves local file paths, checking relative paths against staging dirs, %TEMP% or current directory.
    /// </summary>
    public static string ResolveLocalFilePath(string path)
    {
        if (File.Exists(path)) return path;

        string fileName = Path.GetFileName(path);
        foreach (var dir in KnownStagingDirectories)
        {
            try
            {
                if (Directory.Exists(dir))
                {
                    string combined = Path.Combine(dir, fileName);
                    if (File.Exists(combined)) return combined;
                }
            }
            catch { }
        }

        if (!Path.IsPathRooted(path))
        {
            string inTemp = Path.Combine(Path.GetTempPath(), path);
            if (File.Exists(inTemp)) return inTemp;

            string inCurrent = Path.Combine(Environment.CurrentDirectory, path);
            if (File.Exists(inCurrent)) return inCurrent;
        }

        return path;
    }

    /// <summary>
    /// Scans known tool staging directories (e.g. Desktop\mac\tmp, %TEMP%) to capture staged binaries before execution.
    /// </summary>
    public void ScanKnownStagingDirectories()
    {
        foreach (var dir in KnownStagingDirectories)
        {
            try
            {
                if (!Directory.Exists(dir)) continue;
                var files = Directory.GetFiles(dir);
                foreach (var file in files)
                {
                    try
                    {
                        var info = new FileInfo(file);
                        if (info.Length == 0 || info.Length > AdbPushArtifactVault.DefaultMaxFullCaptureBytes) continue;
                        string relName = Path.GetFileName(file);
                        var art = _vault.TryCaptureLocalFile(
                            file, $"/data/local/tmp/{relName}", "StagedPayloadScanner", 0, "ALL_DEVICES",
                            new Dictionary<string, string> { ["StageOrigin"] = dir });
                        if (art != null)
                        {
                            RecordCapturedArtifact(art);
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }
    }

    private void StartDirectoryWatchers()
    {
        foreach (var dir in KnownStagingDirectories)
        {
            try
            {
                if (!Directory.Exists(dir)) continue;
                var fsw = new FileSystemWatcher(dir)
                {
                    IncludeSubdirectories = true,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                    EnableRaisingEvents = true
                };
                fsw.Created += (s, e) => OnStagedFileDiscovered(e.FullPath, dir);
                fsw.Changed += (s, e) => OnStagedFileDiscovered(e.FullPath, dir);
                _directoryWatchers.Add(fsw);
            }
            catch { }
        }
    }

    private void StopDirectoryWatchers()
    {
        foreach (var w in _directoryWatchers)
        {
            try { w.EnableRaisingEvents = false; w.Dispose(); } catch { }
        }
        _directoryWatchers.Clear();
    }

    private void OnStagedFileDiscovered(string fullPath, string stageDir)
    {
        if (!_isRunning) return;
        _ = Task.Run(async () =>
        {
            await Task.Delay(200); // Give file writer time to flush
            try
            {
                if (!File.Exists(fullPath)) return;
                string fn = Path.GetFileName(fullPath);
                var art = _vault.TryCaptureLocalFile(
                    fullPath, $"/data/local/tmp/{fn}", "StagedDirectoryWatcher", 0, "ALL_DEVICES",
                    new Dictionary<string, string> { ["StageOrigin"] = stageDir });
                if (art != null)
                {
                    RecordCapturedArtifact(art);
                }
            }
            catch { }
        });
    }

    /// <summary>
    /// Tokenizes a command line respecting single and double quotes.
    /// </summary>
    public static List<string> TokenizeCommandLine(string cmdLine)
    {
        var tokens = new List<string>();
        var current = new StringBuilder();
        bool inQuotes = false;
        char quoteChar = '\0';

        for (int i = 0; i < cmdLine.Length; i++)
        {
            char c = cmdLine[i];
            if ((c == '"' || c == '\'') && !inQuotes)
            {
                inQuotes = true;
                quoteChar = c;
            }
            else if (inQuotes && c == quoteChar)
            {
                inQuotes = false;
                quoteChar = '\0';
            }
            else if (!inQuotes && char.IsWhiteSpace(c))
            {
                if (current.Length > 0)
                {
                    tokens.Add(current.ToString());
                    current.Clear();
                }
            }
            else
            {
                current.Append(c);
            }
        }

        if (current.Length > 0)
        {
            tokens.Add(current.ToString());
        }

        return tokens;
    }

    /// <summary>
    /// Simulates capturing a host file push for testing and manual forensics ingestion.
    /// </summary>
    public PushedArtifactInfo? SimulateHostPush(
        string localFilePath,
        string remoteTargetPath,
        string toolName = "GSM_Tool.exe",
        int pid = 1234,
        string serial = "DEVICE001")
    {
        var artifact = _vault.TryCaptureLocalFile(localFilePath, remoteTargetPath, toolName, pid, serial);
        if (artifact != null)
        {
            RecordCapturedArtifact(artifact);
        }
        return artifact;
    }

    /// <summary>
    /// Simulates an in-flight ADB sync stream (SEND -> DATA chunks -> DONE) for testing.
    /// </summary>
    public PushedArtifactInfo? SimulateSyncStream(
        uint channelId,
        string remoteTargetPath,
        byte[] fileBytes,
        string toolName = "GSM_Tool.exe",
        int pid = 1234,
        string serial = "DEVICE001")
    {
        fileBytes ??= [];

        // 1. Build SEND packet: ID_SEND (4B) + PathLen (4B) + "remoteTargetPath,33261"
        string pathAndMode = $"{remoteTargetPath},33261";
        byte[] pathBytes = Encoding.UTF8.GetBytes(pathAndMode);
        byte[] sendPacket = new byte[8 + pathBytes.Length];
        BitConverter.GetBytes(AdbSyncStreamReconstructor.ID_SEND).CopyTo(sendPacket, 0);
        BitConverter.GetBytes((uint)pathBytes.Length).CopyTo(sendPacket, 4);
        pathBytes.CopyTo(sendPacket, 8);

        ProcessSyncWirePayload(channelId, sendPacket, toolName, pid, serial, out _);

        // 2. Build DATA packets (in 16KB chunks)
        int chunkSize = 16 * 1024;
        int offset = 0;
        while (offset < fileBytes.Length)
        {
            int currentLen = Math.Min(chunkSize, fileBytes.Length - offset);
            byte[] dataPacket = new byte[8 + currentLen];
            BitConverter.GetBytes(AdbSyncStreamReconstructor.ID_DATA).CopyTo(dataPacket, 0);
            BitConverter.GetBytes((uint)currentLen).CopyTo(dataPacket, 4);
            Buffer.BlockCopy(fileBytes, offset, dataPacket, 8, currentLen);

            ProcessSyncWirePayload(channelId, dataPacket, toolName, pid, serial, out _);
            offset += currentLen;
        }

        // 3. Build DONE packet: ID_DONE (4B) + mtime (4B)
        byte[] donePacket = new byte[8];
        BitConverter.GetBytes(AdbSyncStreamReconstructor.ID_DONE).CopyTo(donePacket, 0);
        BitConverter.GetBytes((uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds()).CopyTo(donePacket, 4);

        ProcessSyncWirePayload(channelId, donePacket, toolName, pid, serial, out var completedArtifact);
        return completedArtifact;
    }

    private static string FormatBytes(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
        return $"{bytes / (1024.0 * 1024.0):F2} MB";
    }

    public void Dispose()
    {
        Stop();
    }
}
