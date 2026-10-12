using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Management;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using PhoenixGSM.OmniTrace.Bus;
using PhoenixGSM.OmniTrace.Decoders;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.Commands;

/// <summary>
/// Detailed metadata for intercepted GSM tool execution commands.
/// </summary>
public sealed class InterceptedToolCommand
{
    public int ProcessId { get; set; }
    public int ParentProcessId { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public string ParentProcessName { get; set; } = string.Empty;
    public string ExecutablePath { get; set; } = string.Empty;
    public string CommandLine { get; set; } = string.Empty;
    public string CommandAction { get; set; } = string.Empty;
    public string FormattedSummary { get; set; } = string.Empty;
    public string TargetOrEndpoint { get; set; } = string.Empty;
    public string SourceTag { get; set; } = "TOOL-CMD";
    public string ProtocolName { get; set; } = "GSM-TOOL";
    public KnownProtocol Protocol { get; set; } = KnownProtocol.HostCommand;
    public string Category { get; set; } = "Process";
    public string? DecodedScript { get; set; }
    public string TechnicalDetails { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string InterceptionEngine { get; set; } = "WMI";
}

/// <summary>
/// Dedicated Multi-Layer GSM Tool Command Interception Engine.
/// Intercepts raw and formatted commands issued by GSM servicing tools (UnlockTool, Chimera, Miracle, DFT Pro, etc.)
/// across all operating execution mechanisms (CMD, PowerShell, Shell, WMIC, DevCon, PnPUtil, CLI binaries, child processes).
/// Guaranteed to function even if USB or COM port detection fails or is delayed.
/// </summary>
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public sealed class UniversalToolCommandInterceptor : IDisposable
{
    private static readonly string[] KnownGsmToolKeywords =
    [
        "unlocktool", "chimera", "miracle", "dftpro", "pandora", "z3x", "octoplus",
        "samfw", "odin", "3utools", "miflash", "qfil", "fastboot", "spflash", "umt",
        "hydra", "easyjtag", "qunlock", "q-unlock", "simunlock", "sk_unlock", "skunlock",
        "globalunlocker", "global_unlocker", "key-tool", "keytool", "athun", "trd",
        "samsung", "skapple", "irecovery", "idevice", "futurerestore", "palera1n",
        "checkra1n", "gaster", "ipwndfu", "libimobiledevice", "applemobiledevice", "cm2",
        "nck", "infinity", "amt", "dft", "tft", "tftunlock", "cheetah", "grt", "hcu",
        "dc-unlocker", "dcunlocker", "sigmakey", "smart-clip", "qcfire", "medusa",
        "ufi", "mrt", "trtools", "halabtech", "xiaomi"
    ];

    private readonly OmniTraceEventBus? _bus;
    private readonly ConcurrentDictionary<string, DateTime> _recentDeduplicationMap = new();
    private readonly HashSet<int> _activeToolPids = [];
    private readonly object _pidLock = new();

    private ManagementEventWatcher? _wmiWatcher;
    private EventLogWatcher? _securityWatcher;
    private CancellationTokenSource? _cts;
    private Task? _hierarchyPollingTask;
    private bool _isRunning;

    public event Action<InterceptedToolCommand>? OnCommandCaptured;

    public UniversalToolCommandInterceptor(OmniTraceEventBus? bus = null)
    {
        _bus = bus;
    }

    public void RegisterToolPid(int pid)
    {
        lock (_pidLock)
        {
            _activeToolPids.Add(pid);
        }
    }

    public void UnregisterToolPid(int pid)
    {
        lock (_pidLock)
        {
            _activeToolPids.Remove(pid);
        }
    }

    public void Start()
    {
        if (_isRunning) return;
        _isRunning = true;
        _cts = new CancellationTokenSource();

        StartWmiProcessWatcher();
        StartSecurityAuditWatcher();
        StartHierarchyPollingLoop(_cts.Token);
    }

    public void Stop()
    {
        if (!_isRunning) return;
        _isRunning = false;
        _cts?.Cancel();

        try
        {
            _wmiWatcher?.Stop();
            _wmiWatcher?.Dispose();
            _wmiWatcher = null;
        }
        catch { }

        try
        {
            _securityWatcher?.Dispose();
            _securityWatcher = null;
        }
        catch { }

        _recentDeduplicationMap.Clear();
    }

    #region Engine 1: WMI Real-Time Process Creation Interceptor
    private void StartWmiProcessWatcher()
    {
        try
        {
            // Universal process creation query with 250ms polling resolution
            var query = new WqlEventQuery("__InstanceCreationEvent", TimeSpan.FromMilliseconds(250),
                "TargetInstance ISA 'Win32_Process'");

            _wmiWatcher = new ManagementEventWatcher(query);
            _wmiWatcher.EventArrived += (s, e) =>
            {
                try
                {
                    if (e.NewEvent["TargetInstance"] is ManagementBaseObject target)
                    {
                        string name = target["Name"]?.ToString() ?? string.Empty;
                        uint pid = Convert.ToUInt32(target["ProcessId"]);
                        uint parentPid = Convert.ToUInt32(target["ParentProcessId"]);
                        string cmdLine = target["CommandLine"]?.ToString() ?? string.Empty;
                        string exePath = target["ExecutablePath"]?.ToString() ?? string.Empty;

                        ProcessIncomingProcessEvent(name, (int)pid, (int)parentPid, cmdLine, exePath, "WMI", DateTime.UtcNow);
                    }
                }
                catch { }
            };
            _wmiWatcher.Start();
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[UniversalToolCommandInterceptor] WMI Start failed: {ex.Message}");
        }
    }
    #endregion

    #region Engine 2: Security Audit 4688 Interceptor
    private void StartSecurityAuditWatcher()
    {
        try
        {
            var query = new EventLogQuery("Security", PathType.LogName, "*[System[(EventID=4688)]]");
            _securityWatcher = new EventLogWatcher(query);
            _securityWatcher.EventRecordWritten += (s, e) =>
            {
                try
                {
                    if (e.EventRecord is not EventRecord record) return;

                    string newProc = record.Properties.Count > 5 ? record.Properties[5].Value?.ToString() ?? "" : "";
                    string cmdLine = record.Properties.Count > 8 ? record.Properties[8].Value?.ToString() ?? "" : "";
                    string parentProc = record.Properties.Count > 13 ? record.Properties[13].Value?.ToString() ?? "" : "";

                    int newPid = 0;
                    if (record.Properties.Count > 4 && record.Properties[4].Value is string pidHex && pidHex.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                    {
                        int.TryParse(pidHex[2..], System.Globalization.NumberStyles.HexNumber, null, out newPid);
                    }

                    int parentPid = 0;
                    if (record.Properties.Count > 7 && record.Properties[7].Value is string pPidHex && pPidHex.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                    {
                        int.TryParse(pPidHex[2..], System.Globalization.NumberStyles.HexNumber, null, out parentPid);
                    }

                    if (string.IsNullOrWhiteSpace(newProc)) return;

                    string exeName = Path.GetFileName(newProc);
                    DateTime time = record.TimeCreated ?? DateTime.UtcNow;

                    ProcessIncomingProcessEvent(exeName, newPid, parentPid, cmdLine, newProc, "AUDIT-4688", time, parentProc);
                }
                catch { }
            };
            _securityWatcher.Enabled = true;
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[UniversalToolCommandInterceptor] Security Audit 4688 start failed: {ex.Message}");
        }
    }
    #endregion

    #region Engine 3: High-Frequency Process Polling Delta Fallback
    private void StartHierarchyPollingLoop(CancellationToken token)
    {
        _hierarchyPollingTask = Task.Run(async () =>
        {
            var seenPids = new HashSet<int>();
            while (!token.IsCancellationRequested)
            {
                try
                {
                    var procs = Process.GetProcesses();
                    var currentPids = new HashSet<int>();

                    foreach (var p in procs)
                    {
                        try
                        {
                            currentPids.Add(p.Id);
                            string pNameLower = p.ProcessName.ToLowerInvariant();

                            // Track running GSM tools
                            bool isGsm = KnownGsmToolKeywords.Any(k => pNameLower.Contains(k));
                            if (isGsm)
                            {
                                RegisterToolPid(p.Id);
                            }

                            // If new process appeared
                            if (!seenPids.Contains(p.Id) && seenPids.Count > 0)
                            {
                                string exePath = "";
                                try { exePath = p.MainModule?.FileName ?? ""; } catch { }

                                // Quick inspect if relevant utility or GSM child
                                if (IsPotentiallyRelevantUtility(p.ProcessName) || isGsm)
                                {
                                    // Try reading command line via WMI if needed
                                    string cmdLine = exePath;
                                    try
                                    {
                                        using var searcher = new ManagementObjectSearcher(
                                            $"SELECT CommandLine, ParentProcessId FROM Win32_Process WHERE ProcessId = {p.Id}");
                                        foreach (ManagementObject mo in searcher.Get())
                                        {
                                            cmdLine = mo["CommandLine"]?.ToString() ?? exePath;
                                            int parentId = Convert.ToInt32(mo["ParentProcessId"]);
                                            ProcessIncomingProcessEvent(p.ProcessName + ".exe", p.Id, parentId, cmdLine, exePath, "DELTA-POLLER", DateTime.UtcNow);
                                            break;
                                        }
                                    }
                                    catch { }
                                }
                            }
                        }
                        catch { }
                    }

                    seenPids = currentPids;
                    await Task.Delay(400, token);
                }
                catch (OperationCanceledException) { break; }
                catch { await Task.Delay(1000, token); }
            }
        }, token);
    }
    #endregion

    #region Unified Command Ingestion & Analysis
    public void ProcessIncomingProcessEvent(
        string exeName,
        int pid,
        int parentPid,
        string cmdLine,
        string exePath,
        string engine,
        DateTime timestamp,
        string parentPathOverride = "")
    {
        if (string.IsNullOrWhiteSpace(exeName)) return;

        string cleanExe = Path.GetFileName(exeName).ToLowerInvariant();
        if (!cleanExe.EndsWith(".exe") && !cleanExe.Contains('.')) cleanExe += ".exe";

        // Resolve parent name
        string parentName = "System";
        if (!string.IsNullOrEmpty(parentPathOverride))
        {
            parentName = Path.GetFileName(parentPathOverride);
        }
        else if (parentPid > 0)
        {
            try
            {
                var parent = Process.GetProcessById(parentPid);
                parentName = parent.ProcessName + ".exe";
            }
            catch { }
        }

        string parentLower = parentName.ToLowerInvariant();

        // Check if parent is a known GSM tool
        bool parentIsTool = false;
        lock (_pidLock)
        {
            if (_activeToolPids.Contains(parentPid)) parentIsTool = true;
        }
        if (!parentIsTool)
        {
            parentIsTool = KnownGsmToolKeywords.Any(k => parentLower.Contains(k));
            if (parentIsTool && parentPid > 0) RegisterToolPid(parentPid);
        }

        // Noise suppression: drop non-relevant background Windows processes
        if (!parentIsTool && IsBenignNoiseProcess(cleanExe, cmdLine))
        {
            return;
        }

        // Filter out empty bare cmd.exe / conhost with no parameters
        if ((cleanExe == "cmd.exe" || cleanExe == "conhost.exe") &&
            (string.IsNullOrWhiteSpace(cmdLine) || cmdLine.Trim().Equals(cleanExe, StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        // Check relevance
        bool isToolBinary = KnownGsmToolKeywords.Any(k => cleanExe.Contains(k));
        bool isUtility = IsPotentiallyRelevantUtility(cleanExe);
        bool hasDeviceKeywords = HasHardwareOrGsmKeywords(cmdLine);

        if (!parentIsTool && !isToolBinary && !isUtility && !hasDeviceKeywords)
        {
            return;
        }

        // Deduplication using sliding window (3 seconds)
        string dedupeKey = $"{pid}_{cleanExe}_{cmdLine.Trim()}";
        DateTime now = DateTime.UtcNow;

        // Clean expired deduplication entries older than 5 seconds
        if (_recentDeduplicationMap.Count > 100)
        {
            var expired = _recentDeduplicationMap.Where(kv => (now - kv.Value).TotalSeconds > 5).Select(kv => kv.Key).ToList();
            foreach (var k in expired) _recentDeduplicationMap.TryRemove(k, out _);
        }

        if (_recentDeduplicationMap.TryGetValue(dedupeKey, out var prevTime))
        {
            if ((now - prevTime).TotalSeconds < 3.0)
            {
                return; // Duplicate
            }
        }
        _recentDeduplicationMap[dedupeKey] = now;

        // Perform deep domain analysis of the command
        var analyzed = AnalyzeCommand(cleanExe, exePath, cmdLine, parentName, parentPid, pid, engine, timestamp);

        // Dispatch to internal subscribers
        OnCommandCaptured?.Invoke(analyzed);

        // Dispatch to OmniTrace EventBus if connected
        if (_bus != null)
        {
            DispatchToEventBus(analyzed);
        }
    }

    public static InterceptedToolCommand AnalyzeCommand(
        string cleanExe,
        string exePath,
        string cmdLine,
        string parentName,
        int parentPid,
        int pid,
        string engine,
        DateTime timestamp)
    {
        string trimmedCmd = (cmdLine ?? string.Empty).Trim();
        var item = new InterceptedToolCommand
        {
            ProcessId = pid,
            ParentProcessId = parentPid,
            ProcessName = cleanExe,
            ParentProcessName = parentName,
            ExecutablePath = exePath,
            CommandLine = trimmedCmd,
            Timestamp = timestamp,
            InterceptionEngine = engine
        };

        // ══════════════════════════════════════════════════════════════════════
        // CASE 1: libusb-win32 / WinUSB Filter Driver Commands (filter-x64, etc.)
        // ══════════════════════════════════════════════════════════════════════
        if (cleanExe.Contains("filter-") || cleanExe.Contains("install-filter") || trimmedCmd.Contains("filter-x64") || trimmedCmd.Contains("filter-x86"))
        {
            string action = trimmedCmd.Contains("remove", StringComparison.OrdinalIgnoreCase) || trimmedCmd.Contains("uninstall", StringComparison.OrdinalIgnoreCase)
                ? "UNINSTALL"
                : "INSTALL";

            string devMatch = ExtractDevicePattern(trimmedCmd);

            if (trimmedCmd.Contains("VID_0E8D", StringComparison.OrdinalIgnoreCase))
            {
                item.Category = "MediaTek";
                item.Protocol = KnownProtocol.MtkBrom;
                item.ProtocolName = "LIBUSB-FILTER";
                item.SourceTag = "MTK-FILTER";
                item.CommandAction = $"FILTER {action}: {devMatch} (MTK BROM/PRELOADER)";
                item.TargetOrEndpoint = devMatch;
            }
            else if (trimmedCmd.Contains("VID_05C6", StringComparison.OrdinalIgnoreCase) || trimmedCmd.Contains("9008", StringComparison.OrdinalIgnoreCase))
            {
                item.Category = "QualcommEdl";
                item.Protocol = KnownProtocol.QualcommSahara;
                item.ProtocolName = "LIBUSB-FILTER";
                item.SourceTag = "QCOM-FILTER";
                item.CommandAction = $"FILTER {action}: {devMatch} (QUALCOMM EDL 9008)";
                item.TargetOrEndpoint = devMatch;
            }
            else if (trimmedCmd.Contains("VID_1782", StringComparison.OrdinalIgnoreCase))
            {
                item.Category = "UnisocSpd";
                item.Protocol = KnownProtocol.SpreadtrumFdl;
                item.ProtocolName = "LIBUSB-FILTER";
                item.SourceTag = "SPD-FILTER";
                item.CommandAction = $"FILTER {action}: {devMatch} (SPD DIAG/FDL)";
                item.TargetOrEndpoint = devMatch;
            }
            else
            {
                item.Category = "Process";
                item.Protocol = KnownProtocol.HostCommand;
                item.ProtocolName = "LIBUSB-FILTER";
                item.SourceTag = "USB-FILTER";
                item.CommandAction = $"FILTER {action}: {devMatch}".Trim();
                item.TargetOrEndpoint = devMatch;
            }

            item.FormattedSummary = $"[{parentName}] {cleanExe} {trimmedCmd}";
            item.TechnicalDetails = $"Kernel Filter Driver Modification\nBinary: {exePath}\nAction: {action} Filter\nDevice Target: {devMatch}\nCaller: {parentName} (PID {parentPid})";
            return item;
        }

        // ══════════════════════════════════════════════════════════════════════
        // CASE 2: WMIC Queries (Hardware discovery before/during port wait)
        // ══════════════════════════════════════════════════════════════════════
        if (cleanExe.Equals("wmic.exe", StringComparison.OrdinalIgnoreCase) || trimmedCmd.StartsWith("wmic", StringComparison.OrdinalIgnoreCase))
        {
            item.Protocol = KnownProtocol.HostCommand;
            item.ProtocolName = "WMIC";
            item.SourceTag = "WMIC-QUERY";

            if (trimmedCmd.Contains("Win32_PnPEntity", StringComparison.OrdinalIgnoreCase))
            {
                if (trimmedCmd.Contains("VID_0E8D", StringComparison.OrdinalIgnoreCase))
                {
                    item.Category = "MediaTek";
                    item.CommandAction = "WMIC QUERY: PNP (VID_0E8D MTK)";
                }
                else if (trimmedCmd.Contains("VID_05C6", StringComparison.OrdinalIgnoreCase) || trimmedCmd.Contains("9008", StringComparison.OrdinalIgnoreCase))
                {
                    item.Category = "QualcommEdl";
                    item.CommandAction = "WMIC QUERY: PNP (VID_05C6 QCOM 9008)";
                }
                else if (trimmedCmd.Contains("VID_1782", StringComparison.OrdinalIgnoreCase))
                {
                    item.Category = "UnisocSpd";
                    item.CommandAction = "WMIC QUERY: PNP (VID_1782 SPD)";
                }
                else
                {
                    item.Category = "Cmd";
                    item.CommandAction = "WMIC QUERY: WIN32_PNPENTITY";
                }
                item.TargetOrEndpoint = "Win32_PnPEntity";
            }
            else if (trimmedCmd.Contains("Win32_SerialPort", StringComparison.OrdinalIgnoreCase))
            {
                item.Category = "Cmd";
                item.CommandAction = "WMIC QUERY: SERIAL/COM PORTS";
                item.TargetOrEndpoint = "Win32_SerialPort";
            }
            else
            {
                item.Category = "Cmd";
                item.CommandAction = "WMIC QUERY: " + ExtractWmicClass(trimmedCmd);
                item.TargetOrEndpoint = "WMI";
            }

            item.FormattedSummary = $"[{parentName}] {trimmedCmd}";
            item.TechnicalDetails = $"WMI Query Execution\nQuery: {trimmedCmd}\nCaller: {parentName} (PID {parentPid})";
            return item;
        }

        // ══════════════════════════════════════════════════════════════════════
        // CASE 3: DevCon / PnPUtil / DPInst (Driver & Port Enumeration)
        // ══════════════════════════════════════════════════════════════════════
        if (cleanExe.Equals("devcon.exe", StringComparison.OrdinalIgnoreCase) ||
            cleanExe.Equals("pnputil.exe", StringComparison.OrdinalIgnoreCase) ||
            cleanExe.Equals("dpinst.exe", StringComparison.OrdinalIgnoreCase))
        {
            string util = cleanExe.Replace(".exe", "").ToUpperInvariant();
            item.Protocol = KnownProtocol.HostCommand;
            item.ProtocolName = $"{util}-CLI";
            item.SourceTag = util;

            if (trimmedCmd.Contains("VID_0E8D", StringComparison.OrdinalIgnoreCase))
            {
                item.Category = "MediaTek";
                item.CommandAction = $"{util}: STATUS USB\\VID_0E8D* (MTK)";
            }
            else if (trimmedCmd.Contains("VID_05C6", StringComparison.OrdinalIgnoreCase) || trimmedCmd.Contains("9008", StringComparison.OrdinalIgnoreCase))
            {
                item.Category = "QualcommEdl";
                item.CommandAction = $"{util}: STATUS USB\\VID_05C6* (QCOM)";
            }
            else if (trimmedCmd.Contains("VID_1782", StringComparison.OrdinalIgnoreCase))
            {
                item.Category = "UnisocSpd";
                item.CommandAction = $"{util}: STATUS USB\\VID_1782* (SPD)";
            }
            else
            {
                item.Category = "Cmd";
                var parts = trimmedCmd.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                string sub = parts.Length > 1 ? parts[1].ToUpperInvariant() : "EXEC";
                string arg = parts.Length > 2 ? parts[2].ToUpperInvariant() : "";
                item.CommandAction = $"{util} {sub} {arg}".Trim();
            }

            item.TargetOrEndpoint = util;
            item.FormattedSummary = $"[{parentName}] {trimmedCmd}";
            item.TechnicalDetails = $"Hardware PnP / Driver Utility Execution\nCommand: {trimmedCmd}\nCaller: {parentName} (PID {parentPid})";
            return item;
        }

        // ══════════════════════════════════════════════════════════════════════
        // CASE 4: Fastboot CLI Executions
        // ══════════════════════════════════════════════════════════════════════
        if (cleanExe.Equals("fastboot.exe", StringComparison.OrdinalIgnoreCase))
        {
            item.Category = "AdbProxy";
            item.Protocol = KnownProtocol.Fastboot;
            item.ProtocolName = "FASTBOOT-CLI";
            item.SourceTag = "FASTBOOT";
            item.TargetOrEndpoint = "FASTBOOT";

            string subcmd = ExtractFastbootSubcommand(trimmedCmd);
            item.CommandAction = "FASTBOOT " + subcmd.ToUpperInvariant();
            item.FormattedSummary = $"[{parentName}] fastboot {subcmd}";
            item.TechnicalDetails = $"Android Fastboot Bootloader Command\nArguments: {trimmedCmd}\nCaller: {parentName} (PID {parentPid})";
            return item;
        }

        // ══════════════════════════════════════════════════════════════════════
        // CASE 5: ADB CLI Executions
        // ══════════════════════════════════════════════════════════════════════
        if (cleanExe.Equals("adb.exe", StringComparison.OrdinalIgnoreCase))
        {
            item.Category = "AdbProxy";
            item.Protocol = KnownProtocol.ADB;
            item.ProtocolName = "ADB-CLI";
            item.SourceTag = "ADB-CMD";
            item.TargetOrEndpoint = "ADB";

            string subcmd = ExtractAdbSubcommand(trimmedCmd);
            item.CommandAction = "ADB " + subcmd.ToUpperInvariant();
            item.FormattedSummary = $"[{parentName}] adb {subcmd}";
            item.TechnicalDetails = $"Android Debug Bridge Host Invocation\nCommandLine: {trimmedCmd}\nCaller: {parentName} (PID {parentPid})";
            return item;
        }

        // ══════════════════════════════════════════════════════════════════════
        // CASE 6: PowerShell Executions & Encoded Commands
        // ══════════════════════════════════════════════════════════════════════
        if (cleanExe.Contains("powershell") || cleanExe.Contains("pwsh"))
        {
            item.Category = "Shell";
            item.Protocol = KnownProtocol.HostCommand;
            item.ProtocolName = "POWERSHELL";
            item.SourceTag = "POWERSHELL";
            item.TargetOrEndpoint = "POWERSHELL";

            var parsed = ShellCommandParser.ParseShellExecution(cleanExe, trimmedCmd);
            item.DecodedScript = parsed.DecodedScript;
            item.CommandAction = parsed.Subcommand;
            item.FormattedSummary = $"[{parentName}] {parsed.NormalizedCommand}";
            item.TechnicalDetails = $"PowerShell Execution\nRaw CommandLine: {trimmedCmd}\nDecoded Script: {parsed.DecodedScript ?? "N/A"}\nCaller: {parentName} (PID {parentPid})";
            return item;
        }

        // ══════════════════════════════════════════════════════════════════════
        // CASE 7: CMD.EXE Wrapper Executions (Unwrap cmd.exe /c ...)
        // ══════════════════════════════════════════════════════════════════════
        if (cleanExe.Equals("cmd.exe", StringComparison.OrdinalIgnoreCase))
        {
            int cIdx = trimmedCmd.IndexOf("/c ", StringComparison.OrdinalIgnoreCase);
            if (cIdx < 0) cIdx = trimmedCmd.IndexOf("/k ", StringComparison.OrdinalIgnoreCase);

            if (cIdx >= 0 && cIdx + 3 < trimmedCmd.Length)
            {
                string inner = trimmedCmd[(cIdx + 3)..].Trim(' ', '"', '\'');
                var innerTokens = inner.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                string innerExe = innerTokens.Length > 0 ? Path.GetFileName(innerTokens[0]).ToLowerInvariant() : "cmd";

                // Re-evaluate inner command through analyzer
                var nested = AnalyzeCommand(innerExe, innerExe, inner, parentName, parentPid, pid, engine, timestamp);
                nested.SourceTag = "CMD-EXEC";
                nested.FormattedSummary = $"[{parentName}] cmd.exe /c {inner}";
                return nested;
            }

            item.Category = "Cmd";
            item.Protocol = KnownProtocol.HostCommand;
            item.ProtocolName = "HOST-CMD";
            item.SourceTag = "CMD-HOST";
            item.CommandAction = "CMD: " + trimmedCmd;
            item.TargetOrEndpoint = parentName;
            item.FormattedSummary = $"[{parentName}] {trimmedCmd}";
            item.TechnicalDetails = $"Command Prompt Execution\nCommandLine: {trimmedCmd}\nCaller: {parentName} (PID {parentPid})";
            return item;
        }

        // ══════════════════════════════════════════════════════════════════════
        // CASE 8: Apple iOS Utilities (irecovery, ideviceinfo, iproxy, etc.)
        // ══════════════════════════════════════════════════════════════════════
        if (cleanExe.Contains("iproxy") || cleanExe.StartsWith("idevice") || cleanExe.StartsWith("irecovery") ||
            cleanExe.Contains("futurerestore") || cleanExe.Contains("palera1n") || cleanExe.Contains("checkra1n") ||
            cleanExe.Contains("gaster") || cleanExe.Contains("ipwndfu"))
        {
            item.Category = "AppleIos";
            item.Protocol = cleanExe.Contains("iproxy") ? KnownProtocol.AppleRamdiskSsh :
                            cleanExe.Contains("irecovery") ? KnownProtocol.AppleRecovery : KnownProtocol.AppleLockdown;
            item.ProtocolName = "APPLE-CLI";
            item.SourceTag = cleanExe.Contains("irecovery") ? "APPLE-REC" : (cleanExe.Contains("iproxy") ? "APPLE-SSH" : "APPLE-CLI");
            item.TargetOrEndpoint = Path.GetFileNameWithoutExtension(cleanExe).ToUpperInvariant();
            item.CommandAction = $"APPLE: {Path.GetFileNameWithoutExtension(cleanExe).ToUpperInvariant()}";
            item.FormattedSummary = $"[{parentName}] {cleanExe} {trimmedCmd}";
            item.TechnicalDetails = $"Apple iOS Service Execution\nBinary: {exePath}\nArgs: {trimmedCmd}\nCaller: {parentName} (PID {parentPid})";
            return item;
        }

        // ══════════════════════════════════════════════════════════════════════
        // CASE 9: Chipset Flashing Binaries (MTK, Qualcomm EDL, SPD, Samsung)
        // ══════════════════════════════════════════════════════════════════════
        if (cleanExe.Contains("fh_loader") || cleanExe.Contains("emmcdl") || cleanExe.Contains("qsahara") || cleanExe.Contains("qfil") || cleanExe.Contains("edl"))
        {
            item.Category = "QualcommEdl";
            item.Protocol = KnownProtocol.QualcommFirehose;
            item.ProtocolName = "FIREHOSE-CLI";
            item.SourceTag = "QCOM-EDL";
            item.TargetOrEndpoint = "EDL 9008";
            item.CommandAction = $"{Path.GetFileNameWithoutExtension(cleanExe).ToUpperInvariant()}: {ExtractShortArgs(trimmedCmd)}";
            item.FormattedSummary = $"[{parentName}] {cleanExe} {trimmedCmd}";
            item.TechnicalDetails = $"Qualcomm EDL Flasher Execution\nBinary: {exePath}\nArgs: {trimmedCmd}\nCaller: {parentName} (PID {parentPid})";
            return item;
        }

        if (cleanExe.Contains("sp_flash_tool") || cleanExe.Contains("flashtool") || cleanExe.Contains("brom") || cleanExe.Contains("mtk"))
        {
            item.Category = "MediaTek";
            item.Protocol = KnownProtocol.MtkBrom;
            item.ProtocolName = "MTK-CLI";
            item.SourceTag = "MTK-TOOL";
            item.TargetOrEndpoint = "MTK BROM/DA";
            item.CommandAction = $"{Path.GetFileNameWithoutExtension(cleanExe).ToUpperInvariant()}: {ExtractShortArgs(trimmedCmd)}";
            item.FormattedSummary = $"[{parentName}] {cleanExe} {trimmedCmd}";
            item.TechnicalDetails = $"MediaTek Flash Utility Execution\nBinary: {exePath}\nArgs: {trimmedCmd}\nCaller: {parentName} (PID {parentPid})";
            return item;
        }

        if (cleanExe.Contains("researchdownload") || cleanExe.Contains("upgradedownload") || cleanExe.Contains("fdl") || cleanExe.Contains("spd"))
        {
            item.Category = "UnisocSpd";
            item.Protocol = KnownProtocol.SpreadtrumFdl;
            item.ProtocolName = "SPD-CLI";
            item.SourceTag = "SPD-TOOL";
            item.TargetOrEndpoint = "SPD DIAG";
            item.CommandAction = $"{Path.GetFileNameWithoutExtension(cleanExe).ToUpperInvariant()}: {ExtractShortArgs(trimmedCmd)}";
            item.FormattedSummary = $"[{parentName}] {cleanExe} {trimmedCmd}";
            item.TechnicalDetails = $"Unisoc/Spreadtrum Flash Tool Execution\nBinary: {exePath}\nArgs: {trimmedCmd}\nCaller: {parentName} (PID {parentPid})";
            return item;
        }

        // ══════════════════════════════════════════════════════════════════════
        // CASE 10: General Tool Sub-Process / CLI Execution
        // ══════════════════════════════════════════════════════════════════════
        item.Category = "Process";
        item.Protocol = KnownProtocol.HostCommand;
        item.ProtocolName = "GSM-TOOL";
        item.SourceTag = "TOOL-CMD";
        item.TargetOrEndpoint = parentName;

        string shortSub = ExtractShortArgs(trimmedCmd);
        item.CommandAction = $"{Path.GetFileNameWithoutExtension(cleanExe).ToUpperInvariant()}: {shortSub}".Trim(':', ' ');
        item.FormattedSummary = $"[{parentName}] {cleanExe} {trimmedCmd}";
        item.TechnicalDetails = $"GSM Tool Sub-Process Command\nBinary: {exePath}\nCommandLine: {trimmedCmd}\nCaller: {parentName} (PID {parentPid})";

        return item;
    }

    private void DispatchToEventBus(InterceptedToolCommand cmd)
    {
        if (_bus == null) return;

        var logicalCmd = new LogicalCommandEvent
        {
            Command = cmd.CommandAction,
            Protocol = cmd.Protocol,
            Service = cmd.ProcessName,
            Transport = TransportType.BULK,
            DeviceIdentity = cmd.TargetOrEndpoint,
            SessionIdentity = cmd.ProcessName,
            Direction = PacketDirection.HOST_TO_DEVICE,
            Confidence = 0.98,
            Timestamp = cmd.Timestamp
        };

        logicalCmd.Details["CommandLine"] = cmd.CommandLine;
        logicalCmd.Details["ExecutablePath"] = cmd.ExecutablePath;
        logicalCmd.Details["Caller"] = cmd.ParentProcessName;
        logicalCmd.Details["PID"] = cmd.ProcessId.ToString();
        logicalCmd.Details["ParentPID"] = cmd.ParentProcessId.ToString();
        logicalCmd.Details["SourceTag"] = cmd.SourceTag;
        logicalCmd.Details["ProtocolName"] = cmd.ProtocolName;
        logicalCmd.Details["Category"] = cmd.Category;
        logicalCmd.Details["Summary"] = cmd.FormattedSummary;
        logicalCmd.Details["TechnicalDetails"] = cmd.TechnicalDetails;

        if (!string.IsNullOrEmpty(cmd.DecodedScript))
        {
            logicalCmd.Details["DecodedScript"] = cmd.DecodedScript;
        }

        _bus.Correlation.RegisterProcess(new Models.ProcessAttributionMetadata
        {
            ProcessId = cmd.ProcessId,
            ImageName = cmd.ProcessName,
            CommandLine = cmd.CommandLine
        });

        _bus.ReportLogicalCommand(logicalCmd);
    }
    #endregion

    #region Helper Parsers
    private static string ExtractDevicePattern(string cmdLine)
    {
        var match = Regex.Match(cmdLine, @"(?:--device=|device=)?(USB\\[A-Za-z0-9_&]+)", RegexOptions.IgnoreCase);
        if (match.Success) return match.Groups[1].Value;

        var vidMatch = Regex.Match(cmdLine, @"VID_[A-Za-z0-9]+(?:&PID_[A-Za-z0-9]+)?", RegexOptions.IgnoreCase);
        if (vidMatch.Success) return vidMatch.Value;

        return "USB Device";
    }

    private static string ExtractWmicClass(string cmdLine)
    {
        var parts = cmdLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        int pathIdx = Array.FindIndex(parts, p => p.Equals("path", StringComparison.OrdinalIgnoreCase));
        if (pathIdx >= 0 && pathIdx + 1 < parts.Length)
        {
            return parts[pathIdx + 1].ToUpperInvariant();
        }
        return parts.Length > 1 ? parts[1].ToUpperInvariant() : "QUERY";
    }

    private static string ExtractFastbootSubcommand(string cmdLine)
    {
        var tokens = cmdLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        int fbIdx = Array.FindIndex(tokens, t => t.EndsWith("fastboot.exe", StringComparison.OrdinalIgnoreCase) || t.Equals("fastboot", StringComparison.OrdinalIgnoreCase));
        if (fbIdx >= 0 && fbIdx + 1 < tokens.Length)
        {
            return string.Join(" ", tokens.Skip(fbIdx + 1));
        }
        return tokens.Length > 1 ? string.Join(" ", tokens.Skip(1)) : "FASTBOOT";
    }

    private static string ExtractAdbSubcommand(string cmdLine)
    {
        var tokens = cmdLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        int adbIdx = Array.FindIndex(tokens, t => t.EndsWith("adb.exe", StringComparison.OrdinalIgnoreCase) || t.Equals("adb", StringComparison.OrdinalIgnoreCase));
        if (adbIdx >= 0 && adbIdx + 1 < tokens.Length)
        {
            return string.Join(" ", tokens.Skip(adbIdx + 1));
        }
        return tokens.Length > 1 ? string.Join(" ", tokens.Skip(1)) : "ADB";
    }

    private static string ExtractShortArgs(string cmdLine)
    {
        var tokens = cmdLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (tokens.Length <= 1) return string.Empty;
        var args = tokens.Skip(1);
        return string.Join(" ", args);
    }

    private static bool IsPotentiallyRelevantUtility(string exeName)
    {
        string lower = exeName.ToLowerInvariant();
        return lower.Contains("filter-") ||
               lower.Contains("devcon") ||
               lower.Contains("pnputil") ||
               lower.Contains("dpinst") ||
               lower.Contains("wmic") ||
               lower.Contains("fastboot") ||
               lower.Contains("adb") ||
               lower.Contains("cmd.exe") ||
               lower.Contains("powershell") ||
               lower.Contains("pwsh") ||
               lower.Contains("curl") ||
               lower.Contains("certutil") ||
               lower.Contains("bitsadmin") ||
               lower.Contains("sc.exe") ||
               lower.Contains("net.exe") ||
               lower.Contains("reg.exe") ||
               lower.Contains("tar.exe") ||
               lower.Contains("7z.exe") ||
               lower.Contains("flashtool") ||
               lower.Contains("fh_loader") ||
               lower.Contains("emmcdl") ||
               lower.Contains("researchdownload") ||
               lower.Contains("upgradedownload") ||
               lower.Contains("irecovery") ||
               lower.Contains("idevice") ||
               lower.Contains("iproxy");
    }

    private static bool HasHardwareOrGsmKeywords(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return false;
        string t = text.ToLowerInvariant();
        return t.Contains("vid_") || t.Contains("pid_") || t.Contains("usb\\") ||
               t.Contains("9008") || t.Contains("brom") || t.Contains("preloader") ||
               t.Contains("scatter") || t.Contains("edl") || t.Contains("sahara") ||
               t.Contains("firehose") || t.Contains("fdl") || t.Contains("da") ||
               t.Contains("flash") || t.Contains("erase") || t.Contains("install --device") ||
               t.Contains("class ports") || t.Contains("serialcomm") || t.Contains("getvar");
    }

    private static bool IsBenignNoiseProcess(string cleanExe, string cmdLine)
    {
        string l = cleanExe.ToLowerInvariant();
        if (l == "svchost.exe" ||
            l == "taskhostw.exe" ||
            l == "searchhost.exe" ||
            l == "startmenuexperiencehost.exe" ||
            l == "shellexperiencehost.exe" ||
            l == "runtimebroker.exe" ||
            l == "sihost.exe" ||
            l == "ctfmon.exe" ||
            l == "fontdrvhost.exe" ||
            l == "backgroundtaskhost.exe" ||
            l == "wmiprvse.exe" ||
            l == "systemsettings.exe" ||
            l == "applicationframehost.exe" ||
            l == "smartscreen.exe" ||
            l == "securityhealthservice.exe")
        {
            return true;
        }

        if (cmdLine.Contains("--type=renderer", StringComparison.OrdinalIgnoreCase) ||
            cmdLine.Contains("--type=gpu-process", StringComparison.OrdinalIgnoreCase) ||
            cmdLine.Contains("--type=utility", StringComparison.OrdinalIgnoreCase) ||
            cmdLine.Contains("--type=crashpad", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return false;
    }
    #endregion

    public void Dispose()
    {
        Stop();
        GC.SuppressFinalize(this);
    }
}
