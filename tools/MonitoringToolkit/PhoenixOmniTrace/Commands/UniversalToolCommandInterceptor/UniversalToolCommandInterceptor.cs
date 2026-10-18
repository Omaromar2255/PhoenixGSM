using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Management;
using System.Threading;
using System.Threading.Tasks;
using PhoenixGSM.OmniTrace.Bus;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.Commands;

/// <summary>
/// Dedicated Multi-Layer GSM Tool Command Interception Engine.
/// Intercepts raw and formatted commands issued by GSM servicing tools (UnlockTool, Chimera, Miracle, DFT Pro, etc.)
/// across all operating execution mechanisms (CMD, PowerShell, Shell, WMIC, DevCon, PnPUtil, CLI binaries, child processes).
/// Guaranteed to function even if USB or COM port detection fails or is delayed.
/// </summary>
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public sealed partial class UniversalToolCommandInterceptor : IDisposable
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
    private static readonly ConcurrentDictionary<string, byte> _seenSessionWmicQueries = new(StringComparer.OrdinalIgnoreCase);
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

    #region Unified Command Ingestion & Dispatch
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

        // Strict Noise Exclusion
        if (IsStrictlyExcludedProcess(cleanExe) || IsStrictlyExcludedProcess(exeName) ||
            IsStrictlyExcludedProcess(parentName) || IsStrictlyExcludedProcess(parentPathOverride) ||
            HasNoiseKeywords(exeName) || HasNoiseKeywords(cleanExe) || HasNoiseKeywords(cmdLine) ||
            HasNoiseKeywords(parentName) || HasNoiseKeywords(exePath) || HasNoiseKeywords(parentPathOverride))
        {
            return;
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

        // Reject empty WMIC query or duplicate BIOS/Baseboard query
        if (analyzed.CommandAction == "WMIC QUERY: \"\"" || analyzed.CommandAction == "WMIC QUERY: SUPPRESSED_DUPLICATE")
        {
            return;
        }

        // Dispatch to internal subscribers
        OnCommandCaptured?.Invoke(analyzed);

        // Dispatch to OmniTrace EventBus if connected
        if (_bus != null)
        {
            DispatchToEventBus(analyzed);
        }
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

    public void Dispose()
    {
        Stop();
        GC.SuppressFinalize(this);
    }
}
