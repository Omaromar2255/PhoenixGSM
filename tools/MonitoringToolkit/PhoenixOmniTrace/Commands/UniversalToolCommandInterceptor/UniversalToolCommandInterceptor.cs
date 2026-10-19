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
using PhoenixGSM.OmniTrace.Sensors;

namespace PhoenixGSM.OmniTrace.Commands;

/// <summary>
/// Dedicated Multi-Layer GSM Tool Command Interception Engine.
/// Intercepts raw and formatted commands issued by GSM servicing tools and CMD/ADB invocations
/// across WMI, Security Audit 4688, and Fast PEB Delta Polling.
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
            var query = new WqlEventQuery("__InstanceCreationEvent", TimeSpan.FromMilliseconds(150),
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

    #region Engine 3: High-Frequency PEB Process Polling Delta Fallback
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

                            bool isGsm = KnownGsmToolKeywords.Any(k => pNameLower.Contains(k));
                            if (isGsm)
                            {
                                RegisterToolPid(p.Id);
                            }

                            if (!seenPids.Contains(p.Id) && seenPids.Count > 0)
                            {
                                if (IsPotentiallyRelevantUtility(p.ProcessName) || isGsm)
                                {
                                    string exePath = "";
                                    try { exePath = p.MainModule?.FileName ?? ""; } catch { }

                                    // Fast 50-microsecond PEB CommandLine + ParentPID read (with WMI fallback)
                                    string? cmdLine = SmartFilePushArchiver.TryGetProcessCommandLineFast(p.Id, out int parentId);
                                    if (string.IsNullOrWhiteSpace(cmdLine))
                                    {
                                        try
                                        {
                                            using var searcher = new ManagementObjectSearcher(
                                                $"SELECT CommandLine, ParentProcessId FROM Win32_Process WHERE ProcessId = {p.Id}");
                                            foreach (ManagementObject mo in searcher.Get())
                                            {
                                                cmdLine = mo["CommandLine"]?.ToString() ?? exePath;
                                                parentId = Convert.ToInt32(mo["ParentProcessId"]);
                                                break;
                                            }
                                        }
                                        catch { }
                                    }

                                    if (!string.IsNullOrWhiteSpace(cmdLine))
                                    {
                                        ProcessIncomingProcessEvent(p.ProcessName + ".exe", p.Id, parentId, cmdLine, exePath, "DELTA-POLLER", DateTime.UtcNow);
                                    }
                                }
                            }
                        }
                        catch { }
                        finally { p.Dispose(); }
                    }

                    seenPids = currentPids;
                    await Task.Delay(120, token);
                }
                catch (OperationCanceledException) { break; }
                catch { await Task.Delay(500, token); }
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

        string parentName = "System";
        if (!string.IsNullOrEmpty(parentPathOverride))
        {
            parentName = Path.GetFileName(parentPathOverride);
        }
        else if (parentPid > 0)
        {
            try
            {
                using var parent = Process.GetProcessById(parentPid);
                parentName = parent.ProcessName + ".exe";
            }
            catch { }
        }

        bool isExplicitTargetBinary = cleanExe is "adb.exe" or "fastboot.exe";

        // Strict Noise Exclusion (never exclude adb.exe or fastboot.exe even if parent is explorer.exe or cmd.exe!)
        if (!isExplicitTargetBinary &&
            (IsStrictlyExcludedProcess(cleanExe) || IsStrictlyExcludedProcess(exeName) ||
             IsStrictlyExcludedProcess(parentName) || IsStrictlyExcludedProcess(parentPathOverride) ||
             HasNoiseKeywords(exeName) || HasNoiseKeywords(cleanExe) || HasNoiseKeywords(cmdLine) ||
             HasNoiseKeywords(parentName) || HasNoiseKeywords(exePath) || HasNoiseKeywords(parentPathOverride)))
        {
            return;
        }

        string parentLower = parentName.ToLowerInvariant();

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

        if (!parentIsTool && !isExplicitTargetBinary && IsBenignNoiseProcess(cleanExe, cmdLine))
        {
            return;
        }

        if ((cleanExe == "cmd.exe" || cleanExe == "conhost.exe") &&
            (string.IsNullOrWhiteSpace(cmdLine) || cmdLine.Trim().Equals(cleanExe, StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        bool isToolBinary = KnownGsmToolKeywords.Any(k => cleanExe.Contains(k));
        bool isUtility = IsPotentiallyRelevantUtility(cleanExe);
        bool hasDeviceKeywords = HasHardwareOrGsmKeywords(cmdLine);

        if (!parentIsTool && !isToolBinary && !isUtility && !hasDeviceKeywords)
        {
            return;
        }

        string dedupeKey = $"{pid}_{cleanExe}_{cmdLine.Trim()}";
        DateTime now = DateTime.UtcNow;

        if (_recentDeduplicationMap.Count > 100)
        {
            var expired = _recentDeduplicationMap.Where(kv => (now - kv.Value).TotalSeconds > 5).Select(kv => kv.Key).ToList();
            foreach (var k in expired) _recentDeduplicationMap.TryRemove(k, out _);
        }

        if (_recentDeduplicationMap.TryGetValue(dedupeKey, out var prevTime))
        {
            if ((now - prevTime).TotalSeconds < 2.0)
            {
                return;
            }
        }
        _recentDeduplicationMap[dedupeKey] = now;

        var analyzed = AnalyzeCommand(cleanExe, exePath, cmdLine, parentName, parentPid, pid, engine, timestamp);

        if (analyzed.CommandAction == "WMIC QUERY: \"\"" || analyzed.CommandAction == "WMIC QUERY: SUPPRESSED_DUPLICATE")
        {
            return;
        }

        OnCommandCaptured?.Invoke(analyzed);

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
            ParentProcessId = cmd.ParentProcessId,
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
