using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Management;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using PhoenixGSM.MonitoringStudio.Models;

namespace PhoenixGSM.MonitoringStudio.Services;

public partial class MonitoringEngine
{
    private static readonly string[] KnownGsmTools =
    [
        "z3x", "octoplus", "chimera", "samfw", "odin", "3utools",
        "miflash", "qfil", "fastboot", "spflash", "umt", "hydra",
        "miracle", "unlocktool", "pandora", "dftpro", "easyjtag",
        "qunlock", "q-unlock", "simunlock", "sk_unlock", "skunlock",
        "globalunlocker", "global_unlocker", "key-tool", "keytool",
        "athun", "trd", "samsung", "skapple", "irecovery", "idevice",
        "futurerestore", "palera1n", "checkra1n", "gaster", "ipwndfu",
        "libimobiledevice", "applemobiledevice", "itunes", "iproxy", "plink"
    ];

    private static readonly System.Text.RegularExpressions.Regex CliUrlRegex = new(
        @"https?://[a-zA-Z0-9\-\._~:/\?#\[\]@!\$&'\(\)\*\+,;=%]+",
        System.Text.RegularExpressions.RegexOptions.Compiled | System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    private void CheckAndEmitUrls(string cmdLine, string exePath, string parentPath, DateTime timestamp)
    {
        if (!IsUrlMonitoringEnabled) return;
        if (string.IsNullOrWhiteSpace(cmdLine)) return;

        var matches = CliUrlRegex.Matches(cmdLine);
        if (matches.Count == 0) return;

        string exeName = Path.GetFileName(exePath);
        string parentName = Path.GetFileName(parentPath);

        foreach (System.Text.RegularExpressions.Match match in matches)
        {
            string rawUrl = match.Value.Trim(' ', '"', '\'', '<', '>', ';', ',', '`', '(', ')', '[', ']');
            while (rawUrl.EndsWith('.') || rawUrl.EndsWith(',')) rawUrl = rawUrl[..^1];

            if (!Uri.TryCreate(rawUrl, UriKind.Absolute, out var uri)) continue;

            string fileName = Path.GetFileName(uri.LocalPath.Split('?')[0]);
            string cmdText = string.IsNullOrWhiteSpace(fileName) ? "DOWNLOAD LINK" : $"DOWNLOAD: {fileName}";
            string caller = !string.IsNullOrWhiteSpace(parentName) ? parentName : exeName;

            EmitEvent(new LiveEventItem
            {
                Timestamp = timestamp,
                Category = EventSourceCategory.NetworkUrl,
                SourceTag = "CLI-URL",
                Direction = "WEB",
                EndpointOrTarget = uri.Host,
                Protocol = uri.Scheme.ToUpperInvariant(),
                Command = cmdText,
                Summary = $"[{caller}] {rawUrl}",
                RawPayload = Encoding.UTF8.GetBytes(rawUrl),
                PayloadAscii = $"Captured Download Link from CLI:\nURL: {rawUrl}\nHost: {uri.Host}\nPath: {uri.PathAndQuery}\nCaller: {caller}\nProcess: {exeName}\nCommandLine: {cmdLine}\nTime: {timestamp:O}",
                PayloadHex = LiveEventItem.FormatHexDump(Encoding.UTF8.GetBytes(rawUrl)),
                AdditionalDetails = $"Captured from Command-Line / Subprocess execution:\nCaller: {caller}\nExecuted Binary: {exePath}\nCommandLine: {cmdLine}\nTarget URL: {rawUrl}"
            });
        }
    }

    #region Real-Time Universal Tool Command Interception & Fail-Open Layer
    private void StartProcessTraceWatcher()
    {
        // If OmniTrace service is running, UniversalToolCommandInterceptor is already active across WMI, Audit 4688, and Delta Poller.
        // If OmniTrace service is null, launch standalone UniversalToolCommandInterceptor as a fail-open fallback.
        if (_omniService?.UniversalToolInterceptor != null)
        {
            return;
        }

        try
        {
            _fallbackToolInterceptor = new PhoenixGSM.OmniTrace.Commands.UniversalToolCommandInterceptor();
            _fallbackToolInterceptor.OnCommandCaptured += HandleFallbackCommandCaptured;
            _fallbackToolInterceptor.Start();
        }
        catch { }
    }

    private void StartSecurityAuditWatcher()
    {
        // Unifiedly managed inside UniversalToolCommandInterceptor (Engine 2: Security Audit 4688)
    }

    private void HandleFallbackCommandCaptured(PhoenixGSM.OmniTrace.Commands.InterceptedToolCommand cmd)
    {
        var category = Enum.TryParse<EventSourceCategory>(cmd.Category, true, out var cat) ? cat : EventSourceCategory.Process;
        byte[] payloadBytes = Encoding.UTF8.GetBytes(cmd.CommandLine);

        CheckAndEmitUrls(cmd.CommandLine, cmd.ExecutablePath, cmd.ParentProcessName, cmd.Timestamp);

        EmitEvent(new LiveEventItem
        {
            Timestamp = cmd.Timestamp,
            Category = category,
            SourceTag = cmd.SourceTag,
            Direction = "HOST->DEV",
            EndpointOrTarget = cmd.TargetOrEndpoint,
            Protocol = cmd.ProtocolName,
            Command = cmd.CommandAction,
            Summary = cmd.FormattedSummary,
            RawPayload = payloadBytes,
            PayloadAscii = cmd.TechnicalDetails,
            PayloadHex = LiveEventItem.FormatHexDump(payloadBytes),
            AdditionalDetails = cmd.TechnicalDetails
        });
    }

    private void StopSecurityAuditWatcher()
    {
        // Unifiedly managed inside UniversalToolCommandInterceptor
    }

    private void StopProcessTraceWatcher()
    {
        try
        {
            _fallbackToolInterceptor?.Stop();
            _fallbackToolInterceptor?.Dispose();
            _fallbackToolInterceptor = null;
        }
        catch { }
    }

    public static string ExtractShellSubcommand(string exeName, string cmdLine, out string? decodedScript)
    {
        return PhoenixGSM.OmniTrace.Decoders.ShellCommandParser.ExtractShellSubcommand(exeName, cmdLine, out decodedScript);
    }

    public static string ExtractCmdSubcommand(string cmdLine)
    {
        return PhoenixGSM.OmniTrace.Decoders.ShellCommandParser.ExtractShellSubcommand("cmd.exe", cmdLine, out _);
    }
    #endregion

    #region GSM Process Activity Watcher Loop
    private async Task ProcessWatcherLoop(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                var procs = Process.GetProcesses();
                var activeTools = new List<string>();

                foreach (var p in procs)
                {
                    try
                    {
                        string nameLower = p.ProcessName.ToLower();

                        // Filter out browser/CEF/crashpad helper child processes
                        if (nameLower.Contains("browser") || nameLower.Contains("crashpad") || nameLower.Contains("renderer") || nameLower.Contains("cef"))
                            continue;

                        var matchedTool = KnownGsmTools.FirstOrDefault(t => nameLower.Contains(t));
                        if (matchedTool != null)
                        {
                            activeTools.Add(p.ProcessName);

                            if (!_knownToolPids.Contains(p.Id))
                            {
                                _knownToolPids.Add(p.Id);
                                _omniService?.UniversalToolInterceptor?.RegisterToolPid(p.Id);
                                _fallbackToolInterceptor?.RegisterToolPid(p.Id);
                                string exePath = "";
                                try { exePath = p.MainModule?.FileName ?? ""; } catch { }

                                EmitEvent(new LiveEventItem
                                {
                                    Category = EventSourceCategory.Process,
                                    SourceTag = "PROCESS",
                                    Direction = "SYS",
                                    EndpointOrTarget = $"{p.ProcessName}.exe",
                                    Protocol = "GSM-TOOL",
                                    Command = "TOOL DETECTED",
                                    Summary = $"GSM Repair Tool detected: {p.ProcessName} (PID: {p.Id})",
                                    PayloadAscii = $"Process: {p.ProcessName}\nPID: {p.Id}\nPath: {exePath}\nThreads: {p.Threads.Count}",
                                    AdditionalDetails = $"Executable Path: {exePath}"
                                });
                            }
                        }
                    }
                    catch { }
                }

                // Clean up terminated PIDs
                _knownToolPids.RemoveWhere(pid =>
                {
                    try { Process.GetProcessById(pid); return false; }
                    catch { return true; }
                });

                OnToolsChanged?.Invoke(activeTools.Distinct().ToList());
                await Task.Delay(1500, token);
            }
            catch (OperationCanceledException) { break; }
            catch { await Task.Delay(2000, token); }
        }
    }
    #endregion
}
