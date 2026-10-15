using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;

namespace PhoenixGSM.OmniTrace.Commands;

/// <summary>
/// Represents a captured PowerShell script block.
/// كتلة نصية ملتقطة من PowerShell
/// </summary>
public class PowerShellScriptBlock : EventArgs
{
    public string ScriptContent { get; set; } = string.Empty;
    public bool IsDangerous { get; set; }
    public string DetectedKeywords { get; set; } = string.Empty;
}

/// <summary>
/// Monitors PowerShell Script Block Logging (Event ID 4104) via real-time ETW session.
/// مراقب كتل نصوص PowerShell لحظياً عبر جلسة ETW
/// </summary>
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public class PowerShellScriptBlockMonitor : IDisposable
{
    public static readonly Guid PowerShellProviderGuid = new("A0C1853B-5C40-4B15-8766-3CF15B1FE04F");
    public const string DefaultSessionName = "Phoenix-PowerShell-ScriptBlock-Session";

    private TraceEventSession? _session;
    private Task? _processingTask;
    private CancellationTokenSource? _cts;
    private bool _isRunning;

    private static readonly string[] DangerousKeywords =
    [
        "DownloadData", "DownloadFile", "Invoke-Expression", "IEX",
        "[System.Reflection.Assembly]::Load", "BitBlt", "MiniDumpWriteDump",
        "Net.WebClient", "Start-Process", "FromBase64String"
    ];

    public event EventHandler<PowerShellScriptBlock>? OnScriptBlockCaptured;

    public void Start()
    {
        if (_isRunning) return;

        try
        {
            try
            {
                var existing = TraceEventSession.GetActiveSession(DefaultSessionName);
                existing?.Stop();
                existing?.Dispose();
            }
            catch { }

            _session = new TraceEventSession(DefaultSessionName, TraceEventSessionOptions.Create);
            _session.EnableProvider(PowerShellProviderGuid, TraceEventLevel.Verbose, matchAnyKeywords: 0xFFFFFFFFFFFFFFFFUL);

            _session.Source.Dynamic.All += HandleDynamicEvent;

            _cts = new CancellationTokenSource();
            _processingTask = Task.Run(() =>
            {
                try { _session.Source.Process(); }
                catch { }
            });

            _isRunning = true;
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[PowerShellScriptBlockMonitor] Start failed: {ex.Message}");
        }
    }

    private void HandleDynamicEvent(TraceEvent data)
    {
        try
        {
            // Event ID 4104 is Execute a Remote/Local Command / ScriptBlock Logging
            if (data.ID != (TraceEventID)4104 && !data.EventName.Contains("ScriptBlock", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            string scriptText = string.Empty;
            foreach (var name in data.PayloadNames)
            {
                if (name.Contains("ScriptBlockText", StringComparison.OrdinalIgnoreCase) ||
                    name.Contains("Script", StringComparison.OrdinalIgnoreCase) ||
                    name.Contains("Payload", StringComparison.OrdinalIgnoreCase))
                {
                    var val = data.PayloadByName(name)?.ToString();
                    if (!string.IsNullOrWhiteSpace(val))
                    {
                        scriptText = val;
                        break;
                    }
                }
            }

            if (string.IsNullOrWhiteSpace(scriptText))
            {
                scriptText = data.FormattedMessage ?? string.Empty;
            }

            if (string.IsNullOrWhiteSpace(scriptText)) return;

            var block = new PowerShellScriptBlock { ScriptContent = scriptText };
            ScanForDangerousCommands(block);
            OnScriptBlockCaptured?.Invoke(this, block);
        }
        catch { }
    }

    private static void ScanForDangerousCommands(PowerShellScriptBlock block)
    {
        try
        {
            var detected = new System.Collections.Generic.List<string>();
            foreach (var keyword in DangerousKeywords)
            {
                if (block.ScriptContent.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                {
                    detected.Add(keyword);
                }
            }

            if (detected.Count > 0)
            {
                block.IsDangerous = true;
                block.DetectedKeywords = string.Join(", ", detected);
            }
        }
        catch { }
    }

    public void Stop()
    {
        if (!_isRunning) return;
        _isRunning = false;

        try
        {
            _cts?.Cancel();
            _session?.Source?.StopProcessing();
            _session?.Stop();
            _session?.Dispose();
        }
        catch { }
        finally
        {
            _session = null;
            _cts?.Dispose();
            _cts = null;
        }
    }

    public void Dispose()
    {
        Stop();
        GC.SuppressFinalize(this);
    }
}
