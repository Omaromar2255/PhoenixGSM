using System;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Text;
using System.Threading;
using PhoenixGSM.OmniTrace.Bus;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.Sensors;

/// <summary>
/// LAYER 17 — File Extraction & Decryption Operations Monitoring Sensor
/// Intercepts and monitors processes spawned by GSM tools used for unzipping or decrypting files 
/// (e.g. 7z, WinRAR, openssl, cipher, tar) before execution or downloading.
/// </summary>
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public sealed class ExtractionDecryptionSensor : IDisposable
{
    private readonly OmniTraceEventBus _bus;
    private ManagementEventWatcher? _processWatcher;
    private bool _isRunning;
    private ulong _sequence;

    // List of known extraction and decryption tools
    private static readonly string[] MonitoredTools = [
        "7z", "winrar", "unrar", "unzip", "tar", "gzip", "openssl", "cipher", "gpg", "7za"
    ];

    public bool IsRunning => _isRunning;

    public ExtractionDecryptionSensor(OmniTraceEventBus bus)
    {
        _bus = bus ?? throw new ArgumentNullException(nameof(bus));
    }

    public void Start()
    {
        if (_isRunning) return;
        _isRunning = true;
        StartWmiProcessWatcher();
    }

    public void Stop()
    {
        if (!_isRunning) return;
        _isRunning = false;
        try
        {
            _processWatcher?.Stop();
            _processWatcher?.Dispose();
            _processWatcher = null;
        }
        catch { }
    }

    private void StartWmiProcessWatcher()
    {
        try
        {
            string wql = "SELECT * FROM Win32_ProcessStartTrace";
            _processWatcher = new ManagementEventWatcher(new EventQuery(wql));
            _processWatcher.EventArrived += OnProcessStarted;
            _processWatcher.Start();
        }
        catch 
        {
            // Fail-open: if WMI tracing fails (e.g. non-admin), continue without process tracing
        }
    }

    private void OnProcessStarted(object sender, EventArrivedEventArgs e)
    {
        try
        {
            string processName = (string)e.NewEvent.Properties["ProcessName"].Value;
            int pid = Convert.ToInt32(e.NewEvent.Properties["ProcessID"].Value);
            
            if (IsMonitoredTool(processName))
            {
                // We delay slightly to allow process arguments to be fully mapped in WMI
                Thread.Sleep(50);
                
                string cmdLine = GetCommandLine(pid);
                
                if (!string.IsNullOrWhiteSpace(cmdLine))
                {
                    ReportExtractionDecryptionEvent(processName, pid, cmdLine);
                }
            }
        }
        catch { }
    }

    private bool IsMonitoredTool(string processName)
    {
        if (string.IsNullOrEmpty(processName)) return false;
        string lowerName = processName.ToLowerInvariant();
        return MonitoredTools.Any(t => lowerName.Contains(t));
    }

    private string GetCommandLine(int pid)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher($"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
            using var objects = searcher.Get();
            var mbo = objects.Cast<ManagementBaseObject>().SingleOrDefault();
            if (mbo != null && mbo["CommandLine"] != null)
            {
                return mbo["CommandLine"].ToString() ?? string.Empty;
            }
        }
        catch { }
        return string.Empty;
    }

    private void ReportExtractionDecryptionEvent(string toolName, int pid, string commandLine)
    {
        ulong seq = Interlocked.Increment(ref _sequence);
        byte[] payload = Encoding.UTF8.GetBytes(commandLine);
        
        bool isDecryption = toolName.Contains("ssl", StringComparison.OrdinalIgnoreCase) || 
                            toolName.Contains("cipher", StringComparison.OrdinalIgnoreCase) || 
                            toolName.Contains("gpg", StringComparison.OrdinalIgnoreCase);
                            
        string operationType = isDecryption ? "Decryption" : "Extraction";

        var rawEvt = RawCaptureEvent.Create(
            sequence: seq,
            sensor: SensorType.Process,
            transport: TransportType.BULK,
            direction: PacketDirection.INTERNAL,
            device: "Host",
            session: $"{toolName}_{pid}",
            iface: 0,
            endpoint: "ExtDec_Monitor",
            payload: payload,
            timestampSource: "ExtractionDecryptionSensor"
        );

        rawEvt.Metadata["ToolName"] = toolName;
        rawEvt.Metadata["ProcessId"] = pid.ToString();
        rawEvt.Metadata["CommandLine"] = commandLine;
        rawEvt.Metadata["OperationType"] = operationType;
        
        _bus.Publish(rawEvt);

        var cmd = _bus.Correlation.Correlate(
            "EXTRACT_DECRYPT_OP",
            KnownProtocol.InProcess,
            toolName,
            TransportType.BULK,
            "Host",
            $"{toolName}_{pid}",
            PacketDirection.INTERNAL,
            [rawEvt.SequenceNumber],
            [rawEvt.PayloadHash],
            confidence: 1.0,
            suspectedPid: pid,
            suspectedToolName: toolName
        );

        cmd.Details["CommandLine"] = commandLine;
        cmd.Details["OperationType"] = operationType;
        
        if (pid > 0) cmd.Attribution.ProcessId = pid;
        cmd.Attribution.ImageName = toolName;
        cmd.Attribution.CommandLine = commandLine;

        _bus.ReportLogicalCommand(cmd);
    }

    public void Dispose()
    {
        Stop();
    }
}
