using System;
using System.Diagnostics;
using System.IO;
using PhoenixGSM.OmniTrace.Correlation;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.Sensors;

/// <summary>
/// LAYER 1 — Process Observation & Attribution Sensor
/// Tracks process lifecycle to enrich logical commands with attribution metadata.
/// IMPORTANT ARCHITECTURAL PRINCIPLE:
/// Process presence is NEVER required for command capture.
/// The capture engine functions 100% identically even if no adb.exe or known tool exists.
/// </summary>
public sealed class ProcessAttributionSensor
{
    private readonly CommandCorrelationEngine _correlation;

    public ProcessAttributionSensor(CommandCorrelationEngine correlation)
    {
        _correlation = correlation;
    }

    public ProcessAttributionMetadata RegisterProcessFromDiagnostics(Process proc)
    {
        var meta = new ProcessAttributionMetadata
        {
            ProcessId = proc.Id,
            ImageName = proc.ProcessName,
            StartTime = DateTimeOffset.UtcNow
        };

        try
        {
            meta.ImagePath = proc.MainModule?.FileName ?? string.Empty;
        }
        catch { }

        _correlation.RegisterProcess(meta);
        return meta;
    }

    public ProcessAttributionMetadata RegisterProcessManual(
        int pid,
        int ppid,
        string imageName,
        string imagePath,
        string commandLine,
        string user = "Current")
    {
        var meta = new ProcessAttributionMetadata
        {
            ProcessId = pid,
            ParentProcessId = ppid,
            ImageName = imageName,
            ImagePath = imagePath,
            CommandLine = commandLine,
            User = user,
            ProcessGuid = Guid.NewGuid().ToString("N"),
            StartTime = DateTimeOffset.UtcNow
        };

        _correlation.RegisterProcess(meta);
        return meta;
    }

    public void NotifyProcessExited(int pid)
    {
        _correlation.UnregisterProcess(pid);
    }
}
