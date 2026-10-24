using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using PhoenixOmniTrace.L24_SourceSentinel.Models;

namespace PhoenixOmniTrace.L24_SourceSentinel.Core;

public sealed class RamAndModuleWatcher : IDisposable
{
    private readonly ConcurrentDictionary<string, LoadedModuleArtifact> _seenModules = new();
    private readonly ConcurrentDictionary<int, DateTime> _monitoredPids = new();
    private bool _isDisposed;

    public event Action<SourceTelemetryEvent>? OnModuleOrRamActivity;
    public event Action<int, string, string>? OnExternalModuleDiscovered;

    public void RegisterProcess(int targetPid)
    {
        _monitoredPids[targetPid] = DateTime.UtcNow;
    }

    public void ScanProcessModulesAndMemory(int targetPid, string? dumpDirectory = null)
    {
        if (_isDisposed) return;
        try
        {
            using var proc = Process.GetProcessById(targetPid);
            RegisterProcess(targetPid);

            foreach (ProcessModule mod in proc.Modules)
            {
                string key = $"{targetPid}:{mod.FileName}:{mod.BaseAddress}";
                if (_seenModules.TryAdd(key, new LoadedModuleArtifact(
                    mod.ModuleName, 
                    mod.FileName, 
                    mod.BaseAddress, 
                    mod.ModuleMemorySize, 
                    IsUnpackedInRam: false, 
                    DetectionTimestamp: DateTime.UtcNow, 
                    ProcessId: targetPid)))
                {
                    // فحص إذا كانت المكتبة تستحق الاهتمام الجنائي
                    bool isSystemIgnored = mod.FileName.StartsWith(@"C:\Windows\System32", StringComparison.OrdinalIgnoreCase)
                                        || mod.FileName.StartsWith(@"C:\Windows\SysWOW64", StringComparison.OrdinalIgnoreCase);

                    bool isSpecialDriverOrGsm = mod.ModuleName.Contains("usb", StringComparison.OrdinalIgnoreCase)
                                             || mod.ModuleName.Contains("setupapi", StringComparison.OrdinalIgnoreCase)
                                             || mod.ModuleName.Contains("serial", StringComparison.OrdinalIgnoreCase)
                                             || mod.ModuleName.Contains("ftdi", StringComparison.OrdinalIgnoreCase)
                                             || mod.ModuleName.Contains("ch34", StringComparison.OrdinalIgnoreCase)
                                             || mod.ModuleName.Contains("cp210", StringComparison.OrdinalIgnoreCase)
                                             || mod.ModuleName.Contains("adb", StringComparison.OrdinalIgnoreCase)
                                             || mod.ModuleName.Contains("fastboot", StringComparison.OrdinalIgnoreCase)
                                             || mod.ModuleName.Contains("edl", StringComparison.OrdinalIgnoreCase)
                                             || mod.ModuleName.Contains("brom", StringComparison.OrdinalIgnoreCase)
                                             || mod.ModuleName.Contains("da", StringComparison.OrdinalIgnoreCase);

                    if (!isSystemIgnored || isSpecialDriverOrGsm)
                    {
                        OnModuleOrRamActivity?.Invoke(new SourceTelemetryEvent
                        {
                            ProcessId = targetPid,
                            ThreadId = 0,
                            Stage = SentinelStage.RamUnpackOrModuleLoad,
                            HookedApiName = "ModuleLoaderSnap",
                            CallerModuleOrigin = proc.ProcessName,
                            TargetResource = mod.FileName,
                            CommandCategory = "External Module Loaded",
                            DecodedCommandText = $"استدعاء وتحميل المكتبة الخارجية [{mod.ModuleName}] عند العنوان 0x{mod.BaseAddress.ToInt64():X} (الحجم: {mod.ModuleMemorySize / 1024} KB)",
                            PayloadSize = mod.ModuleMemorySize
                        });

                        OnExternalModuleDiscovered?.Invoke(targetPid, proc.ProcessName, mod.FileName);
                    }
                }
            }
        }
        catch { /* قد تكون العملية قد أُغلقت أو محمية بصلاحيات مؤقتة */ }
    }

    public void ReportRamUnpackEvent(int pid, IntPtr memoryAddress, int sizeBytes, string details)
    {
        string key = $"{pid}:RAM:0x{memoryAddress.ToInt64():X}";
        var artifact = new LoadedModuleArtifact(
            ModuleName: $"RAM_Code_0x{memoryAddress.ToInt64():X}",
            FilePath: $"[In-Memory Executable Region @ 0x{memoryAddress.ToInt64():X}]",
            BaseAddress: memoryAddress,
            MemorySize: sizeBytes,
            IsUnpackedInRam: true,
            DetectionTimestamp: DateTime.UtcNow,
            ProcessId: pid
        );
        _seenModules[key] = artifact;

        OnModuleOrRamActivity?.Invoke(new SourceTelemetryEvent
        {
            ProcessId = pid,
            ThreadId = 0,
            Stage = SentinelStage.RamUnpackOrModuleLoad,
            HookedApiName = "VirtualProtect / In-Memory Execution",
            CallerModuleOrigin = $"[RAM_Unpacked_0x{memoryAddress.ToInt64():X}]",
            TargetResource = $"MemoryRegion:0x{memoryAddress.ToInt64():X}",
            CommandCategory = "RAM Unpack / Execution",
            DecodedCommandText = $"رصد فك تشغيل كود تنفيذي بالذاكرة (In-Memory Unpack) عند 0x{memoryAddress.ToInt64():X} بحجم {sizeBytes} بايت: {details}",
            PayloadSize = sizeBytes
        });
    }

    public void Reset()
    {
        _seenModules.Clear();
        _monitoredPids.Clear();
    }

    public void Dispose()
    {
        _isDisposed = true;
        Reset();
    }
}
