using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using PhoenixOmniTrace.L24_SourceSentinel.Models;

namespace PhoenixOmniTrace.L24_SourceSentinel.Core;

public sealed class ActiveComAndUsbPortPoller : IDisposable
{
    private CancellationTokenSource? _cts;
    private readonly ConcurrentDictionary<string, string> _knownPorts = new();
    private static volatile string _latestActivePortLabel = string.Empty;

    public event Action<SourceTelemetryEvent>? OnPortActivityDetected;

    public static string GetPrimaryActivePortLabel()
    {
        return !string.IsNullOrWhiteSpace(_latestActivePortLabel)
            ? _latestActivePortLabel
            : "Active Modem Buffer";
    }

    public void StartPolling(int targetPid, string processName)
    {
        _cts?.Cancel();
        _cts = new CancellationTokenSource();
        var token = _cts.Token;

        Task.Run(async () =>
        {
            while (!token.IsCancellationRequested)
            {
                CheckActiveSerialCommPorts(targetPid, processName);
                await Task.Delay(700, token).ConfigureAwait(false);
            }
        }, token);
    }

    private void CheckActiveSerialCommPorts(int pid, string processName)
    {
        try
        {
            if (!OperatingSystem.IsWindows()) return;

            using var key = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DEVICEMAP\SERIALCOMM");
            if (key == null) return;

            foreach (string kernelDeviceName in key.GetValueNames())
            {
                string portName = key.GetValue(kernelDeviceName)?.ToString() ?? string.Empty;
                if (string.IsNullOrEmpty(portName)) continue;

                var (category, description) = ClassifyKernelPort(kernelDeviceName, portName, processName);
                _latestActivePortLabel = $"{portName} ({category})";

                string compositeKey = $"{kernelDeviceName}=>{portName}";
                if (_knownPorts.TryAdd(compositeKey, portName))
                {
                    OnPortActivityDetected?.Invoke(new SourceTelemetryEvent
                    {
                        ProcessId = pid,
                        ThreadId = 0,
                        Stage = SentinelStage.PortAndDeviceRadar,
                        HookedApiName = "SERIALCOMM_SmartClassifier",
                        CallerModuleOrigin = processName,
                        TargetResource = $"{kernelDeviceName} -> {portName}",
                        CommandCategory = category,
                        DecodedCommandText = description,
                        PureCommandText = $"{portName} ({kernelDeviceName})",
                        PayloadSize = portName.Length
                    });
                }
            }
        }
        catch { }
    }

    public static (string Category, string Description) ClassifyKernelPort(string kernelPath, string comPort, string processName)
    {
        if (kernelPath.Contains("cdcacm", StringComparison.OrdinalIgnoreCase) ||
            kernelPath.Contains("mtk", StringComparison.OrdinalIgnoreCase) ||
            kernelPath.Contains("vcom", StringComparison.OrdinalIgnoreCase) ||
            kernelPath.Contains("0e8d", StringComparison.OrdinalIgnoreCase))
        {
            return ("MediaTek BROM / Preloader Port",
                $"رصد منفذ MediaTek (BROM / Preloader / DA) نشط للأداة [{processName}]: {comPort} (المسار الكيرنلي: {kernelPath})");
        }

        if (kernelPath.Contains("ssudmdm", StringComparison.OrdinalIgnoreCase) ||
            kernelPath.Contains("ssud", StringComparison.OrdinalIgnoreCase))
        {
            return ("Samsung Modem / Odin Port",
                $"رصد منفذ مودم سامسونج نشط للأداة [{processName}]: {comPort} (المسار الكيرنلي: {kernelPath})");
        }

        if (kernelPath.Contains("QCUSB", StringComparison.OrdinalIgnoreCase) ||
            kernelPath.Contains("qcusb", StringComparison.OrdinalIgnoreCase) ||
            kernelPath.Contains("qcom", StringComparison.OrdinalIgnoreCase))
        {
            return ("Qualcomm EDL 9008 / DIAG Port",
                $"رصد منفذ كوالكوم (EDL / DIAG) نشط للأداة [{processName}]: {comPort} (المسار الكيرنلي: {kernelPath})");
        }

        if (kernelPath.Contains("USBSER", StringComparison.OrdinalIgnoreCase))
        {
            return ("USB Serial / Bootrom Port",
                $"رصد منفذ USB تسلسلي نشط (محتمل MTK/SPD/Modem) للأداة [{processName}]: {comPort} (المسار الكيرنلي: {kernelPath})");
        }

        return ("Active Serial / Modem Port",
            $"رصد منفذ تسلسلي نشط متاح للأداة [{processName}]: {comPort} (المسار الكيرنلي: {kernelPath})");
    }

    public void Stop()
    {
        try
        {
            _cts?.Cancel();
            _cts?.Dispose();
        }
        catch { }
        _cts = null;
        _knownPorts.Clear();
    }

    public void Dispose() => Stop();
}
