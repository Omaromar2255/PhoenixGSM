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
    public event Action<SourceTelemetryEvent>? OnPortActivityDetected;

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
                await Task.Delay(800, token);
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

                string compositeKey = $"{kernelDeviceName}=>{portName}";
                if (_knownPorts.TryAdd(compositeKey, portName))
                {
                    var (category, description) = ClassifyKernelPort(kernelDeviceName, portName, processName);

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
                        PayloadSize = portName.Length
                    });
                }
            }
        }
        catch { }
    }

    public static (string Category, string Description) ClassifyKernelPort(string kernelPath, string comPort, string processName)
    {
        // 1. بورت معالجات MediaTek (CDC-ACM / Preloader / BROM VCOM) مثل \Device\cdcacm1 -> COM59
        if (kernelPath.Contains("cdcacm", StringComparison.OrdinalIgnoreCase) ||
            kernelPath.Contains("mtk", StringComparison.OrdinalIgnoreCase) ||
            kernelPath.Contains("vcom", StringComparison.OrdinalIgnoreCase))
        {
            return ("MediaTek BROM / Preloader Port",
                $"رصد منفذ MediaTek (BROM / Preloader / DA) نشط للأداة [{processName}]: {comPort} (المسار الكيرنلي: {kernelPath})");
        }

        // 2. بورت مودم سامسونج مثل \Device\ssudmdm0000 -> COM103
        if (kernelPath.Contains("ssudmdm", StringComparison.OrdinalIgnoreCase) ||
            kernelPath.Contains("ssud", StringComparison.OrdinalIgnoreCase))
        {
            return ("Samsung Modem / Odin Port",
                $"رصد منفذ مودم سامسونج نشط للأداة [{processName}]: {comPort} (المسار الكيرنلي: {kernelPath})");
        }

        // 3. بورت كوالكوم (EDL 9008 / QMI / DIAG)
        if (kernelPath.Contains("QCUSB", StringComparison.OrdinalIgnoreCase) ||
            kernelPath.Contains("qcusb", StringComparison.OrdinalIgnoreCase) ||
            kernelPath.Contains("qcom", StringComparison.OrdinalIgnoreCase))
        {
            return ("Qualcomm EDL 9008 / DIAG Port",
                $"رصد منفذ كوالكوم (EDL / DIAG) نشط للأداة [{processName}]: {comPort} (المسار الكيرنلي: {kernelPath})");
        }

        // 4. بورت USB Serial عام (USBSER)
        if (kernelPath.Contains("USBSER", StringComparison.OrdinalIgnoreCase))
        {
            return ("USB Serial / Bootrom Port",
                $"رصد منفذ USB تسلسلي نشط (محتمل MTK/SPD/Modem) للأداة [{processName}]: {comPort} (المسار الكيرنلي: {kernelPath})");
        }

        return ("Active Serial / Modem Port",
            $"رصد منفذ تسلسلي نشط متاح للأداة [{processName}]: {comPort} (المسار الكيرنلي: {kernelPath})");
    }

    public void Dispose() => _cts?.Cancel();
}
