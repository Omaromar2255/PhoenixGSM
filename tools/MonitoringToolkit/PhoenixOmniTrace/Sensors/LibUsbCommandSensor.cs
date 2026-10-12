using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using PhoenixGSM.OmniTrace.Bus;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.Sensors;

/// <summary>
/// LAYER 19 — LibUsb/WinUSB In-Process API Hooking Sensor
/// Intercepts libusb, WinUSB, or filter-x64 driver communication natively from the tool's process.
/// Captures commands from the tool itself (before or regardless of device connection) in the same
/// style as process execution.
/// Hooks: libusb_control_transfer, libusb_bulk_transfer, WinUsb_ControlTransfer, DeviceIoControl (for filter-x64).
/// </summary>
public sealed class LibUsbCommandSensor : IDisposable
{
    private readonly OmniTraceEventBus _bus;
    private bool _isRunning;
    private ulong _sequence;
    private CancellationTokenSource _cts = new();

    // Observability metrics
    private long _libUsbCallsCaptured;
    private long _bytesCaptured;

    public bool IsRunning => _isRunning;
    public long LibUsbCallsCaptured => Interlocked.Read(ref _libUsbCallsCaptured);
    public long BytesCaptured => Interlocked.Read(ref _bytesCaptured);

    // Track active hooked PIDs
    private readonly HashSet<int> _hookedPids = new();

    public LibUsbCommandSensor(OmniTraceEventBus bus)
    {
        _bus = bus ?? throw new ArgumentNullException(nameof(bus));
    }

    public void Start()
    {
        if (_isRunning) return;
        _isRunning = true;
        _cts = new CancellationTokenSource();
        
        // Start IPC Server for the injected payload to send data back
        Task.Run(() => StartIpcServer(_cts.Token), _cts.Token);
    }

    public void Stop()
    {
        if (!_isRunning) return;
        _isRunning = false;
        _cts.Cancel();
        _hookedPids.Clear();
    }

    /// <summary>
    /// Injects the interception DLL into the target process to hook libusb and WinUSB functions.
    /// </summary>
    public bool InjectIntoProcess(int pid, string targetDllPath)
    {
        if (_hookedPids.Contains(pid)) return true;

        try
        {
            Console.WriteLine($"[LibUsbCommandSensor] Injecting into PID {pid} to hook LibUsb/WinUSB/DeviceIoControl...");
            
            string targetDllPathActual = typeof(LibUsbCommandSensor).Assembly.Location;
            EasyHook.RemoteHooking.Inject(
                pid,
                EasyHook.InjectionOptions.DoNotRequireStrongName,
                targetDllPathActual,
                targetDllPathActual,
                "PhoenixOmniTrace_LibUsbPipe" // IPC Channel Name
            );

            _hookedPids.Add(pid);
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[LibUsbCommandSensor] Failed to inject into PID {pid}: {ex.Message}");
            return false;
        }
    }

    private async Task StartIpcServer(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                using var pipeServer = new NamedPipeServerStream("PhoenixOmniTrace_LibUsbPipe", PipeDirection.In, NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Message, PipeOptions.Asynchronous);
                
                await pipeServer.WaitForConnectionAsync(token);

                _ = Task.Run(() => HandleClientConnection(pipeServer, token), token);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                Console.WriteLine($"[LibUsbCommandSensor] IPC Server error: {ex.Message}");
                await Task.Delay(1000, token);
            }
        }
    }

    private void HandleClientConnection(NamedPipeServerStream pipe, CancellationToken token)
    {
        using var reader = new BinaryReader(pipe, Encoding.UTF8, leaveOpen: false);
        try
        {
            while (pipe.IsConnected && !token.IsCancellationRequested)
            {
                // Format: [PID 4B] [ApiNameLength 4B] [ApiName X] [TargetLength 4B] [Target X] [PayloadLength 4B] [Payload X]
                int pid = reader.ReadInt32();
                string apiName = reader.ReadString();
                string targetDevice = reader.ReadString();
                int payloadLen = reader.ReadInt32();
                byte[] payload = reader.ReadBytes(payloadLen);

                IngestLibUsbCall(pid, apiName, targetDevice, payload);
            }
        }
        catch (EndOfStreamException) { /* Expected disconnect */ }
        catch (Exception ex)
        {
            Console.WriteLine($"[LibUsbCommandSensor] Error reading pipe: {ex.Message}");
        }
    }

    public void IngestLibUsbCall(int pid, string apiName, string targetDevice, byte[] payload)
    {
        string toolName = "UnknownTool.exe";
        try
        {
            var proc = Process.GetProcessById(pid);
            toolName = proc.ProcessName;
        }
        catch { }

        Interlocked.Increment(ref _libUsbCallsCaptured);
        Interlocked.Add(ref _bytesCaptured, payload.Length);

        // 1. Publish RawCaptureEvent
        ulong seq = Interlocked.Increment(ref _sequence);
        var rawEvt = RawCaptureEvent.Create(
            sequence: seq,
            sensor: SensorType.Process,
            transport: TransportType.BULK, 
            direction: PacketDirection.HOST_TO_DEVICE,
            device: string.IsNullOrWhiteSpace(targetDevice) ? "FilterDriver_LibUsb" : targetDevice,
            session: $"{toolName}_{pid}_{apiName}",
            iface: 0,
            endpoint: apiName,
            payload: payload.Length > 0 ? payload : Encoding.UTF8.GetBytes(apiName),
            timestampSource: "LibUsbCommandSensor"
        );

        rawEvt.Metadata["ToolName"] = toolName;
        rawEvt.Metadata["ProcessId"] = pid.ToString();
        rawEvt.Metadata["LibUsbApi"] = apiName;
        rawEvt.Metadata["TargetDevice"] = targetDevice;
        rawEvt.Metadata["SourceTag"] = "LIBUSB-HOOK";
        rawEvt.Metadata["OperationType"] = "MediaTek Service Execution";

        _bus.Publish(rawEvt);

        // 2. Correlate and Report LogicalCommandEvent
        var cmd = _bus.Correlation.Correlate(
            $"LIBUSB_{apiName}",
            KnownProtocol.MtkBrom, // MediaTek context
            toolName,
            TransportType.BULK,
            string.IsNullOrWhiteSpace(targetDevice) ? "FilterDriver_LibUsb" : targetDevice,
            $"{toolName}_{pid}_{apiName}",
            PacketDirection.HOST_TO_DEVICE,
            [rawEvt.SequenceNumber],
            [rawEvt.PayloadHash],
            confidence: 1.0,
            suspectedPid: pid,
            suspectedToolName: toolName
        );

        cmd.Details["LibUsbApi"] = apiName;
        cmd.Details["TargetDevice"] = targetDevice;
        cmd.Details["OperationType"] = "MediaTek Service Execution";
        cmd.Details["Caller"] = $"{toolName} (PID {pid})";
        cmd.Attribution.ProcessId = pid;
        cmd.Attribution.ImageName = toolName;

        _bus.ReportLogicalCommand(cmd);
    }

    public void Dispose()
    {
        Stop();
    }
}
