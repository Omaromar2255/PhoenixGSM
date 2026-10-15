using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using EasyHook;
using PhoenixGSM.OmniTrace.Bus;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.Sensors;

/// <summary>
/// LAYER 7 — In-Process API Hooking Sensor
/// Intercepts Windows API calls directly from the target tool (UnlockTool, etc.)
/// before they reach the filter driver or modem port.
/// Hooks: DeviceIoControl, WriteFile, ReadFile, SetupDiGetDeviceRegistryPropertyW.
/// </summary>
public sealed class ToolApiHookSensor : IDisposable
{
    private readonly OmniTraceEventBus _bus;
    private bool _isRunning;
    private ulong _sequence;
    private CancellationTokenSource _cts = new();

    // Observability metrics
    private long _apiCallsCaptured;
    private long _bytesCaptured;

    public bool IsRunning => _isRunning;
    public long ApiCallsCaptured => Interlocked.Read(ref _apiCallsCaptured);
    public long BytesCaptured => Interlocked.Read(ref _bytesCaptured);

    // Track active hooked PIDs
    private readonly HashSet<int> _hookedPids = new();

    public ToolApiHookSensor(OmniTraceEventBus bus)
    {
        _bus = bus ?? throw new ArgumentNullException(nameof(bus));
    }

    public void Start()
    {
        _isRunning = true;
        _cts = new CancellationTokenSource();
        
        // Start IPC Server for the injected payload to send data back
        Task.Run(() => StartIpcServer(_cts.Token), _cts.Token);
    }

    public void Stop()
    {
        _isRunning = false;
        _cts.Cancel();
        _hookedPids.Clear();
    }

    /// <summary>
    /// Injects the interception DLL into the target process.
    /// </summary>
    public bool InjectIntoProcess(int pid, string targetDllPath)
    {
        if (_hookedPids.Contains(pid)) return true;

        try
        {
            Console.WriteLine($"[ToolApiHookSensor] Injecting into PID {pid}...");
            
            // In a real EasyHook scenario, we call RemoteHooking.Inject
            // This is simulated injection logic for the architectural framework
            /*
            RemoteHooking.Inject(
                pid,
                InjectionOptions.DoNotRequireStrongName,
                targetDllPath,
                targetDllPath,
                "PhoenixOmniTrace_Pipe" // IPC Channel Name
            );
            */

            _hookedPids.Add(pid);
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ToolApiHookSensor] Failed to inject: {ex.Message}");
            return false;
        }
    }

    private async Task StartIpcServer(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                using var pipeServer = new NamedPipeServerStream("PhoenixOmniTrace_HookPipe", PipeDirection.In, NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Message, PipeOptions.Asynchronous);
                
                await pipeServer.WaitForConnectionAsync(token);

                _ = Task.Run(() => HandleClientConnection(pipeServer, token), token);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                Console.WriteLine($"[ToolApiHookSensor] IPC Server error: {ex.Message}");
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

                IngestHookedCall(pid, apiName, targetDevice, payload);
            }
        }
        catch (EndOfStreamException) { /* Expected disconnect */ }
        catch (Exception ex)
        {
            Console.WriteLine($"[ToolApiHookSensor] Error reading pipe: {ex.Message}");
        }
    }

    public void IngestHookedCall(int pid, string apiName, string targetDevice, byte[] payload)
    {
        string toolName = "UnknownTool.exe";
        try
        {
            var proc = Process.GetProcessById(pid);
            toolName = proc.ProcessName;
        }
        catch { }

        Interlocked.Increment(ref _apiCallsCaptured);
        Interlocked.Add(ref _bytesCaptured, payload.Length);

        // 1. Publish RawCaptureEvent
        ulong seq = Interlocked.Increment(ref _sequence);
        var rawEvt = RawCaptureEvent.Create(
            sequence: seq,
            sensor: SensorType.Process,
            transport: TransportType.BULK, // Generic for API calls
            direction: PacketDirection.HOST_TO_DEVICE,
            device: targetDevice,
            session: $"{toolName}_{pid}_API",
            iface: 0,
            endpoint: apiName,
            payload: payload.Length > 0 ? payload : Encoding.UTF8.GetBytes(apiName),
            timestampSource: "ToolApiHookSensor"
        );

        rawEvt.Metadata["ToolName"] = toolName;
        rawEvt.Metadata["ProcessId"] = pid.ToString();
        rawEvt.Metadata["ApiCalled"] = apiName;
        rawEvt.Metadata["TargetDevice"] = targetDevice;
        rawEvt.Metadata["SourceTag"] = "API-HOOK";

        _bus.Publish(rawEvt);

        // 2. Correlate and Report LogicalCommandEvent
        var cmd = _bus.Correlation.Correlate(
            $"API_{apiName}",
            KnownProtocol.InProcess,
            toolName,
            TransportType.BULK,
            targetDevice,
            $"{toolName}_{pid}_API",
            PacketDirection.HOST_TO_DEVICE,
            [rawEvt.SequenceNumber],
            [rawEvt.PayloadHash],
            confidence: 1.0,
            suspectedPid: pid,
            suspectedToolName: toolName
        );

        cmd.Details["ApiCalled"] = apiName;
        cmd.Details["TargetDevice"] = targetDevice;
        cmd.Attribution.ProcessId = pid;
        cmd.Attribution.ImageName = toolName;

        _bus.ReportLogicalCommand(cmd);
    }

    public void Dispose()
    {
        Stop();
    }
}
