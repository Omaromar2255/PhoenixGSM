using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
using PhoenixGSM.OmniTrace.Bus;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.Sensors;

/// <summary>
/// LAYER 3D — USBPcap Fallback Packet Sensor
/// Provides secondary/redundant raw USB packet sniffing via USBPcap kernel driver
/// control devices (\\.\USBPcap1 .. \\.\USBPcap8) if installed on the system.
/// Designed for 100% fail-open operation: if USBPcap is absent, the sensor reports
/// status and gracefully steps aside, allowing ETW, Kernel Filter, and Serial sensors to operate unimpeded.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class UsbPcapSensor : IDisposable
{
    private readonly OmniTraceEventBus _bus;
    private readonly UsbDeviceSensor _usbSensor;
    private CancellationTokenSource? _cts;
    private Task? _workerTask;
    private bool _isRunning;
    private bool _isAvailable;
    private string? _activeDevicePath;

    // Observability metrics
    private long _packetsCaptured;
    private long _bytesCaptured;
    private long _errorCount;
    private string? _lastError;

    public bool IsRunning => _isRunning;
    public bool IsAvailable => _isAvailable;
    public string? ActiveDevicePath => _activeDevicePath;
    public long PacketsCaptured => Interlocked.Read(ref _packetsCaptured);
    public long BytesCaptured => Interlocked.Read(ref _bytesCaptured);
    public long ErrorCount => Interlocked.Read(ref _errorCount);
    public string? LastError => _lastError;

    public event Action<RawCaptureEvent>? OnPacketCaptured;

    public UsbPcapSensor(OmniTraceEventBus bus, UsbDeviceSensor? usbSensor = null)
    {
        _bus = bus ?? throw new ArgumentNullException(nameof(bus));
        _usbSensor = usbSensor ?? bus.UsbSensor;
    }

    public void Start()
    {
        if (_isRunning) return;

        // Probe for USBPcap devices \\.\USBPcap1 .. \\.\USBPcap8
        string? targetDevice = null;
        for (int i = 1; i <= 8; i++)
        {
            string path = $@"\\.\USBPcap{i}";
            try
            {
                using var handle = CreateFile(
                    path,
                    FileAccess.Read,
                    FileShare.ReadWrite,
                    IntPtr.Zero,
                    FileMode.Open,
                    0x40000000 /* FILE_FLAG_OVERLAPPED */,
                    IntPtr.Zero);

                if (!handle.IsInvalid)
                {
                    targetDevice = path;
                    break;
                }
            }
            catch { }
        }

        if (targetDevice == null)
        {
            _isAvailable = false;
            _bus.ReportAnomaly("USBP_CAP_NOT_INSTALLED", "USBPcap driver is not installed on this system. Operating with ETW + Kernel Filter sensors.");
            return;
        }

        _activeDevicePath = targetDevice;
        _isAvailable = true;
        _cts = new CancellationTokenSource();
        _isRunning = true;

        _workerTask = Task.Run(() => CaptureLoop(targetDevice, _cts.Token));
    }

    private void CaptureLoop(string devicePath, CancellationToken ct)
    {
        try
        {
            using var fileHandle = CreateFile(
                devicePath,
                FileAccess.Read,
                FileShare.ReadWrite,
                IntPtr.Zero,
                FileMode.Open,
                0,
                IntPtr.Zero);

            if (fileHandle.IsInvalid)
            {
                _isAvailable = false;
                _isRunning = false;
                return;
            }

            using var stream = new FileStream(fileHandle, FileAccess.Read, 65536, false);
            byte[] headerBuffer = new byte[24]; // USBPcap minimal packet header

            while (!ct.IsCancellationRequested && _isRunning)
            {
                int read = stream.Read(headerBuffer, 0, headerBuffer.Length);
                if (read < headerBuffer.Length) break;

                ushort headerLen = BitConverter.ToUInt16(headerBuffer, 0);
                byte info = headerBuffer[14];
                byte endpoint = headerBuffer[18];
                uint dataLength = BitConverter.ToUInt32(headerBuffer, 20);

                PacketDirection direction = (info & 0x01) != 0 ? PacketDirection.DEVICE_TO_HOST : PacketDirection.HOST_TO_DEVICE;

                byte[] payload = Array.Empty<byte>();
                if (dataLength > 0 && dataLength <= 1048576) // Max 1MB packet
                {
                    payload = new byte[dataLength];
                    int payloadRead = 0;
                    while (payloadRead < dataLength && !ct.IsCancellationRequested)
                    {
                        int r = stream.Read(payload, payloadRead, (int)dataLength - payloadRead);
                        if (r <= 0) break;
                        payloadRead += r;
                    }
                }

                string epAddr = $"0x{endpoint:X2}";
                string deviceId = "USB\\USBPcapDevice";
                string session = $"USBPcap_{_activeDevicePath}";

                var rawEvt = _usbSensor.IngestUsbPacket(
                    deviceId: deviceId,
                    interfaceIndex: 0,
                    endpointAddress: epAddr,
                    direction: direction,
                    payload: payload,
                    transportSession: session,
                    sensor: SensorType.USB,
                    transport: TransportType.BULK
                );

                Interlocked.Increment(ref _packetsCaptured);
                Interlocked.Add(ref _bytesCaptured, payload.Length);
                OnPacketCaptured?.Invoke(rawEvt);
            }
        }
        catch (Exception ex)
        {
            if (_isRunning)
            {
                Interlocked.Increment(ref _errorCount);
                _lastError = ex.Message;
                _bus.ReportAnomaly("USBP_CAP_READ_ERROR", ex.Message);
            }
        }
        finally
        {
            _isRunning = false;
        }
    }

    public void Stop()
    {
        if (!_isRunning) return;
        _isRunning = false;
        _cts?.Cancel();

        try
        {
            _workerTask?.Wait(1000);
        }
        catch { }

        _cts?.Dispose();
        _cts = null;
    }

    public void Dispose()
    {
        Stop();
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern SafeFileHandle CreateFile(
        string lpFileName,
        [MarshalAs(UnmanagedType.U4)] FileAccess dwDesiredAccess,
        [MarshalAs(UnmanagedType.U4)] FileShare dwShareMode,
        IntPtr lpSecurityAttributes,
        [MarshalAs(UnmanagedType.U4)] FileMode dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);
}
