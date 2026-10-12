using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.IO.Ports;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using PhoenixGSM.OmniTrace.Bus;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.Sensors;

/// <summary>
/// LAYER 3C — Serial & Modem Port Data Sensor
/// Passively discovers and monitors COM / Modem ports used by GSM tools
/// (e.g. Chimera, UnlockTool, Odin, Global Unlocker, Qualcomm DIAG, Samsung Modem, MediaTek BROM).
/// Operates in fail-open mode: if a port is exclusively held by a tool, it gracefully tracks
/// the channel metadata and topology without crashing or disrupting the external tool.
/// </summary>
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public sealed class SerialPortSensor : IDisposable
{
    private readonly OmniTraceEventBus _bus;
    private readonly ConcurrentDictionary<string, SerialPortMonitorInstance> _monitoredPorts = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, string> _portToDeviceDescription = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, string> _portToHardwareId = new(StringComparer.OrdinalIgnoreCase);

    private CancellationTokenSource? _cts;
    private Task? _discoveryTask;
    private bool _isRunning;
    private ulong _sequence;

    // Observability metrics
    private long _portsDiscovered;
    private long _packetsCaptured;
    private long _bytesCaptured;
    private long _errorsCount;
    private string? _lastError;

    public bool IsRunning => _isRunning;
    public long PortsDiscovered => Interlocked.Read(ref _portsDiscovered);
    public long PacketsCaptured => Interlocked.Read(ref _packetsCaptured);
    public long BytesCaptured => Interlocked.Read(ref _bytesCaptured);
    public long ErrorsCount => Interlocked.Read(ref _errorsCount);
    public string? LastError => _lastError;
    public int ActiveListenersCount => _monitoredPorts.Count;
    public IReadOnlyCollection<string> MonitoredPortNames => _monitoredPorts.Keys.ToArray();
    public IReadOnlyCollection<string> AllDiscoveredPortNames => _portToDeviceDescription.Keys.Concat(_monitoredPorts.Keys).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    public bool IsPortMonitored(string portName) => _monitoredPorts.ContainsKey(portName);
    public string? GetPortDescription(string portName) => _portToDeviceDescription.TryGetValue(portName, out var desc) ? desc : null;
    public string? GetPortHardwareId(string portName) => _portToHardwareId.TryGetValue(portName, out var hwId) ? hwId : null;

    public event Action<RawCaptureEvent>? OnSerialDataCaptured;

    public event Action<string, string>? OnPortDiscovered;
    public event Action<string>? OnPortRemoved;

    public SerialPortSensor(OmniTraceEventBus bus)
    {
        _bus = bus ?? throw new ArgumentNullException(nameof(bus));
    }

    public void Start()
    {
        if (_isRunning) return;

        _cts = new CancellationTokenSource();
        _isRunning = true;

        // Initial scan
        RefreshPortDescriptions();
        ScanPorts();

        // Start background discovery loop
        _discoveryTask = Task.Run(async () =>
        {
            while (!_cts.Token.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(1000, _cts.Token);
                    RefreshPortDescriptions();
                    ScanPorts();
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    Interlocked.Increment(ref _errorsCount);
                    _lastError = ex.Message;
                }
            }
        }, _cts.Token);
    }

    public void Stop()
    {
        if (!_isRunning) return;

        _isRunning = false;
        _cts?.Cancel();

        try
        {
            _discoveryTask?.Wait(2000);
        }
        catch { }

        foreach (var kvp in _monitoredPorts)
        {
            kvp.Value.Dispose();
        }
        _monitoredPorts.Clear();

        _bus.Flush();

        _cts?.Dispose();
        _cts = null;
    }

    private void RefreshPortDescriptions()
    {
        try
        {
            // 1. Scan Modem Class: HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E96D-E325-11CE-BFC1-08002BE10318}
            // (e.g. SAMSUNG Mobile USB Modem #6 on COM12)
            using (var modemClassKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Class\{4D36E96D-E325-11CE-BFC1-08002BE10318}"))
            {
                if (modemClassKey != null)
                {
                    foreach (var subKeyName in modemClassKey.GetSubKeyNames())
                    {
                        if (subKeyName.Length == 4 && int.TryParse(subKeyName, out _))
                        {
                            using var devKey = modemClassKey.OpenSubKey(subKeyName);
                            var attachedTo = devKey?.GetValue("AttachedTo")?.ToString();
                            var driverDesc = devKey?.GetValue("DriverDesc")?.ToString();
                            var matchingDevId = devKey?.GetValue("MatchingDeviceId")?.ToString();

                            if (!string.IsNullOrWhiteSpace(attachedTo) && attachedTo.StartsWith("COM", StringComparison.OrdinalIgnoreCase))
                            {
                                if (!string.IsNullOrWhiteSpace(driverDesc)) _portToDeviceDescription[attachedTo] = driverDesc;
                                if (!string.IsNullOrWhiteSpace(matchingDevId)) _portToHardwareId[attachedTo] = matchingDevId;
                            }
                        }
                    }
                }
            }

            // 2. Scan Ports Class: HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E978-E325-11CE-BFC1-08002BE10318}
            // (e.g. Qualcomm HS-USB Diagnostics, MediaTek USB VCOM)
            using (var portsClassKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Class\{4D36E978-E325-11CE-BFC1-08002BE10318}"))
            {
                if (portsClassKey != null)
                {
                    foreach (var subKeyName in portsClassKey.GetSubKeyNames())
                    {
                        if (subKeyName.Length == 4 && int.TryParse(subKeyName, out _))
                        {
                            using var devKey = portsClassKey.OpenSubKey(subKeyName);
                            var driverDesc = devKey?.GetValue("DriverDesc")?.ToString();
                            var matchingDevId = devKey?.GetValue("MatchingDeviceId")?.ToString();

                            using var paramsKey = devKey?.OpenSubKey("Device Parameters");
                            var portName = paramsKey?.GetValue("PortName")?.ToString();

                            if (!string.IsNullOrWhiteSpace(portName) && portName.StartsWith("COM", StringComparison.OrdinalIgnoreCase))
                            {
                                if (!string.IsNullOrWhiteSpace(driverDesc)) _portToDeviceDescription[portName] = driverDesc;
                                if (!string.IsNullOrWhiteSpace(matchingDevId)) _portToHardwareId[portName] = matchingDevId;
                            }
                        }
                    }
                }
            }

            // 3. Scan Hardware Device Map: HKLM\HARDWARE\DEVICEMAP\SERIALCOMM
            using (var serialCommKey = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DEVICEMAP\SERIALCOMM"))
            {
                if (serialCommKey != null)
                {
                    foreach (var valName in serialCommKey.GetValueNames())
                    {
                        var port = serialCommKey.GetValue(valName)?.ToString();
                        if (!string.IsNullOrWhiteSpace(port) && !_portToHardwareId.ContainsKey(port))
                        {
                            _portToHardwareId[port] = valName;
                        }
                    }
                }
            }
        }
        catch
        {
            // Fallback gracefully on restricted environments
        }
    }

    private void ScanPorts()
    {
        string[] currentPorts;
        try
        {
            currentPorts = SerialPort.GetPortNames();
        }
        catch
        {
            currentPorts = Array.Empty<string>();
        }

        var activeSet = new HashSet<string>(currentPorts, StringComparer.OrdinalIgnoreCase);

        // Also check if any known active serial comm ports are in registry
        try
        {
            using var serialCommKey = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DEVICEMAP\SERIALCOMM");
            if (serialCommKey != null)
            {
                foreach (var valName in serialCommKey.GetValueNames())
                {
                    var port = serialCommKey.GetValue(valName)?.ToString();
                    if (!string.IsNullOrWhiteSpace(port) && port.StartsWith("COM", StringComparison.OrdinalIgnoreCase))
                    {
                        activeSet.Add(port);
                    }
                }
            }
        }
        catch { }

        // Also include all ports discovered in Modem and Ports registry classes
        foreach (var p in _portToDeviceDescription.Keys)
        {
            activeSet.Add(p);
        }

        Interlocked.Exchange(ref _portsDiscovered, activeSet.Count);

        // Check for removed ports
        foreach (var existing in _monitoredPorts.Keys)
        {
            if (!activeSet.Contains(existing))
            {
                if (_monitoredPorts.TryRemove(existing, out var monitor))
                {
                    monitor.Dispose();
                    OnPortRemoved?.Invoke(existing);
                    _bus.ReportAnomaly("SERIAL_PORT_DISCONNECTED", $"Serial/Modem port {existing} disconnected.");
                }
            }
        }

        // Check for new ports
        foreach (var portName in activeSet)
        {
            if (!_monitoredPorts.ContainsKey(portName))
            {
                _portToDeviceDescription.TryGetValue(portName, out var desc);
                _portToHardwareId.TryGetValue(portName, out var hwId);

                desc ??= $"Serial Port ({portName})";
                hwId ??= $"SERIAL\\{portName}";

                var monitor = new SerialPortMonitorInstance(
                    portName: portName,
                    description: desc,
                    hardwareId: hwId,
                    onDataReceived: IngestDataChunk,
                    onAnomaly: (code, msg) => _bus.ReportAnomaly(code, msg)
                );

                if (_monitoredPorts.TryAdd(portName, monitor))
                {
                    OnPortDiscovered?.Invoke(portName, desc);
                    monitor.StartListening();
                }
            }
        }
    }


    private void IngestDataChunk(string portName, string description, string hwId, byte[] data, PacketDirection direction)
    {
        if (data == null || data.Length == 0) return;

        ulong seq = Interlocked.Increment(ref _sequence);
        Interlocked.Increment(ref _packetsCaptured);
        Interlocked.Add(ref _bytesCaptured, data.Length);

        var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Port"] = portName,
            ["Description"] = description,
            ["HardwareId"] = hwId,
            ["Timestamp"] = DateTimeOffset.UtcNow.ToString("o")
        };

        var rawEvt = RawCaptureEvent.Create(
            sequence: seq,
            sensor: SensorType.Serial,
            transport: TransportType.SERIAL,
            direction: direction,
            device: hwId,
            session: $"SERIAL_{portName}",
            iface: 0,
            endpoint: portName,
            payload: data,
            timestampSource: "SerialPortSensor",
            metadata: metadata
        );

        _bus.Publish(rawEvt);
        OnSerialDataCaptured?.Invoke(rawEvt);
    }

    public bool SendAtCommandToPort(string portName, string command, out string error)
    {
        if (!_monitoredPorts.ContainsKey(portName))
        {
            ScanPorts();
        }

        if (_monitoredPorts.TryGetValue(portName, out var monitor))
        {
            string cleanCmd = command.TrimEnd('\r', '\n') + "\r\n";
            return monitor.TrySendCommand(cleanCmd, out error);
        }
        error = $"Port {portName} is not being monitored.";
        return false;
    }

    public bool SendAtCommandToAnyPort(string command, out string error)
    {
        error = "";
        string cleanCmd = command.TrimEnd('\r', '\n') + "\r\n";
        if (_monitoredPorts.IsEmpty)
        {
            ScanPorts();
        }
        foreach (var kvp in _monitoredPorts)
        {
            if (kvp.Value.TrySendCommand(cleanCmd, out error))
            {
                return true;
            }
        }
        error = string.IsNullOrEmpty(error) ? "No monitored port is currently open to receive commands." : error;
        return false;
    }


    /// <summary>
    /// Simulates data ingestion on a specific port (used for tests and synthetic simulation)
    /// </summary>
    public void SimulateSerialDataIngestion(string portName, byte[] data, PacketDirection direction)
    {
        if (_monitoredPorts.TryGetValue(portName, out var monitor))
        {
            monitor.IngestData(data, direction);
        }
        else
        {
            IngestDataChunk(portName, $"Serial Port ({portName})", $"SERIAL\\{portName}", data, direction);
        }
    }

    /// <summary>
    /// Ingests captured traffic from external capture sources (e.g. Kernel filter UpperFilter, USB ETW)
    /// </summary>
    public void IngestCapturedPortTraffic(string portName, byte[] data, PacketDirection direction, string? toolName = null, int pid = 0)
    {
        if (data == null || data.Length == 0) return;

        _portToDeviceDescription.TryGetValue(portName, out var desc);
        _portToHardwareId.TryGetValue(portName, out var hwId);
        desc ??= $"Modem/Serial Port ({portName})";
        hwId ??= $"SERIAL\\{portName}";

        ulong seq = Interlocked.Increment(ref _sequence);
        Interlocked.Increment(ref _packetsCaptured);
        Interlocked.Add(ref _bytesCaptured, data.Length);

        var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Port"] = portName,
            ["Description"] = desc,
            ["HardwareId"] = hwId,
            ["Timestamp"] = DateTimeOffset.UtcNow.ToString("o")
        };

        if (!string.IsNullOrEmpty(toolName)) metadata["ProcessName"] = toolName;
        if (pid > 0) metadata["ProcessId"] = pid.ToString();

        var rawEvt = RawCaptureEvent.Create(
            sequence: seq,
            sensor: SensorType.Serial,
            transport: TransportType.SERIAL,
            direction: direction,
            device: hwId,
            session: $"SERIAL_{portName}",
            iface: 0,
            endpoint: portName,
            payload: data,
            timestampSource: "SerialPortSensor",
            metadata: metadata
        );

        _bus.Publish(rawEvt);
        OnSerialDataCaptured?.Invoke(rawEvt);
    }

    public void Dispose()
    {
        Stop();
    }

    /// <summary>
    /// Instance monitoring a single COM port
    /// </summary>
    private sealed class SerialPortMonitorInstance : IDisposable
    {
        private readonly string _portName;
        private readonly string _description;
        private readonly string _hardwareId;
        private readonly Action<string, string, string, byte[], PacketDirection> _onDataReceived;
        private readonly Action<string, string> _onAnomaly;
        private readonly object _ioLock = new();

        private SerialPort? _serialPort;
        private bool _isDisposed;
        private bool _isLockedByTool;

        public bool IsLockedByTool => _isLockedByTool;

        public SerialPortMonitorInstance(
            string portName,
            string description,
            string hardwareId,
            Action<string, string, string, byte[], PacketDirection> onDataReceived,
            Action<string, string> onAnomaly)
        {
            _portName = portName;
            _description = description;
            _hardwareId = hardwareId;
            _onDataReceived = onDataReceived;
            _onAnomaly = onAnomaly;
        }

        public void StartListening()
        {
            // Fail-Open / Non-intrusive Passive Mode:
            // Do NOT hold an exclusive CreateFile handle on physical/virtual COM ports,
            // as this prevents external GSM tools (Chimera, Odin, UnlockTool, etc.) from accessing the modem.
            // Full passive traffic capture is handled via USB ETW and Kernel Driver layers.
            _isLockedByTool = false;
        }

        public bool TrySendCommand(string command, out string error)
        {
            error = "";
            lock (_ioLock)
            {
                SerialPort? sp = null;
                try
                {
                    sp = new SerialPort(_portName, 115200, Parity.None, 8, StopBits.One)
                    {
                        ReadTimeout = 400,
                        WriteTimeout = 1000,
                        DtrEnable = true,
                        RtsEnable = true,
                        Handshake = Handshake.None
                    };

                    sp.Open();
                    _isLockedByTool = false;

                    byte[] data = Encoding.ASCII.GetBytes(command);
                    sp.Write(data, 0, data.Length);
                    _onDataReceived(_portName, _description, _hardwareId, data, PacketDirection.HOST_TO_DEVICE);

                    // Read response if available
                    byte[] readBuf = new byte[2048];
                    int totalRead = 0;
                    DateTime deadline = DateTime.UtcNow.AddMilliseconds(500);
                    while (DateTime.UtcNow < deadline)
                    {
                        try
                        {
                            if (sp.BytesToRead > 0)
                            {
                                int r = sp.Read(readBuf, totalRead, readBuf.Length - totalRead);
                                if (r > 0)
                                {
                                    totalRead += r;
                                    string interim = Encoding.ASCII.GetString(readBuf, 0, totalRead);
                                    if (interim.Contains("OK\r") || interim.Contains("ERROR\r") || interim.EndsWith("\n"))
                                    {
                                        break;
                                    }
                                }
                            }
                            else
                            {
                                Thread.Sleep(25);
                            }
                        }
                        catch (TimeoutException) { break; }
                        catch { break; }
                    }

                    if (totalRead > 0)
                    {
                        byte[] resp = new byte[totalRead];
                        Buffer.BlockCopy(readBuf, 0, resp, 0, totalRead);
                        _onDataReceived(_portName, _description, _hardwareId, resp, PacketDirection.DEVICE_TO_HOST);
                    }

                    return true;
                }
                catch (UnauthorizedAccessException ex)
                {
                    _isLockedByTool = true;
                    error = $"Port {_portName} is currently in use by an external GSM servicing tool ({ex.Message}).";
                    return false;
                }
                catch (Exception ex)
                {
                    error = ex.Message;
                    return false;
                }
                finally
                {
                    try
                    {
                        sp?.Close();
                        sp?.Dispose();
                    }
                    catch { }
                }
            }
        }

        public void IngestData(byte[] data, PacketDirection direction)
        {
            if (data != null && data.Length > 0)
            {
                _onDataReceived(_portName, _description, _hardwareId, data, direction);
            }
        }

        public void Dispose()
        {
            if (_isDisposed) return;
            _isDisposed = true;

            lock (_ioLock)
            {
                try
                {
                    _serialPort?.Close();
                    _serialPort?.Dispose();
                    _serialPort = null;
                }
                catch { }
            }
        }
    }
}
