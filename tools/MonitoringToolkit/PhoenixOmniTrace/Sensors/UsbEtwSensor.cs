using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using PhoenixGSM.OmniTrace.Bus;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.Sensors;

/// <summary>
/// LAYER 3B — USB ETW Kernel Sensor
/// Subscribes to Windows built-in USB ETW providers (USBXHCI and USBHUB3)
/// to passively capture USB packets with process attribution (PID) directly from the OS,
/// completely independent of kernel filter drivers and immune to exclusive handle locks.
/// </summary>
public sealed class UsbEtwSensor : IDisposable
{
    public static readonly Guid XhciProviderGuid = new("30E1D284-5D88-459C-83FD-6345B39B19EC");
    public static readonly Guid Hub3ProviderGuid = new("AC52AD17-CC01-4F85-8DF5-4DCE4333C99B");
    public static readonly Guid UcxProviderGuid = new("36DA592D-E43A-4E28-AF6F-4BC57C5A11E8");
    public static readonly Guid UsbPortProviderGuid = new("C88A4EF5-D048-4013-9408-E04B7DB2814A");
    public static readonly Guid SerialClassExtensionV2Guid = new("EEE173EF-7ED2-45DE-9877-01C70A852FBD");
    public static readonly Guid SerialClassExtensionGuid = new("47BC9477-A8BA-452E-B951-4F2ED3593CF9");
    public const string DefaultSessionName = "Microsoft-Windows-USB-Diagnostics-Session";

    private readonly OmniTraceEventBus _bus;
    private readonly UsbDeviceSensor _usbSensor;
    private TraceEventSession? _session;
    private Task? _processingTask;
    private CancellationTokenSource? _cts;
    private bool _isRunning;

    // Topology cache: maps slot/port to known device IDs
    private readonly ConcurrentDictionary<int, string> _portToDeviceMap = new();
    private readonly ConcurrentDictionary<string, string> _slotToDeviceMap = new(StringComparer.OrdinalIgnoreCase);

    // Observability metrics
    private long _eventsReceived;
    private long _packetsIngested;
    private long _bytesIngested;
    private long _errorCount;
    private string? _lastError;

    public string SessionName { get; }
    public bool IsRunning => _isRunning;
    public long EventsReceived => Interlocked.Read(ref _eventsReceived);
    public long PacketsIngested => Interlocked.Read(ref _packetsIngested);
    public long BytesIngested => Interlocked.Read(ref _bytesIngested);
    public long ErrorCount => Interlocked.Read(ref _errorCount);
    public string? LastError => _lastError;

    public event Action<RawCaptureEvent>? OnPacketCaptured;
    public event Action<TraceEvent>? OnRawEtwEvent;

    public UsbEtwSensor(OmniTraceEventBus bus, UsbDeviceSensor? usbSensor = null, string sessionName = DefaultSessionName)
    {
        _bus = bus ?? throw new ArgumentNullException(nameof(bus));
        _usbSensor = usbSensor ?? bus.UsbSensor;
        SessionName = sessionName;
    }

    public void Start()
    {
        if (_isRunning) return;

        try
        {
            // 1. Elevation check: ETW kernel sessions require administrative privileges.
            bool? isElevated = TraceEventSession.IsElevated();
            if (isElevated == false)
            {
                _lastError = "Administrator privileges required to start real-time ETW kernel session.";
                _bus.ReportAnomaly("ETW_ELEVATION_REQUIRED", _lastError);
                return;
            }

            // 2. Clear any lingering session with the same name from previous runs
            try
            {
                var existing = TraceEventSession.GetActiveSession(SessionName);
                if (existing != null)
                {
                    existing.Stop();
                    existing.Dispose();
                }
            }
            catch { }

            // 3. Create real-time ETW session with 128 MB buffer for high throughput
            _session = new TraceEventSession(SessionName, TraceEventSessionOptions.Create)
            {
                BufferSizeMB = 128
            };

            // 4. Enable USB xHCI, Hub3, UCX, and Serial providers with targeted data keywords
            // Analytic channel (0x4000000000000000UL) + Transfer/Debug channel (0x8000000000000000UL)
            // at Verbose level is REQUIRED for Windows xHCI to emit packet payload buffers (fid_Data / Buffer).
            ulong xhciKeywords = 0x40000000000385D5UL | 0x8000000000000000UL;
            ulong ucxKeywords  = 0x80000000000385D5UL;
            ulong hub3Keywords = 0x4000000000038415UL | 0x8000000000000000UL;
            ulong portKeywords = 0x01;
            ulong serialKeywords = 0x40000000000007E0UL | 0x8000000000000000UL;

            _session.EnableProvider(XhciProviderGuid, TraceEventLevel.Verbose, matchAnyKeywords: xhciKeywords);
            _session.EnableProvider(Hub3ProviderGuid, TraceEventLevel.Informational, matchAnyKeywords: hub3Keywords);
            _session.EnableProvider(UcxProviderGuid, TraceEventLevel.Verbose, matchAnyKeywords: ucxKeywords);
            _session.EnableProvider(UsbPortProviderGuid, TraceEventLevel.Informational, matchAnyKeywords: portKeywords);
            _session.EnableProvider(SerialClassExtensionV2Guid, TraceEventLevel.Verbose, matchAnyKeywords: serialKeywords);
            _session.EnableProvider(SerialClassExtensionGuid, TraceEventLevel.Verbose, matchAnyKeywords: 0xC000000000000000UL);

            // 5. Subscribe to dynamic parser events
            _session.Source.Dynamic.All += HandleTraceEvent;

            // 6. Launch background worker thread for event processing
            _cts = new CancellationTokenSource();
            _processingTask = Task.Factory.StartNew(() =>
            {
                try
                {
                    _session.Source.Process();
                }
                catch (Exception ex)
                {
                    if (_isRunning)
                    {
                        Interlocked.Increment(ref _errorCount);
                        _lastError = ex.Message;
                        _bus.ReportAnomaly("ETW_PROCESS_ERROR", ex.Message);
                    }
                }
            }, TaskCreationOptions.LongRunning);

            _isRunning = true;
        }
        catch (Exception ex)
        {
            Interlocked.Increment(ref _errorCount);
            _lastError = ex.Message;
            _bus.ReportAnomaly("ETW_SESSION_START_FAILED", ex.Message);
            // Fail-open: do not crash the service or block other sensors
        }
    }

    public void HandleTraceEvent(TraceEvent data)
    {
        try
        {
            // 1. Provider validation: process events from USBXHCI, USBHUB3, UCX, USBPORT, or Serial providers
            bool isSerialProvider = data.ProviderGuid == SerialClassExtensionV2Guid ||
                                    data.ProviderGuid == SerialClassExtensionGuid ||
                                    (!string.IsNullOrEmpty(data.ProviderName) && data.ProviderName.Contains("Serial", StringComparison.OrdinalIgnoreCase));

            if (!isSerialProvider &&
                data.ProviderGuid != XhciProviderGuid &&
                data.ProviderGuid != Hub3ProviderGuid &&
                data.ProviderGuid != UcxProviderGuid &&
                data.ProviderGuid != UsbPortProviderGuid &&
                !string.Equals(data.ProviderName, "Microsoft-Windows-USB-USBXHCI", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(data.ProviderName, "Microsoft-Windows-USB-USBHUB3", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(data.ProviderName, "Microsoft-Windows-USB-UCX", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(data.ProviderName, "Microsoft-Windows-USB-USBPORT", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            Interlocked.Increment(ref _eventsReceived);
            OnRawEtwEvent?.Invoke(data);

            string evtName = data.EventName ?? string.Empty;
            int eventId = (int)data.ID;

            // 2. Identify event category: Transfer vs Rundown/Management
            bool isTransferEvent =
                isSerialProvider ||
                evtName.Contains("Transfer", StringComparison.OrdinalIgnoreCase) ||
                evtName.Contains("Urb", StringComparison.OrdinalIgnoreCase) ||
                evtName.Contains("Bulk", StringComparison.OrdinalIgnoreCase) ||
                evtName.Contains("ClientRequest", StringComparison.OrdinalIgnoreCase) ||
                evtName.Contains("Submit", StringComparison.OrdinalIgnoreCase) ||
                evtName.Contains("DataBusTrace", StringComparison.OrdinalIgnoreCase) ||
                evtName.Contains("BusTrace", StringComparison.OrdinalIgnoreCase) ||
                evtName.Contains("Pipe", StringComparison.OrdinalIgnoreCase) ||
                evtName.Contains("IO", StringComparison.OrdinalIgnoreCase) ||
                eventId == 41 || eventId == 42 || eventId == 92 || eventId == 93 ||
                eventId == 100 || eventId == 101 || eventId == 102;

            bool isRundownOrManagement =
                evtName.Contains("Rundown", StringComparison.OrdinalIgnoreCase) ||
                evtName.Contains("Controller", StringComparison.OrdinalIgnoreCase) ||
                evtName.Contains("TimeSync", StringComparison.OrdinalIgnoreCase) ||
                evtName.Contains("SaveState", StringComparison.OrdinalIgnoreCase) ||
                evtName.Contains("RestoreState", StringComparison.OrdinalIgnoreCase) ||
                evtName.Contains("D0Entry", StringComparison.OrdinalIgnoreCase) ||
                evtName.Contains("D0Exit", StringComparison.OrdinalIgnoreCase) ||
                evtName.Contains("Health", StringComparison.OrdinalIgnoreCase) ||
                evtName.Contains("PartitionInfo", StringComparison.OrdinalIgnoreCase);

            // If this is purely a rundown/topology/state event, update topology cache without creating fake USB packets
            if (isRundownOrManagement && !isTransferEvent)
            {
                UpdateTopologyFromEvent(data);
                return;
            }

            // 3. Process Attribution (PID and Process Name)
            int pid = data.ProcessID;
            string procName = data.ProcessName ?? string.Empty;

            var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["EtwProvider"] = data.ProviderName ?? "",
                ["EtwProviderGuid"] = data.ProviderGuid.ToString(),
                ["EtwEventName"] = evtName,
                ["EtwEventId"] = eventId.ToString(),
                ["Timestamp"] = data.TimeStamp.ToString("o")
            };

            string deviceId = "USB_UNKNOWN";
            int? portNumber = null;
            string? slotId = null;
            int ifaceIndex = 0;
            string endpointAddress = "0x00";
            PacketDirection direction = PacketDirection.HOST_TO_DEVICE;
            TransportType transport = isSerialProvider ? TransportType.SERIAL : TransportType.BULK;
            byte[]? payload = null;

            if (isSerialProvider)
            {
                if (evtName.Contains("Transmit", StringComparison.OrdinalIgnoreCase) || evtName.Contains("Write", StringComparison.OrdinalIgnoreCase))
                {
                    direction = PacketDirection.HOST_TO_DEVICE;
                }
                else if (evtName.Contains("Receive", StringComparison.OrdinalIgnoreCase) || evtName.Contains("Read", StringComparison.OrdinalIgnoreCase))
                {
                    direction = PacketDirection.DEVICE_TO_HOST;
                }
            }

            foreach (string name in data.PayloadNames)
            {
                try
                {
                    object? val = data.PayloadByName(name);
                    if (val == null) continue;

                    string valStr = val.ToString() ?? "";
                    metadata[name] = valStr;

                    // Check for true initiating PID in payload (common when DPC completed in PID 4/0)
                    if ((pid <= 4 || string.IsNullOrWhiteSpace(procName)) &&
                        (name.Equals("ProcessId", StringComparison.OrdinalIgnoreCase) ||
                         name.Equals("fid_ProcessId", StringComparison.OrdinalIgnoreCase) ||
                         name.Equals("ClientId", StringComparison.OrdinalIgnoreCase)))
                    {
                        if (int.TryParse(valStr, out int p) && p > 4)
                        {
                            pid = p;
                        }
                    }

                    // Port extraction
                    if (portNumber == null && (name.Equals("Port", StringComparison.OrdinalIgnoreCase) ||
                                               name.Equals("PortNumber", StringComparison.OrdinalIgnoreCase) ||
                                               name.Equals("fid_PortNumber", StringComparison.OrdinalIgnoreCase) ||
                                               name.Equals("HubPort", StringComparison.OrdinalIgnoreCase)))
                    {
                        if (int.TryParse(valStr, out int p) && p > 0) portNumber = p;
                    }

                    // Slot ID extraction for topology correlation
                    if (slotId == null && (name.Equals("fid_SlotId", StringComparison.OrdinalIgnoreCase) ||
                                           name.Equals("SlotId", StringComparison.OrdinalIgnoreCase)))
                    {
                        slotId = valStr;
                    }

                    // Device identity: ONLY accept valid USB device strings, reject booleans, pointers, integers
                    if (valStr.StartsWith("USB\\", StringComparison.OrdinalIgnoreCase) ||
                        valStr.Contains("VID_", StringComparison.OrdinalIgnoreCase) ||
                        name.Equals("DeviceInstanceId", StringComparison.OrdinalIgnoreCase) ||
                        name.Equals("DriverKeyName", StringComparison.OrdinalIgnoreCase))
                    {
                        deviceId = valStr;
                    }

                    // Endpoint extraction and direction inference from MSB
                    if (name.Contains("Endpoint", StringComparison.OrdinalIgnoreCase) ||
                        name.Contains("Pipe", StringComparison.OrdinalIgnoreCase))
                    {
                        if (val is byte bVal && bVal > 0)
                        {
                            endpointAddress = $"0x{bVal:X2}";
                            direction = (bVal & 0x80) != 0 ? PacketDirection.DEVICE_TO_HOST : PacketDirection.HOST_TO_DEVICE;
                        }
                        else if (int.TryParse(valStr, out int epInt) && epInt > 0 && epInt <= 0xFF)
                        {
                            endpointAddress = $"0x{(byte)epInt:X2}";
                            direction = (epInt & 0x80) != 0 ? PacketDirection.DEVICE_TO_HOST : PacketDirection.HOST_TO_DEVICE;
                        }
                        else if (valStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase) && valStr.Length <= 4)
                        {
                            endpointAddress = valStr;
                            if (byte.TryParse(valStr.Substring(2), System.Globalization.NumberStyles.HexNumber, null, out byte epByte))
                            {
                                direction = (epByte & 0x80) != 0 ? PacketDirection.DEVICE_TO_HOST : PacketDirection.HOST_TO_DEVICE;
                            }
                        }
                    }

                    // Interface extraction
                    if (name.Equals("InterfaceNumber", StringComparison.OrdinalIgnoreCase) ||
                        name.Equals("fid_InterfaceNumber", StringComparison.OrdinalIgnoreCase) ||
                        name.Equals("Interface", StringComparison.OrdinalIgnoreCase))
                    {
                        if (int.TryParse(valStr, out int iface)) ifaceIndex = iface;
                    }

                    // Explicit transfer direction fields
                    if (name.Equals("Direction", StringComparison.OrdinalIgnoreCase) ||
                        name.Equals("TransferDirection", StringComparison.OrdinalIgnoreCase) ||
                        name.Equals("fid_Direction", StringComparison.OrdinalIgnoreCase))
                    {
                        if (string.Equals(valStr, "In", StringComparison.OrdinalIgnoreCase) || valStr == "1")
                        {
                            direction = PacketDirection.DEVICE_TO_HOST;
                        }
                        else if (string.Equals(valStr, "Out", StringComparison.OrdinalIgnoreCase) || valStr == "0")
                        {
                            direction = PacketDirection.HOST_TO_DEVICE;
                        }
                    }

                    // Transfer type
                    if (name.Contains("TransferType", StringComparison.OrdinalIgnoreCase) ||
                        name.Contains("UrbFunction", StringComparison.OrdinalIgnoreCase))
                    {
                        if (valStr.Contains("Control", StringComparison.OrdinalIgnoreCase)) transport = TransportType.CONTROL;
                        else if (valStr.Contains("Interrupt", StringComparison.OrdinalIgnoreCase)) transport = TransportType.INTERRUPT;
                        else transport = TransportType.BULK;
                    }

                    // Payload extraction from dedicated data buffer properties
                    if (payload == null && (name.Equals("Buffer", StringComparison.OrdinalIgnoreCase) ||
                                           name.Equals("Data", StringComparison.OrdinalIgnoreCase) ||
                                           name.Equals("Payload", StringComparison.OrdinalIgnoreCase) ||
                                           name.Equals("TransferBuffer", StringComparison.OrdinalIgnoreCase) ||
                                           name.Equals("PacketData", StringComparison.OrdinalIgnoreCase) ||
                                           name.Equals("fid_Data", StringComparison.OrdinalIgnoreCase) ||
                                           name.Equals("fid_Buffer", StringComparison.OrdinalIgnoreCase) ||
                                           name.Equals("fid_Payload", StringComparison.OrdinalIgnoreCase) ||
                                           name.Equals("fid_TransferBuffer", StringComparison.OrdinalIgnoreCase)))
                    {
                        if (val is byte[] rawBytes && rawBytes.Length > 0)
                        {
                            payload = rawBytes;
                        }
                    }
                }
                catch { }
            }

            // Resolve process name
            if ((string.IsNullOrWhiteSpace(procName) || procName.Equals("System", StringComparison.OrdinalIgnoreCase)) && pid > 4)
            {
                try
                {
                    procName = Process.GetProcessById(pid).ProcessName;
                }
                catch { }
            }
            if (string.IsNullOrWhiteSpace(procName))
            {
                procName = pid <= 4 ? "System/Kernel" : $"PID_{pid}";
            }
            metadata["ProcessId"] = pid.ToString();
            metadata["ProcessName"] = procName;

            // Resolve device identity from topology map if not explicit
            if (deviceId == "USB_UNKNOWN")
            {
                if (portNumber != null && _portToDeviceMap.TryGetValue(portNumber.Value, out var mappedDev))
                {
                    deviceId = mappedDev;
                }
                else if (slotId != null && _slotToDeviceMap.TryGetValue(slotId, out var slotDev))
                {
                    deviceId = slotDev;
                }
                else if (portNumber != null)
                {
                    deviceId = $"USB\\PORT_{portNumber}";
                }
                else
                {
                    deviceId = isSerialProvider ? "SERIAL\\MODEM_PORT" : "USB\\ROOT_HUB30";
                }
            }

            // Check event name specifically for transfer completion / IN semantics
            if (evtName.EndsWith("_In", StringComparison.OrdinalIgnoreCase) ||
                evtName.Contains("TransferIn", StringComparison.OrdinalIgnoreCase) ||
                evtName.Contains("ReadComplete", StringComparison.OrdinalIgnoreCase))
            {
                direction = PacketDirection.DEVICE_TO_HOST;
            }

            // Assign safe payload: if dedicated buffer was not present, check if event is raw bus trace
            if (payload == null || payload.Length == 0)
            {
                if (data.EventDataLength > 0 &&
                    (evtName.Contains("DataBusTrace", StringComparison.OrdinalIgnoreCase) ||
                     evtName.Contains("Payload", StringComparison.OrdinalIgnoreCase)))
                {
                    try
                    {
                        payload = data.EventData();
                    }
                    catch
                    {
                        payload = Array.Empty<byte>();
                    }
                }
                else
                {
                    payload = Array.Empty<byte>();
                }
            }

            string session = $"ETW_PID_{pid}_{procName}";

            var rawEvt = _usbSensor.IngestUsbPacket(
                deviceId: deviceId,
                interfaceIndex: ifaceIndex,
                endpointAddress: endpointAddress,
                direction: direction,
                payload: payload,
                transportSession: session,
                metadata: metadata,
                sensor: isSerialProvider ? SensorType.Serial : SensorType.ETW,
                transport: transport
            );

            Interlocked.Increment(ref _packetsIngested);
            Interlocked.Add(ref _bytesIngested, payload.Length);
            OnPacketCaptured?.Invoke(rawEvt);
        }
        catch (Exception ex)
        {
            Interlocked.Increment(ref _errorCount);
            _lastError = ex.Message;
            _bus.ReportAnomaly("ETW_EVENT_PARSE_ERROR", ex.Message);
        }
    }

    private void UpdateTopologyFromEvent(TraceEvent data)
    {
        try
        {
            int? port = null;
            string? slot = null;
            string? devId = null;

            foreach (string name in data.PayloadNames)
            {
                object? val = data.PayloadByName(name);
                if (val == null) continue;
                string valStr = val.ToString() ?? "";

                if (name.Contains("Port", StringComparison.OrdinalIgnoreCase) && int.TryParse(valStr, out int p) && p > 0)
                {
                    port = p;
                }
                if (name.Contains("Slot", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(valStr))
                {
                    slot = valStr;
                }
                if (valStr.StartsWith("USB\\", StringComparison.OrdinalIgnoreCase) || valStr.Contains("VID_", StringComparison.OrdinalIgnoreCase))
                {
                    devId = valStr;
                }
            }

            if (devId != null)
            {
                if (port != null) _portToDeviceMap[port.Value] = devId;
                if (slot != null) _slotToDeviceMap[slot] = devId;
            }
        }
        catch { }
    }

    public RawCaptureEvent SimulateIngestPacket(
        string deviceId,
        int portNumber,
        int pid,
        string procName,
        int ifaceIndex,
        string endpointAddress,
        PacketDirection direction,
        byte[] payload,
        string eventName = "UsbBulkTransferSubmit",
        string providerName = "Microsoft-Windows-USB-USBXHCI")
    {
        var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["EtwProvider"] = providerName,
            ["EtwEventName"] = eventName,
            ["ProcessId"] = pid.ToString(),
            ["ProcessName"] = procName,
            ["Port"] = portNumber.ToString(),
            ["Endpoint"] = endpointAddress
        };

        var rawEvt = _usbSensor.IngestUsbPacket(
            deviceId: deviceId,
            interfaceIndex: ifaceIndex,
            endpointAddress: endpointAddress,
            direction: direction,
            payload: payload,
            transportSession: $"ETW_PID_{pid}_{procName}",
            metadata: metadata,
            sensor: SensorType.ETW,
            transport: TransportType.BULK
        );

        Interlocked.Increment(ref _packetsIngested);
        Interlocked.Add(ref _bytesIngested, payload.Length);
        OnPacketCaptured?.Invoke(rawEvt);
        return rawEvt;
    }

    public void Stop()
    {
        if (!_isRunning) return;
        _isRunning = false;

        try
        {
            _cts?.Cancel();
            _session?.Source?.StopProcessing();
        }
        catch { }

        try
        {
            _processingTask?.Wait(1500);
        }
        catch { }

        try
        {
            _session?.Stop();
            _session?.Dispose();
        }
        catch { }
        finally
        {
            _session = null;
            _cts?.Dispose();
            _cts = null;
            _processingTask = null;
        }
    }

    public void Dispose()
    {
        Stop();
    }
}
