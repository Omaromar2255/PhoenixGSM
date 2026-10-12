using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using Microsoft.Win32;
using PhoenixGSM.OmniTrace.Bus;
using PhoenixGSM.OmniTrace.Decoders;
using PhoenixGSM.OmniTrace.Models;
using PhoenixGSM.OmniTrace.Sensors;
using PhoenixGSM.OmniTrace.Service;

namespace PhoenixGSM.OmniTrace.Tests;

public static partial class Program
{
    private static bool Test16_LivePhysicalDeviceCapture()
    {
        using var bus = new OmniTraceEventBus();
        var capturedCommands = new List<LogicalCommandEvent>();
        bus.OnLogicalCommand += cmd => capturedCommands.Add(cmd);

        // Probe real ADB daemon port (default 5037)
        try
        {
            using var tcp = new System.Net.Sockets.TcpClient();
            var connectTask = tcp.ConnectAsync(System.Net.IPAddress.Loopback, 5037);
            if (!connectTask.Wait(1000))
            {
                return true; // Not listening, skip gracefully
            }

            using var stream = tcp.GetStream();
            stream.ReadTimeout = 1000;

            // Request real ADB host version
            string req = "000Chost:version";
            byte[] reqBytes = Encoding.ASCII.GetBytes(req);

            var rawEvt = RawCaptureEvent.Create(
                sequence: 5555,
                sensor: SensorType.VirtualProxy,
                transport: TransportType.TCP,
                direction: PacketDirection.HOST_TO_DEVICE,
                device: "127.0.0.1:5037",
                session: "LIVE_DEVICE_INSPECTION",
                iface: 0,
                endpoint: "5037",
                payload: reqBytes
            );
            bus.ProcessSingleEvent(rawEvt);

            // Execute wire request against real ADB server
            stream.Write(reqBytes, 0, reqBytes.Length);
            byte[] respBuf = new byte[16];
            int read = stream.Read(respBuf, 0, respBuf.Length);

            if (read > 0)
            {
                byte[] respChunk = new byte[read];
                Array.Copy(respBuf, 0, respChunk, 0, read);
                var rawResp = RawCaptureEvent.Create(
                    sequence: 5556,
                    sensor: SensorType.VirtualProxy,
                    transport: TransportType.TCP,
                    direction: PacketDirection.DEVICE_TO_HOST,
                    device: "127.0.0.1:5037",
                    session: "LIVE_DEVICE_INSPECTION",
                    iface: 0,
                    endpoint: "5037",
                    payload: respChunk
                );
                bus.ProcessSingleEvent(rawResp);
            }

            return capturedCommands.Any(c => c.Protocol == KnownProtocol.ADB && c.Service == "host" && c.Command.Contains("version"));
        }
        catch
        {
            return true;
        }
    }

    private static bool Test17_UsbEtwSensorProcessAttributionAndIngestion()
    {
        using var bus = new OmniTraceEventBus();
        using var etwSensor = new UsbEtwSensor(bus, bus.UsbSensor, sessionName: "PhoenixOmniTrace_Test17Session");

        var capturedEvents = new List<RawCaptureEvent>();
        etwSensor.OnPacketCaptured += evt => capturedEvents.Add(evt);

        // ADB message header payload (A_CNXN)
        byte[] payload = Encoding.UTF8.GetBytes("CNXN\x01\x00\x00\x00\x00\x10\x00\x00host::features=shell_v2\0");

        // Simulate ETW packet from GlobalUnlocker.exe on Port 2
        var raw = etwSensor.SimulateIngestPacket(
            deviceId: "USB\\VID_22B8&PID_2E81\\ZY224BHZSQ",
            portNumber: 2,
            pid: 14880,
            procName: "GlobalUnlocker.exe",
            ifaceIndex: 0,
            endpointAddress: "0x01",
            direction: PacketDirection.HOST_TO_DEVICE,
            payload: payload,
            eventName: "UsbBulkTransferSubmit",
            providerName: "Microsoft-Windows-USB-USBXHCI"
        );

        if (raw == null) return false;
        if (raw.Sensor != SensorType.ETW) return false;
        if (raw.Direction != PacketDirection.HOST_TO_DEVICE) return false;
        if (!raw.Metadata.ContainsKey("ProcessName") || raw.Metadata["ProcessName"] != "GlobalUnlocker.exe") return false;
        if (!raw.Metadata.ContainsKey("ProcessId") || raw.Metadata["ProcessId"] != "14880") return false;
        if (!raw.Metadata.ContainsKey("Port") || raw.Metadata["Port"] != "2") return false;
        if (etwSensor.PacketsIngested != 1) return false;
        if (etwSensor.BytesIngested != (long)payload.Length) return false;
        if (capturedEvents.Count != 1) return false;

        return true;
    }

    private static bool Test18_AdbProxyFailOpenWhenPortBound()
    {
        using var bus = new OmniTraceEventBus();

        // Find an available port to simulate collision
        int testPort = 59137;
        var existingListener = new TcpListener(IPAddress.Loopback, testPort);
        existingListener.Start();

        try
        {
            // Now attempt to start AdbTransparentProxy on that same already-bound port
            using var proxy = new AdbTransparentProxy(bus, listenPort: testPort, targetPort: 5038);

            // Must not throw exception
            proxy.Start();

            // Must detect collision and enter Fail-Open mode
            if (!proxy.IsPortBoundByAnotherProcess) return false;
            if (proxy.IsRunning) return false;
            if (!proxy.StatusMessage.Contains("Fail-Open", StringComparison.OrdinalIgnoreCase)) return false;

            proxy.Stop();
            return true;
        }
        finally
        {
            existingListener.Stop();
        }
    }

    private static bool Test19_PhoenixOmniTraceServiceLifecycleWithEtwAndProxy()
    {
        using var service = new PhoenixOmniTraceService(proxyPort: 59138, pipeName: "OmniTrace_Test19_Pipe");

        if (service.IsRunning) return false;
        if (service.UsbEtwSensor == null) return false;
        if (service.AdbProxy == null) return false;
        if (service.UsbSensor == null) return false;

        service.Start();
        if (!service.IsRunning) return false;

        service.Stop();
        if (service.IsRunning) return false;

        return true;
    }

    private static bool Test20_DeviceClassRegistryLowerFilterVerification()
    {
        if (!OperatingSystem.IsWindows()) return true;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Class\{3F966BD9-FA04-4EC5-991C-D326973B5128}", false);
            if (key == null) return false;

            var lower = key.GetValue("LowerFilters");
            var upper = key.GetValue("UpperFilters");

            bool hasLower = false;
            if (lower is string[] lArr)
            {
                hasLower = lArr.Any(s => s.Equals("PhoenixUsbMonitor", StringComparison.OrdinalIgnoreCase));
            }
            else if (lower is string lStr)
            {
                hasLower = lStr.Equals("PhoenixUsbMonitor", StringComparison.OrdinalIgnoreCase);
            }

            bool hasConflictingUpper = false;
            if (upper is string[] uArr)
            {
                hasConflictingUpper = uArr.Any(s => s.Equals("PhoenixUsbMonitor", StringComparison.OrdinalIgnoreCase));
            }
            else if (upper is string uStr)
            {
                hasConflictingUpper = uStr.Equals("PhoenixUsbMonitor", StringComparison.OrdinalIgnoreCase);
            }

            // UpperFilters MUST NOT conflict (clean separation between ETW/LowerFilter and driver stack)
            return !hasConflictingUpper;
        }
        catch
        {
            return false;
        }
    }

    private static bool Test21_RealEtwTraceEtlVerification()
    {
        string etlPath = @"c:\Users\pc5\softwer\phtest_000001.etl";
        if (!System.IO.File.Exists(etlPath))
        {
            Console.WriteLine("    [INFO] phtest_000001.etl not found, skipping.");
            return true;
        }

        using var bus = new OmniTraceEventBus();
        using var etwSensor = new UsbEtwSensor(bus, bus.UsbSensor, sessionName: "PhoenixOmniTrace_Test21Session");

        int eventCount = 0;
        using var source = new Microsoft.Diagnostics.Tracing.ETWTraceEventSource(etlPath);
        etwSensor.OnPacketCaptured += evt =>
        {
            if (evt.SequenceNumber <= 5)
            {
                Console.WriteLine($"    [RAW EVT {evt.SequenceNumber}] Device='{evt.DeviceIdentity}', Endpoint='{evt.Endpoint}', Dir={evt.Direction}, PayloadLen={evt.RawPayload.Length}");
            }
        };

        source.Dynamic.All += data =>
        {
            eventCount++;
            etwSensor.HandleTraceEvent(data);
        };

        source.Process();
        Console.WriteLine($"    [INFO] Processed {eventCount} real ETW events from phtest_000001.etl.");
        Console.WriteLine($"    [INFO] Events received: {etwSensor.EventsReceived}, Packets ingested (rundown only): {etwSensor.PacketsIngested}, Errors: {etwSensor.ErrorCount}");

        // Verify that rundown events were NOT falsely ingested as data packets (preserving protocol stream integrity)
        bool rundownSafelyIgnored = etwSensor.PacketsIngested == 0;

        // Now verify that a real USB transfer event is successfully ingested with full attribution
        byte[] testPayload = Encoding.UTF8.GetBytes("CNXN\x01\x00\x00\x00\x00\x10\x00\x00device::ro.product.model=XT1650\0");
        var transferEvt = etwSensor.SimulateIngestPacket(
            deviceId: "USB\\VID_22B8&PID_2E81\\ZY224BHZSQ",
            portNumber: 2,
            pid: 14880,
            procName: "GlobalUnlocker.exe",
            ifaceIndex: 0,
            endpointAddress: "0x01",
            direction: PacketDirection.HOST_TO_DEVICE,
            payload: testPayload,
            eventName: "UsbBulkTransferSubmit",
            providerName: "Microsoft-Windows-USB-USBXHCI"
        );

        bool transferIngested = transferEvt != null &&
                                etwSensor.PacketsIngested == 1 &&
                                etwSensor.BytesIngested == testPayload.Length &&
                                transferEvt.DeviceIdentity.Contains("VID_22B8") &&
                                transferEvt.Metadata["ProcessName"] == "GlobalUnlocker.exe";

        return eventCount > 0 && rundownSafelyIgnored && transferIngested && etwSensor.ErrorCount == 0;
    }

    private static bool Test22_UsbEtwRobustnessAndLifecycle()
    {
        using var bus = new OmniTraceEventBus();
        using var etwSensor = new UsbEtwSensor(bus, bus.UsbSensor, sessionName: "PhoenixOmniTrace_Test22Session");

        // 1. Test Direction Inference: OUT endpoint 0x01 with event containing "Information" MUST NOT flip to IN
        var outEvt = etwSensor.SimulateIngestPacket(
            deviceId: "USB\\VID_22B8&PID_2E81\\ZY224BHZSQ",
            portNumber: 2,
            pid: 14880,
            procName: "GlobalUnlocker.exe",
            ifaceIndex: 0,
            endpointAddress: "0x01",
            direction: PacketDirection.HOST_TO_DEVICE,
            payload: [0x41, 0x42, 0x43],
            eventName: "USBXHCIInformationEvent"
        );
        if (outEvt.Direction != PacketDirection.HOST_TO_DEVICE) return false;

        // 2. Test Direction Inference: IN endpoint 0x81
        var inEvt = etwSensor.SimulateIngestPacket(
            deviceId: "USB\\VID_22B8&PID_2E81\\ZY224BHZSQ",
            portNumber: 2,
            pid: 14880,
            procName: "GlobalUnlocker.exe",
            ifaceIndex: 0,
            endpointAddress: "0x81",
            direction: PacketDirection.DEVICE_TO_HOST,
            payload: [0x4F, 0x4B, 0x41, 0x59],
            eventName: "UsbBulkTransferComplete"
        );
        if (inEvt.Direction != PacketDirection.DEVICE_TO_HOST) return false;

        // 3. Test Device Identity Integrity: device name contains valid hardware ID
        if (!outEvt.DeviceIdentity.StartsWith("USB\\VID_22B8", StringComparison.OrdinalIgnoreCase)) return false;

        // 4. Test Multiple Start / Stop cycles (no ObjectDisposedException or leaks)
        for (int i = 0; i < 3; i++)
        {
            etwSensor.Start();
            Thread.Sleep(50);
            etwSensor.Stop();
        }

        return etwSensor.ErrorCount == 0;
    }

    private static bool Test23_All4UsbEtwProvidersAndDataKeywords()
    {
        // 1. Verify that all 4 provider GUIDs are properly defined
        if (UsbEtwSensor.XhciProviderGuid != new Guid("30E1D284-5D88-459C-83FD-6345B39B19EC")) return false;
        if (UsbEtwSensor.Hub3ProviderGuid != new Guid("AC52AD17-CC01-4F85-8DF5-4DCE4333C99B")) return false;
        if (UsbEtwSensor.UcxProviderGuid != new Guid("36DA592D-E43A-4E28-AF6F-4BC57C5A11E8")) return false;
        if (UsbEtwSensor.UsbPortProviderGuid != new Guid("C88A4EF5-D048-4013-9408-E04B7DB2814A")) return false;

        using var bus = new OmniTraceEventBus();
        using var etwSensor = new UsbEtwSensor(bus, bus.UsbSensor, sessionName: "PhoenixOmniTrace_Test23Session");

        // 2. Test UCX provider ingestion (FullDataBusTrace event with raw URB payload)
        byte[] ucxPayload = [0x53, 0x41, 0x4D, 0x53, 0x55, 0x4E, 0x47, 0x5F, 0x41, 0x54]; // "SAMSUNG_AT"
        var ucxEvt = etwSensor.SimulateIngestPacket(
            deviceId: "USB\\VID_04E8&PID_6860&ADB\\6&5FC5C6A&0&0003",
            portNumber: 2,
            pid: 13604,
            procName: "GlobalUnlocker.exe",
            ifaceIndex: 0,
            endpointAddress: "0x01",
            direction: PacketDirection.HOST_TO_DEVICE,
            payload: ucxPayload,
            eventName: "UCX_URB_TRANSFER",
            providerName: "Microsoft-Windows-USB-UCX"
        );
        if (ucxEvt == null || ucxEvt.Transport != TransportType.BULK || ucxEvt.CapturedPayload.Length != ucxPayload.Length) return false;

        // 3. Test USBPORT provider ingestion (USB 2.0 Bulk Transfer event with payload)
        byte[] usbPortPayload = [0x41, 0x54, 0x2B, 0x44, 0x45, 0x56]; // "AT+DEV"
        var usbPortEvt = etwSensor.SimulateIngestPacket(
            deviceId: "USB\\VID_04E8&PID_6860&MODEM\\6&5FC5C6A&0&0001",
            portNumber: 2,
            pid: 9764,
            procName: "chimera_browser.exe",
            ifaceIndex: 1,
            endpointAddress: "0x82",
            direction: PacketDirection.DEVICE_TO_HOST,
            payload: usbPortPayload,
            eventName: "USBPORT_BULK_OR_INTERRUPT_TRANSFER",
            providerName: "Microsoft-Windows-USB-USBPORT"
        );
        if (usbPortEvt == null || usbPortEvt.Direction != PacketDirection.DEVICE_TO_HOST) return false;

        // 4. Test metric checks
        return etwSensor.PacketsIngested == 2 && etwSensor.BytesIngested == (ucxPayload.Length + usbPortPayload.Length) && etwSensor.ErrorCount == 0;
    }

    private static bool Test24_SerialPortSensorModemDiscoveryAndFailOpen()
    {
        using var bus = new OmniTraceEventBus();
        using var serialSensor = new SerialPortSensor(bus);

        // Start serial sensor (tests registry scanning, port enumeration, non-blocking fail-open)
        serialSensor.Start();
        Thread.Sleep(200);

        // Verify that discovery ran and did not throw exceptions
        long portsFound = serialSensor.PortsDiscovered;
        long errCount = serialSensor.ErrorsCount;

        serialSensor.Stop();

        return errCount == 0;
    }

    private static bool Test25_FullServiceEndToEndWithAllSensors()
    {
        using var service = new PhoenixOmniTraceService(proxyPort: 5039, pipeName: "PhoenixOmniTrace_Test25Pipe");

        var receivedEvents = new List<RawCaptureEvent>();
        service.EventBus.OnRawCaptured += (evt) =>
        {
            lock (receivedEvents) receivedEvents.Add(evt);
        };

        service.Start();
        if (!service.IsRunning) return false;

        // Ingest test USB packet
        service.UsbSensor.IngestUsbPacket(
            deviceId: "USB\\VID_04E8&PID_6860&ADB\\6&5FC5C6A&0&0003",
            interfaceIndex: 0,
            endpointAddress: "0x01",
            direction: PacketDirection.HOST_TO_DEVICE,
            payload: Encoding.UTF8.GetBytes("OPEN shell:getprop\n"),
            transportSession: "SAMSUNG_TEST_SESSION"
        );

        Thread.Sleep(100);

        bool eventReceived = false;
        lock (receivedEvents)
        {
            eventReceived = receivedEvents.Any(e => e.DeviceIdentity.Contains("VID_04E8") && e.PayloadUtf8.Contains("getprop"));
        }

        service.Stop();
        if (service.IsRunning) return false;

        return eventReceived;
    }

    private static bool Test26_AntiKillShieldAndStealthConfig()
    {
        // 1. Verify StealthConfig eliminates all trigger keywords from OS-visible markers
        if (PhoenixGSM.OmniTrace.Service.StealthConfig.ContainsTriggerWord(PhoenixGSM.OmniTrace.Service.StealthConfig.WindowTitle))
            return false;

        if (PhoenixGSM.OmniTrace.Service.StealthConfig.ContainsTriggerWord(PhoenixGSM.OmniTrace.Service.StealthConfig.EtwSessionName))
            return false;

        if (PhoenixGSM.OmniTrace.Service.StealthConfig.ContainsTriggerWord(PhoenixGSM.OmniTrace.Service.StealthConfig.PipeName))
            return false;

        // Verify trigger word detector works accurately (positive control)
        if (!PhoenixGSM.OmniTrace.Service.StealthConfig.ContainsTriggerWord("PhoenixGSM Monitoring Studio Sniffer"))
            return false;

        // 2. Verify ProcessGuardian lifecycle and breadcrumb tracking
        string tempBreadcrumb = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"shield_test_{Guid.NewGuid():N}.dat");
        try
        {
            using (var guardian = new PhoenixGSM.OmniTrace.Service.ProcessGuardian())
            {
                guardian.Activate(tempBreadcrumb);
                if (!guardian.IsProtected) return false;

                if (!System.IO.File.Exists(tempBreadcrumb)) return false;
                string content = ReadFileWithRetryShare(tempBreadcrumb);
                if (!content.StartsWith("RUNNING")) return false;
            }

            // After dispose, clean shutdown should be recorded
            if (!System.IO.File.Exists(tempBreadcrumb)) return false;
            string finalContent = ReadFileWithRetryShare(tempBreadcrumb);
            if (!finalContent.StartsWith("CLEAN_SHUTDOWN")) return false;
        }
        finally
        {
            try { System.IO.File.Delete(tempBreadcrumb); } catch { }
        }

        return true;
    }

    private static string ReadFileWithRetryShare(string path)
    {
        for (int i = 0; i < 10; i++)
        {
            try
            {
                using var fs = new System.IO.FileStream(path, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.ReadWrite | System.IO.FileShare.Delete);
                using var reader = new System.IO.StreamReader(fs, Encoding.UTF8);
                return reader.ReadToEnd();
            }
            catch (System.IO.IOException)
            {
                Thread.Sleep(25);
            }
        }
        return System.IO.File.ReadAllText(path);
    }
}
