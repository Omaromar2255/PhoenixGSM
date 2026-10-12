using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using PhoenixGSM.OmniTrace.Bus;
using PhoenixGSM.OmniTrace.Decoders;
using PhoenixGSM.OmniTrace.Detection;
using PhoenixGSM.OmniTrace.Ipc;
using PhoenixGSM.OmniTrace.Models;
using PhoenixGSM.OmniTrace.Reassembly;
using PhoenixGSM.OmniTrace.Sensors;
using PhoenixGSM.OmniTrace.Service;

namespace PhoenixGSM.OmniTrace.Tests;

public static partial class Program
{
    private static bool Test9_TcpAdbTransport()
    {
        using var bus = new OmniTraceEventBus();
        var capturedCommands = new List<LogicalCommandEvent>();
        bus.OnLogicalCommand += cmd => capturedCommands.Add(cmd);

        string request = "000Chost:version";
        var rawEvt = RawCaptureEvent.Create(
            sequence: 77,
            sensor: SensorType.Network,
            transport: TransportType.TCP,
            direction: PacketDirection.HOST_TO_DEVICE,
            device: "192.168.1.100:5555",
            session: "TCP_ADB_SESSION",
            iface: 0,
            endpoint: "5555",
            payload: Encoding.ASCII.GetBytes(request)
        );

        bus.ProcessSingleEvent(rawEvt);

        return capturedCommands.Any(c => c.Transport == TransportType.TCP && c.Protocol == KnownProtocol.ADB);
    }

    private static bool Test10_ArbitraryPortDiscovery()
    {
        Environment.SetEnvironmentVariable("ANDROID_ADB_SERVER_PORT", "5039");
        int port = AdbTransparentProxy.DiscoverAdbServerPort();
        Environment.SetEnvironmentVariable("ANDROID_ADB_SERVER_PORT", null);

        return port == 5039;
    }

    private static bool Test11_UnknownProtocolRobustness()
    {
        using var bus = new OmniTraceEventBus();
        var rng = new Random(42);
        byte[] randomNoise = new byte[256];
        rng.NextBytes(randomNoise);

        var rawEvt = RawCaptureEvent.Create(
            sequence: 88,
            sensor: SensorType.USB,
            transport: TransportType.BULK,
            direction: PacketDirection.HOST_TO_DEVICE,
            device: "UNKNOWN_CHIP_USB",
            session: "UNKNOWN_SESS",
            iface: 0,
            endpoint: "0x01",
            payload: randomNoise
        );

        bus.ProcessSingleEvent(rawEvt);
        var metrics = bus.GetMetrics();

        return metrics.UnknownEvents > 0 && metrics.ParserErrors == 0;
    }

    private static bool Test12_HighThroughputStress()
    {
        using var bus = new OmniTraceEventBus(10000);
        int totalPackets = 5000;

        for (int i = 0; i < totalPackets; i++)
        {
            var raw = RawCaptureEvent.Create(
                sequence: (ulong)i,
                sensor: SensorType.USB,
                transport: TransportType.BULK,
                direction: PacketDirection.HOST_TO_DEVICE,
                device: "STRESS_DEVICE",
                session: "STRESS_SESSION",
                iface: 0,
                endpoint: "0x01",
                payload: [0x01, 0x02, 0x03, 0x04]
            );
            bus.Publish(raw);
        }

        var metrics = bus.GetMetrics();
        return metrics.RawEventsCaptured == totalPackets && metrics.DroppedEvents == 0;
    }

    private static bool Test13_ParserFuzzing()
    {
        var wireDecoder = new AdbWireDecoder();
        var smartDecoder = new AdbSmartSocketDecoder();
        var detector = new ProtocolDetector();
        var shellRecon = new ShellStreamReconstructor();

        var fuzzCases = new List<byte[]>
        {
            Array.Empty<byte>(),
            new byte[] { 0x00 },
            new byte[] { 0xFF, 0xFF, 0xFF, 0xFF },
            new byte[] { 0x43, 0x4E, 0x58, 0x4E }, // partial 4 bytes
            new byte[23], // truncated 23-byte header
            new byte[24], // 24 zero bytes
            new byte[] { 0xC0, 0xC1, 0xF5, 0xFF }, // invalid UTF-8 bytes
            Encoding.ASCII.GetBytes("FFFF999999999999"), // huge malformed smart socket hex
            Encoding.ASCII.GetBytes("-001"), // invalid negative hex
            Encoding.ASCII.GetBytes("0000"), // zero length
            new byte[] { 0x1B, 0x5B }, // unterminated escape sequence
            new byte[] { 0x1B, 0x5B, 0x39, 0x39, 0x39, 0x7E }, // unknown escape sequence
            new byte[] { 0x08, 0x08, 0x08, 0x08 }, // backspaces on empty buffer
        };

        // Add 50 randomized fuzzy chunks
        var rng = new Random(1337);
        for (int i = 0; i < 50; i++)
        {
            byte[] buf = new byte[rng.Next(1, 512)];
            rng.NextBytes(buf);
            fuzzCases.Add(buf);
        }

        foreach (var fuzz in fuzzCases)
        {
            // None of these calls must throw an unhandled exception
            wireDecoder.DecodePackets(fuzz, out _);
            smartDecoder.Decode(fuzz, out _);
            detector.DetectCandidates(fuzz, SensorType.USB, TransportType.BULK, PacketDirection.HOST_TO_DEVICE);
            shellRecon.ProcessInputBytes(fuzz, out _, out _);
        }

        return true;
    }

    private static bool Test14_UsbLifecyclePower()
    {
        using var bus = new OmniTraceEventBus();
        var capturedCommands = new List<LogicalCommandEvent>();
        bus.OnLogicalCommand += cmd => capturedCommands.Add(cmd);

        // 1. Initial connection
        byte[] p1 = AdbWirePacket.BuildPacket(AdbWirePacket.A_OPEN, 1, 0, Encoding.UTF8.GetBytes("shell:echo CONNECT_1\0"));
        bus.ProcessSingleEvent(RawCaptureEvent.Create(1, SensorType.USB, TransportType.BULK, PacketDirection.HOST_TO_DEVICE, "LIFECYCLE_PHONE", "SESS_1", 0, "0x01", p1));

        // 2. Selective Suspend / Sleep simulation
        var key1 = new CaptureSessionKey("LIFECYCLE_PHONE", 0, "0x01", PacketDirection.HOST_TO_DEVICE, "SESS_1");
        bus.Reassembler.ResetSession(key1);

        // 3. Resume / Device Reset simulation
        byte[] p2 = AdbWirePacket.BuildPacket(AdbWirePacket.A_OPEN, 2, 0, Encoding.UTF8.GetBytes("shell:echo RESUME_2\0"));
        bus.ProcessSingleEvent(RawCaptureEvent.Create(2, SensorType.USB, TransportType.BULK, PacketDirection.HOST_TO_DEVICE, "LIFECYCLE_PHONE", "SESS_2", 0, "0x01", p2));

        var busMetrics = bus.GetMetrics();

        bool hasConn1 = capturedCommands.Any(c => c.Command.Contains("CONNECT_1"));
        bool hasResume2 = capturedCommands.Any(c => c.Command.Contains("RESUME_2"));
        return hasConn1 && hasResume2 && busMetrics.DroppedEvents == 0;
    }

    private static bool Test15_ServiceFailureAndFailOpen()
    {
        string pipeName = "PhoenixTestPipe_" + Guid.NewGuid().ToString("N");
        using var service = new PhoenixOmniTraceService(proxyPort: 5049, pipeName: pipeName);
        service.Start();
        Thread.Sleep(100);

        // Connect GUI IPC Client
        using var client = new OmniTraceIpcClient(pipeName);
        bool connected = client.Connect(2000);
        if (!connected) return false;

        bool pingOk = client.Ping();
        if (!pingOk) return false;

        // Simulate GUI crash / sudden disconnect
        client.Dispose();
        Thread.Sleep(50);

        // Verify capture continues uninterrupted (Fail-Open)
        byte[] pkt = AdbWirePacket.BuildPacket(AdbWirePacket.A_OPEN, 5, 0, Encoding.UTF8.GetBytes("shell:echo FAIL_OPEN_TEST\0"));
        service.EventBus.ProcessSingleEvent(RawCaptureEvent.Create(999, SensorType.USB, TransportType.BULK, PacketDirection.HOST_TO_DEVICE, "FAIL_OPEN_DEV", "SESS_FO", 0, "0x01", pkt));

        var metrics = service.EventBus.GetMetrics();
        bool captureContinued = metrics.RawEventsCaptured >= 1 && metrics.DecodedEvents >= 1;

        // Reconnect new GUI instance and verify query succeeds
        using var client2 = new OmniTraceIpcClient(pipeName);
        bool reconnected = client2.Connect(2000);
        if (!reconnected) return false;

        var queriedMetrics = client2.QueryMetrics();
        bool queriedOk = queriedMetrics != null && queriedMetrics.RawEventsCaptured >= 1;

        return captureContinued && queriedOk;
    }
}
