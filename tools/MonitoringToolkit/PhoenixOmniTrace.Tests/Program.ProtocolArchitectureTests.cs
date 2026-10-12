using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using PhoenixGSM.OmniTrace.Bus;
using PhoenixGSM.OmniTrace.Decoders;
using PhoenixGSM.OmniTrace.Models;
using PhoenixGSM.OmniTrace.Reassembly;

namespace PhoenixGSM.OmniTrace.Tests;

public static partial class Program
{
    private static bool Test1_NoAdbExe()
    {
        using var bus = new OmniTraceEventBus();
        var capturedCommands = new List<LogicalCommandEvent>();
        bus.OnLogicalCommand += cmd => capturedCommands.Add(cmd);

        // Send Smart Socket request: "0012host:track-devices"
        string smartCmd = "0012host:track-devices";
        byte[] payload = Encoding.ASCII.GetBytes(smartCmd);

        var rawEvt = RawCaptureEvent.Create(
            sequence: 1,
            sensor: SensorType.VirtualProxy,
            transport: TransportType.TCP,
            direction: PacketDirection.HOST_TO_DEVICE,
            device: "127.0.0.1:5037",
            session: "TEST_SESSION_1",
            iface: 0,
            endpoint: "5037",
            payload: payload
        );

        bus.ProcessSingleEvent(rawEvt);

        bool hasCommand = capturedCommands.Any(c => c.Protocol == KnownProtocol.ADB && c.Service == "host" && c.Command.Contains("track-devices"));
        bool hasRawHash = !string.IsNullOrEmpty(rawEvt.PayloadHash);

        return hasCommand && hasRawHash;
    }

    private static bool Test2_InteractiveShellReconstruction()
    {
        var reconstructor = new ShellStreamReconstructor();

        // 1. Mandatory p.md test sequence (lines 1290-1297):
        // echo PHOENIX_001, id, getprop, ls, pwd, uname -a
        reconstructor.ProcessInputBytes(Encoding.UTF8.GetBytes("echo PHOENIX_001\r\n"), out string? cmd1, out _);
        if (cmd1 != "echo PHOENIX_001") return false;

        reconstructor.ProcessInputBytes(Encoding.UTF8.GetBytes("id\r\n"), out string? cmd2, out _);
        if (cmd2 != "id") return false;

        // 2. Exact example from p.md line 984:
        // RAW: \x1b[D\x7fgetpro\x1b[Cp\r -> RECONSTRUCTED: getprop
        byte[] pmdExample = Encoding.UTF8.GetBytes("\x1b[D\x7fgetpro\x1b[Cp\r\n");
        reconstructor.ProcessInputBytes(pmdExample, out string? cmd3, out _);
        if (cmd3 != "getprop") return false;

        reconstructor.ProcessInputBytes(Encoding.UTF8.GetBytes("ls\r\n"), out string? cmd4, out _);
        if (cmd4 != "ls") return false;

        reconstructor.ProcessInputBytes(Encoding.UTF8.GetBytes("pwd\r\n"), out string? cmd5, out _);
        if (cmd5 != "pwd") return false;

        // 3. Realistic cursor editing with left arrow, delete key \x1b[3~, and right arrow:
        // Type "unamxx" -> Left Arrow \x1b[D -> Left Arrow \x1b[D -> Delete \x1b[3~ -> Delete \x1b[3~ -> "e -a\r\n"
        // Should reconstruct to "uname -a"
        byte[] cursorEdit = Encoding.UTF8.GetBytes("unamxx\x1b[D\x1b[D\x1b[3~\x1b[3~e -a\r\n");
        reconstructor.ProcessInputBytes(cursorEdit, out string? cmd6, out _);
        if (cmd6 != "uname -a") return false;

        // 4. Multi-byte UTF-8 test (Arabic Unicode code points)
        reconstructor.ProcessInputBytes(Encoding.UTF8.GetBytes("echo مرحباً_فينيكس\r\n"), out string? cmdUtf8, out _);
        if (cmdUtf8 != "echo مرحباً_فينيكس") return false;

        // 5. Chunk-fragmented escape sequence across packet boundaries:
        // "\x1b[" in chunk 1, "D" in chunk 2
        reconstructor.ProcessInputBytes(Encoding.UTF8.GetBytes("ls"), out _, out _);
        reconstructor.ProcessInputBytes(new byte[] { 0x1B, (byte)'[' }, out _, out _);
        reconstructor.ProcessInputBytes(new byte[] { (byte)'D' }, out _, out _); // cursor moved between 'l' and 's'
        reconstructor.ProcessInputBytes(Encoding.UTF8.GetBytes(" -la\r\n"), out string? cmdFrag, out _);
        if (cmdFrag != "l -las") return false;

        // 6. Verify complete raw transcript contains original raw fragments
        string transcript = reconstructor.GetFullRawTranscript();
        bool hasTokens = transcript.Contains("PHOENIX_001") && transcript.Contains("unamxx") && transcript.Contains("مرحباً_فينيكس");

        return hasTokens && reconstructor.ReconstructedCommands.Count >= 7;
    }

    private static bool Test3_Fragmentation()
    {
        using var bus = new OmniTraceEventBus();
        var capturedCommands = new List<LogicalCommandEvent>();
        bus.OnLogicalCommand += cmd => capturedCommands.Add(cmd);

        // Build full ADB OPEN packet: OPEN shell:pm list packages\0
        byte[] serviceBytes = Encoding.UTF8.GetBytes("shell:pm list packages\0");
        byte[] fullPacket = AdbWirePacket.BuildPacket(AdbWirePacket.A_OPEN, 101, 0, serviceBytes);

        // Fragment into 1-byte, 2-byte, 3-byte chunks
        int offset = 0;
        int[] chunkSizes = [1, 1, 2, 3, 1, 4, 2, 5, 1, fullPacket.Length - 20];
        ulong seq = 1;

        foreach (int size in chunkSizes)
        {
            if (offset >= fullPacket.Length) break;
            int actual = Math.Min(size, fullPacket.Length - offset);
            byte[] chunk = new byte[actual];
            Array.Copy(fullPacket, offset, chunk, 0, actual);
            offset += actual;

            var rawEvt = RawCaptureEvent.Create(
                sequence: seq++,
                sensor: SensorType.USB,
                transport: TransportType.BULK,
                direction: PacketDirection.HOST_TO_DEVICE,
                device: "MOTO_XT1650",
                session: "SESSION_FRAG_1",
                iface: 0,
                endpoint: "0x01",
                payload: chunk
            );

            bus.ProcessSingleEvent(rawEvt);
        }

        return capturedCommands.Any(c => c.Command.Contains("shell:pm list packages") && c.Protocol == KnownProtocol.ADB);
    }

    private static bool Test4_Coalescing()
    {
        using var bus = new OmniTraceEventBus();
        var capturedCommands = new List<LogicalCommandEvent>();
        bus.OnLogicalCommand += cmd => capturedCommands.Add(cmd);

        // Build 2 distinct ADB packets:
        // Packet 1: OPEN shell:id\0
        byte[] pkt1 = AdbWirePacket.BuildPacket(AdbWirePacket.A_OPEN, 1, 0, Encoding.UTF8.GetBytes("shell:id\0"));
        // Packet 2: OPEN shell:getprop\0
        byte[] pkt2 = AdbWirePacket.BuildPacket(AdbWirePacket.A_OPEN, 2, 0, Encoding.UTF8.GetBytes("shell:getprop\0"));

        // Coalesce into one single transfer
        byte[] coalesced = new byte[pkt1.Length + pkt2.Length];
        Array.Copy(pkt1, 0, coalesced, 0, pkt1.Length);
        Array.Copy(pkt2, 0, coalesced, pkt1.Length, pkt2.Length);

        var rawEvt = RawCaptureEvent.Create(
            sequence: 99,
            sensor: SensorType.USB,
            transport: TransportType.BULK,
            direction: PacketDirection.HOST_TO_DEVICE,
            device: "MOTO_XT1650",
            session: "SESSION_COALESCE_1",
            iface: 0,
            endpoint: "0x01",
            payload: coalesced
        );

        bus.ProcessSingleEvent(rawEvt);

        bool hasId = capturedCommands.Any(c => c.Command.Contains("shell:id"));
        bool hasGetprop = capturedCommands.Any(c => c.Command.Contains("shell:getprop"));

        return hasId && hasGetprop;
    }

    private static bool Test5_MultipleDevicesIsolation()
    {
        using var bus = new OmniTraceEventBus();
        var commandsDevA = new List<LogicalCommandEvent>();
        var commandsDevB = new List<LogicalCommandEvent>();

        bus.OnLogicalCommand += cmd =>
        {
            if (cmd.DeviceIdentity == "DEVICE_A_MOTOROLA") commandsDevA.Add(cmd);
            if (cmd.DeviceIdentity == "DEVICE_B_SAMSUNG") commandsDevB.Add(cmd);
        };

        byte[] pktA = AdbWirePacket.BuildPacket(AdbWirePacket.A_OPEN, 1, 0, Encoding.UTF8.GetBytes("shell:getprop ro.product.model\0"));
        byte[] pktB = AdbWirePacket.BuildPacket(AdbWirePacket.A_OPEN, 2, 0, Encoding.UTF8.GetBytes("shell:uname -a\0"));

        // Send half of DevA packet, half of DevB packet (interleaved)
        var rawA1 = RawCaptureEvent.Create(1, SensorType.USB, TransportType.BULK, PacketDirection.HOST_TO_DEVICE, "DEVICE_A_MOTOROLA", "SESS_A", 0, "0x01", pktA[..15]);
        var rawB1 = RawCaptureEvent.Create(2, SensorType.USB, TransportType.BULK, PacketDirection.HOST_TO_DEVICE, "DEVICE_B_SAMSUNG", "SESS_B", 0, "0x01", pktB[..10]);
        var rawA2 = RawCaptureEvent.Create(3, SensorType.USB, TransportType.BULK, PacketDirection.HOST_TO_DEVICE, "DEVICE_A_MOTOROLA", "SESS_A", 0, "0x01", pktA[15..]);
        var rawB2 = RawCaptureEvent.Create(4, SensorType.USB, TransportType.BULK, PacketDirection.HOST_TO_DEVICE, "DEVICE_B_SAMSUNG", "SESS_B", 0, "0x01", pktB[10..]);

        bus.ProcessSingleEvent(rawA1);
        bus.ProcessSingleEvent(rawB1);
        bus.ProcessSingleEvent(rawA2);
        bus.ProcessSingleEvent(rawB2);

        bool aOk = commandsDevA.Count == 1 && commandsDevA[0].Command.Contains("ro.product.model");
        bool bOk = commandsDevB.Count == 1 && commandsDevB[0].Command.Contains("uname -a");

        return aOk && bOk;
    }

    private static bool Test6_DisconnectReconnectLifecycle()
    {
        using var bus = new OmniTraceEventBus();
        var commands = new List<LogicalCommandEvent>();
        bus.OnLogicalCommand += cmd => commands.Add(cmd);

        // Session 1: Before disconnect
        byte[] pkt1 = AdbWirePacket.BuildPacket(AdbWirePacket.A_OPEN, 1, 0, Encoding.UTF8.GetBytes("shell:id\0"));
        var raw1 = RawCaptureEvent.Create(1, SensorType.USB, TransportType.BULK, PacketDirection.HOST_TO_DEVICE, "MOTO_XT1650", "SESSION_OLD", 0, "0x01", pkt1);
        bus.ProcessSingleEvent(raw1);

        // Disconnect: Session cleared
        var oldKey = new CaptureSessionKey("MOTO_XT1650", 0, "0x01", PacketDirection.HOST_TO_DEVICE, "SESSION_OLD");
        bus.Reassembler.ResetSession(oldKey);

        // Session 2: After reconnect
        byte[] pkt2 = AdbWirePacket.BuildPacket(AdbWirePacket.A_OPEN, 2, 0, Encoding.UTF8.GetBytes("shell:pwd\0"));
        var raw2 = RawCaptureEvent.Create(2, SensorType.USB, TransportType.BULK, PacketDirection.HOST_TO_DEVICE, "MOTO_XT1650", "SESSION_NEW", 0, "0x01", pkt2);
        bus.ProcessSingleEvent(raw2);

        // Both commands should be recorded across the disconnect/reconnect boundary
        bool hasOld = commands.Any(c => c.SessionIdentity == "SESSION_OLD" && c.Command.Contains("id"));
        bool hasNew = commands.Any(c => c.SessionIdentity == "SESSION_NEW" && c.Command.Contains("pwd"));

        return hasOld && hasNew;
    }

    private static bool Test7_DifferentUsbInterfaces()
    {
        using var bus = new OmniTraceEventBus();
        var capturedCommands = new List<LogicalCommandEvent>();
        bus.OnLogicalCommand += cmd => capturedCommands.Add(cmd);

        // Interface 0: ADB Bulk
        byte[] adbPkt = AdbWirePacket.BuildPacket(AdbWirePacket.A_OPEN, 1, 0, Encoding.UTF8.GetBytes("shell:id\0"));
        var rawAdb = RawCaptureEvent.Create(1, SensorType.USB, TransportType.BULK, PacketDirection.HOST_TO_DEVICE, "COMPOSITE_DEV", "SESS_IF0", iface: 0, endpoint: "0x01", payload: adbPkt);

        // Interface 1: MTP Bulk
        byte[] mtpData = [0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        var rawMtp = RawCaptureEvent.Create(2, SensorType.USB, TransportType.BULK, PacketDirection.HOST_TO_DEVICE, "COMPOSITE_DEV", "SESS_IF1", iface: 1, endpoint: "0x02", payload: mtpData);

        // Interface 2: Modem / AT Serial
        byte[] atData = Encoding.ASCII.GetBytes("AT+GMM\r\n");
        var rawModem = RawCaptureEvent.Create(3, SensorType.USB, TransportType.SERIAL, PacketDirection.HOST_TO_DEVICE, "COMPOSITE_DEV", "SESS_IF2", iface: 2, endpoint: "0x03", payload: atData);

        // Interface 3: Vendor diagnostic
        byte[] diagData = [0x7E, 0x0C, 0x14, 0x3A, 0x7E];
        var rawDiag = RawCaptureEvent.Create(4, SensorType.USB, TransportType.BULK, PacketDirection.HOST_TO_DEVICE, "COMPOSITE_DEV", "SESS_IF3", iface: 3, endpoint: "0x04", payload: diagData);

        bus.ProcessSingleEvent(rawAdb);
        bus.ProcessSingleEvent(rawMtp);
        bus.ProcessSingleEvent(rawModem);
        bus.ProcessSingleEvent(rawDiag);

        bool ifaceCountOk = bus.Reassembler.GetActiveSessionCount() == 4;
        bool hasAdb = capturedCommands.Any(c => c.Protocol == KnownProtocol.ADB && c.Service.Contains("id"));
        bool hasAt = capturedCommands.Any(c => c.Protocol == KnownProtocol.SerialAt && c.Command.Contains("AT+GMM"));

        return ifaceCountOk && hasAdb && hasAt;
    }

    private static bool Test8_DirectUsbPreservation()
    {
        using var bus = new OmniTraceEventBus();
        byte[] vendorBinaryData = [0x55, 0xAA, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];

        var rawEvt = RawCaptureEvent.Create(
            sequence: 50,
            sensor: SensorType.USB,
            transport: TransportType.BULK,
            direction: PacketDirection.DEVICE_TO_HOST,
            device: "USB\\VID_9999&PID_8888",
            session: "DIRECT_USB_SESS",
            iface: 1,
            endpoint: "0x82",
            payload: vendorBinaryData
        );

        bus.ProcessSingleEvent(rawEvt);
        var metrics = bus.GetMetrics();

        // Must capture event and mark unknown without throwing or dropping
        return metrics.RawEventsCaptured == 1 && metrics.UnknownEvents >= 1 && metrics.DroppedEvents == 0;
    }
}
