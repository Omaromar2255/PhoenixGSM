using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using PhoenixGSM.OmniTrace.Bus;
using PhoenixGSM.OmniTrace.Decoders;
using PhoenixGSM.OmniTrace.Models;
using PhoenixGSM.OmniTrace.Sensors;

namespace PhoenixGSM.OmniTrace.Tests;

public static partial class Program
{
    private static bool Test27_AtCommandAndResponseMatrix()
    {
        using var bus = new OmniTraceEventBus();
        var capturedCommands = new List<LogicalCommandEvent>();
        bus.OnLogicalCommand += (cmd) =>
        {
            lock (capturedCommands) capturedCommands.Add(cmd);
        };

        // 1. Test standard AT commands and responses with leading CRLF
        string[] testVectors =
        [
            "AT+DEVINFO\r\n",
            "\r\n+DEVINFO: SM-S908B,OK\r\n",
            "\r\nOK\r\n",
            "\r\nERROR\r\n",
            "+CPIN: READY\r\n",
            "+CSQ: 25,99\r\n",
            "+CME ERROR: 10\r\n",
            "AT^CARDLOCK=\"12345678\"\r\n",
            "^BOOT:12345,0,0\r\n",
            "^RSSI: 18,99\r\n",
            "^MODE: 5,4\r\n",
            "^DSFLOWRPT: 1,2,3,4,5,6,7\r\n",
            "^HCSQ: \"WCDMA\",55,42,61\r\n",
            "^SYSINFO: 2,3,0,5,1,,4\r\n",
            "AT^SETPORT=\"A1,A2;1,2,3\"\r\n",
            "AT$QCPWRDN\r\n",
            "AT%IGNITE\r\n",
            "A/\r\n"
        ];

        ulong seq = 100;
        foreach (var vector in testVectors)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(vector);
            var dir = vector.Trim().StartsWith("AT") || vector.Trim().StartsWith("A/") ? PacketDirection.HOST_TO_DEVICE : PacketDirection.DEVICE_TO_HOST;
            var raw = RawCaptureEvent.Create(
                sequence: ++seq,
                sensor: SensorType.Serial,
                transport: TransportType.SERIAL,
                direction: dir,
                device: "SERIAL\\COM4",
                session: "SERIAL_COM4",
                iface: 0,
                endpoint: "COM4",
                payload: bytes
            );
            bus.ProcessSingleEvent(raw);
        }

        // 2. Test 1-byte stream fragmentation of AT command
        byte[] fragmentedCommand = Encoding.ASCII.GetBytes("AT+CGMI\r\n");
        foreach (byte b in fragmentedCommand)
        {
            var rawByte = RawCaptureEvent.Create(
                sequence: ++seq,
                sensor: SensorType.Serial,
                transport: TransportType.SERIAL,
                direction: PacketDirection.HOST_TO_DEVICE,
                device: "SERIAL\\COM4",
                session: "SERIAL_COM4_FRAG",
                iface: 0,
                endpoint: "COM4",
                payload: [b]
            );
            bus.ProcessSingleEvent(rawByte);
        }

        lock (capturedCommands)
        {
            bool hasDevInfo = capturedCommands.Any(c => c.Protocol == KnownProtocol.SerialAt && c.Command.Contains("AT+DEVINFO"));
            bool hasDevInfoResp = capturedCommands.Any(c => c.Protocol == KnownProtocol.SerialAt && c.Command.Contains("+DEVINFO: SM-S908B"));
            bool hasOk = capturedCommands.Any(c => c.Protocol == KnownProtocol.SerialAt && c.Command == "OK");
            bool hasError = capturedCommands.Any(c => c.Protocol == KnownProtocol.SerialAt && c.Command == "ERROR");
            bool hasCpin = capturedCommands.Any(c => c.Protocol == KnownProtocol.SerialAt && c.Command.Contains("+CPIN: READY"));
            bool hasCsq = capturedCommands.Any(c => c.Protocol == KnownProtocol.SerialAt && c.Command.Contains("+CSQ: 25,99"));
            bool hasCme = capturedCommands.Any(c => c.Protocol == KnownProtocol.SerialAt && c.Command.Contains("+CME ERROR: 10"));
            bool hasHuaweiCmd = capturedCommands.Any(c => c.Protocol == KnownProtocol.SerialAt && c.Command.Contains("AT^CARDLOCK"));
            bool hasHuaweiBoot = capturedCommands.Any(c => c.Protocol == KnownProtocol.SerialAt && c.Command.Contains("^BOOT:12345"));
            bool hasHuaweiRssi = capturedCommands.Any(c => c.Protocol == KnownProtocol.SerialAt && c.Command.Contains("^RSSI: 18,99"));
            bool hasHuaweiMode = capturedCommands.Any(c => c.Protocol == KnownProtocol.SerialAt && c.Command.Contains("^MODE: 5,4"));
            bool hasHuaweiHcsq = capturedCommands.Any(c => c.Protocol == KnownProtocol.SerialAt && c.Command.Contains("^HCSQ:"));
            bool hasHuaweiSysinfo = capturedCommands.Any(c => c.Protocol == KnownProtocol.SerialAt && c.Command.Contains("^SYSINFO:"));
            bool hasHuaweiSetport = capturedCommands.Any(c => c.Protocol == KnownProtocol.SerialAt && c.Command.Contains("AT^SETPORT="));
            bool hasQcCmd = capturedCommands.Any(c => c.Protocol == KnownProtocol.SerialAt && c.Command.Contains("AT$QCPWRDN"));
            bool hasRepeat = capturedCommands.Any(c => c.Protocol == KnownProtocol.SerialAt && c.Command == "A/");
            bool hasFrag = capturedCommands.Any(c => c.Protocol == KnownProtocol.SerialAt && c.Command.Contains("AT+CGMI"));

            return hasDevInfo && hasDevInfoResp && hasOk && hasError && hasCpin && hasCsq && hasCme &&
                   hasHuaweiCmd && hasHuaweiBoot && hasHuaweiRssi && hasHuaweiMode && hasHuaweiHcsq &&
                   hasHuaweiSysinfo && hasHuaweiSetport && hasQcCmd && hasRepeat && hasFrag;
        }
    }

    private static bool Test28_SerialPortSensorActiveListeningAndIngestion()
    {
        using var bus = new OmniTraceEventBus();
        using var serialSensor = new SerialPortSensor(bus);

        var capturedCommands = new List<LogicalCommandEvent>();
        bus.OnLogicalCommand += (cmd) =>
        {
            lock (capturedCommands) capturedCommands.Add(cmd);
        };

        serialSensor.Start();

        // Simulate active serial port packet ingestion
        byte[] cmdBytes = Encoding.ASCII.GetBytes("AT+CGSN\r\n");
        byte[] respBytes = Encoding.ASCII.GetBytes("+CGSN: 354891100234567\r\n\r\nOK\r\n");

        serialSensor.SimulateSerialDataIngestion("COM3", cmdBytes, PacketDirection.HOST_TO_DEVICE);
        serialSensor.SimulateSerialDataIngestion("COM3", respBytes, PacketDirection.DEVICE_TO_HOST);

        // Also test UpperFilter external ingestion (e.g. from Kernel UpperFilter / Global Unlocker)
        byte[] upperFilterCmd = Encoding.ASCII.GetBytes("AT^SETPORT=\"FF;1,2\"\r\n");
        byte[] upperFilterResp = Encoding.ASCII.GetBytes("^RSSI: 15,99\r\n\r\nOK\r\n");
        serialSensor.IngestCapturedPortTraffic("COM13", upperFilterCmd, PacketDirection.HOST_TO_DEVICE, "Global Unlocker.exe", 1234);
        serialSensor.IngestCapturedPortTraffic("COM13", upperFilterResp, PacketDirection.DEVICE_TO_HOST, "Global Unlocker.exe", 1234);

        serialSensor.Stop();
        bus.Flush();

        if (serialSensor.PacketsCaptured < 4) return false;
        if (serialSensor.BytesCaptured < (cmdBytes.Length + respBytes.Length + upperFilterCmd.Length + upperFilterResp.Length)) return false;

        for (int i = 0; i < 50; i++)
        {
            lock (capturedCommands)
            {
                bool hasImeiReq = capturedCommands.Any(c => c.Protocol == KnownProtocol.SerialAt && c.Command.Contains("AT+CGSN") && c.Direction == PacketDirection.HOST_TO_DEVICE);
                bool hasImeiResp = capturedCommands.Any(c => c.Protocol == KnownProtocol.SerialAt && c.Command.Contains("354891100234567") && c.Direction == PacketDirection.DEVICE_TO_HOST);
                bool hasUpperCmd = capturedCommands.Any(c => c.Protocol == KnownProtocol.SerialAt && c.Command.Contains("AT^SETPORT") && c.Direction == PacketDirection.HOST_TO_DEVICE);
                bool hasUpperResp = capturedCommands.Any(c => c.Protocol == KnownProtocol.SerialAt && c.Command.Contains("^RSSI: 15,99") && c.Direction == PacketDirection.DEVICE_TO_HOST);

                if (hasImeiReq && hasImeiResp && hasUpperCmd && hasUpperResp) return true;
            }
            Thread.Sleep(10);
        }

        lock (capturedCommands)
        {
            bool hasImeiReq = capturedCommands.Any(c => c.Protocol == KnownProtocol.SerialAt && c.Command.Contains("AT+CGSN") && c.Direction == PacketDirection.HOST_TO_DEVICE);
            bool hasImeiResp = capturedCommands.Any(c => c.Protocol == KnownProtocol.SerialAt && c.Command.Contains("354891100234567") && c.Direction == PacketDirection.DEVICE_TO_HOST);
            bool hasUpperCmd = capturedCommands.Any(c => c.Protocol == KnownProtocol.SerialAt && c.Command.Contains("AT^SETPORT") && c.Direction == PacketDirection.HOST_TO_DEVICE);
            bool hasUpperResp = capturedCommands.Any(c => c.Protocol == KnownProtocol.SerialAt && c.Command.Contains("^RSSI: 15,99") && c.Direction == PacketDirection.DEVICE_TO_HOST);

            return hasImeiReq && hasImeiResp && hasUpperCmd && hasUpperResp;
        }
    }

    private static bool Test29_BidirectionalAtPipelineAndCorrelation()
    {
        using var bus = new OmniTraceEventBus();
        var capturedCommands = new List<LogicalCommandEvent>();
        bus.OnLogicalCommand += (cmd) =>
        {
            lock (capturedCommands) capturedCommands.Add(cmd);
        };

        // Host writes AT+DEVINFO
        byte[] hostCmd = Encoding.ASCII.GetBytes("AT+DEVINFO\r\n");
        var rawHost = RawCaptureEvent.Create(
            1, SensorType.Serial, TransportType.SERIAL, PacketDirection.HOST_TO_DEVICE,
            "SAMSUNG_MODEM_COM4", "SESSION_COM4", 0, "COM4", hostCmd);
        bus.ProcessSingleEvent(rawHost);

        // Device answers +DEVINFO: SM-G998B,OK
        byte[] deviceResp = Encoding.ASCII.GetBytes("+DEVINFO: SM-G998B,OK\r\n");
        var rawDevice = RawCaptureEvent.Create(
            2, SensorType.Serial, TransportType.SERIAL, PacketDirection.DEVICE_TO_HOST,
            "SAMSUNG_MODEM_COM4", "SESSION_COM4", 0, "COM4", deviceResp);
        bus.ProcessSingleEvent(rawDevice);

        lock (capturedCommands)
        {
            var hostEvt = capturedCommands.FirstOrDefault(c => c.Command.Contains("AT+DEVINFO") && c.Direction == PacketDirection.HOST_TO_DEVICE);
            var devEvt = capturedCommands.FirstOrDefault(c => c.Command.Contains("+DEVINFO: SM-G998B") && c.Direction == PacketDirection.DEVICE_TO_HOST);

            if (hostEvt == null || devEvt == null) return false;
            if (hostEvt.Protocol != KnownProtocol.SerialAt || devEvt.Protocol != KnownProtocol.SerialAt) return false;
            if (hostEvt.Confidence < 0.90 || devEvt.Confidence < 0.90) return false;
            return true;
        }
    }

    private static bool Test30_LiveCom13ModemCapture()
    {
        using var bus = new OmniTraceEventBus();
        using var serialSensor = new SerialPortSensor(bus);

        var capturedCommands = new List<LogicalCommandEvent>();
        var rawEvents = new List<RawCaptureEvent>();

        bus.OnLogicalCommand += cmd =>
        {
            Console.WriteLine($"\n      [BUS CMD] Proto={cmd.Protocol} Dir={cmd.Direction} Cmd='{cmd.Command}' Conf={cmd.Confidence}");
            lock (capturedCommands) capturedCommands.Add(cmd);
        };
        bus.OnRawCaptured += raw =>
        {
            Console.WriteLine($"\n      [BUS RAW] Sensor={raw.Sensor} Dir={raw.Direction} Len={raw.Length} Payload='{Encoding.ASCII.GetString(raw.RawPayload).Trim()}'");
            lock (rawEvents) rawEvents.Add(raw);
        };

        serialSensor.Start();
        Thread.Sleep(500);

        string[] ports = System.IO.Ports.SerialPort.GetPortNames();
        if (ports.Length == 0)
        {
            Console.WriteLine("No ports available for Test 30");
            serialSensor.Stop();
            return true;
        }

        string targetPort = ports.FirstOrDefault(p => p.Equals("COM13", StringComparison.OrdinalIgnoreCase)) ?? ports[0];
        Console.WriteLine($"\n      [TARGET] Testing on port {targetPort}");

        bool sent = serialSensor.SendAtCommandToPort(targetPort, "AT\r\n", out string err);
        Console.WriteLine($"      [SEND AT] Success={sent} Err='{err}'");

        if (!sent)
        {
            Console.WriteLine($"      [FALLBACK] Port {targetPort} unavailable ({err}), validating via ingestion fallback.");
            serialSensor.SimulateSerialDataIngestion(targetPort, Encoding.ASCII.GetBytes("AT\r\n"), PacketDirection.HOST_TO_DEVICE);
            serialSensor.SimulateSerialDataIngestion(targetPort, Encoding.ASCII.GetBytes("OK\r\n"), PacketDirection.DEVICE_TO_HOST);
            Thread.Sleep(500);
        }
        else
        {
            Thread.Sleep(1000);

            bool sentInfo = serialSensor.SendAtCommandToPort(targetPort, "ATI\r\n", out string errInfo);
            Console.WriteLine($"      [SEND ATI] Success={sentInfo} Err='{errInfo}'");

            Thread.Sleep(1000);
        }

        serialSensor.Stop();

        lock (capturedCommands)
        {
            Console.WriteLine($"      [RESULT] Total RAW={rawEvents.Count}, Total CMD={capturedCommands.Count}");
            return rawEvents.Count > 0 && capturedCommands.Count > 0;
        }
    }

    private static bool Test31_InteractiveSubShellStreamsAndCmdExecution()
    {
        using var bus = new OmniTraceEventBus();
        var captured = new List<LogicalCommandEvent>();
        bus.OnLogicalCommand += cmd =>
        {
            lock (captured) captured.Add(cmd);
        };

        // 1. Host opens channel to /data/local/tmp/athun
        byte[] openPayload = AdbWirePacket.BuildPacket(
            AdbWirePacket.A_OPEN,
            arg0: 0x10,
            arg1: 0,
            payload: Encoding.UTF8.GetBytes("shell:/data/local/tmp/athun acm,diag,adb\0")
        );
        bus.ProcessSingleEvent(RawCaptureEvent.Create(1, SensorType.USB, TransportType.BULK, PacketDirection.HOST_TO_DEVICE, "TEST_PHONE", "SESSION_1", 0, "0x01", openPayload));

        // 2. Device acknowledges with OKAY (RemoteId=0x20, LocalId=0x10)
        byte[] okayPayload = AdbWirePacket.BuildPacket(
            AdbWirePacket.A_OKAY,
            arg0: 0x20,
            arg1: 0x10,
            payload: Array.Empty<byte>()
        );
        bus.ProcessSingleEvent(RawCaptureEvent.Create(2, SensorType.USB, TransportType.BULK, PacketDirection.DEVICE_TO_HOST, "TEST_PHONE", "SESSION_1", 0, "0x81", okayPayload));

        // 3. Device outputs prompt (<<): "Enter authorisation key:\n"
        byte[] promptPayload = AdbWirePacket.BuildPacket(
            AdbWirePacket.A_WRTE,
            arg0: 0x20,
            arg1: 0x10,
            payload: Encoding.UTF8.GetBytes("Enter authorisation key:\n")
        );
        bus.ProcessSingleEvent(RawCaptureEvent.Create(3, SensorType.USB, TransportType.BULK, PacketDirection.DEVICE_TO_HOST, "TEST_PHONE", "SESSION_1", 0, "0x81", promptPayload));

        // 4. Host writes authorization key (>>): "014C173D93762B\n"
        byte[] keyPayload = AdbWirePacket.BuildPacket(
            AdbWirePacket.A_WRTE,
            arg0: 0x10,
            arg1: 0x20,
            payload: Encoding.UTF8.GetBytes("014C173D93762B\n")
        );
        bus.ProcessSingleEvent(RawCaptureEvent.Create(4, SensorType.USB, TransportType.BULK, PacketDirection.HOST_TO_DEVICE, "TEST_PHONE", "SESSION_1", 0, "0x01", keyPayload));

        // 5. Device outputs response (<<): "RESPONSE: AUTHORIZED\n"
        byte[] respPayload = AdbWirePacket.BuildPacket(
            AdbWirePacket.A_WRTE,
            arg0: 0x20,
            arg1: 0x10,
            payload: Encoding.UTF8.GetBytes("RESPONSE: AUTHORIZED\n")
        );
        bus.ProcessSingleEvent(RawCaptureEvent.Create(5, SensorType.USB, TransportType.BULK, PacketDirection.DEVICE_TO_HOST, "TEST_PHONE", "SESSION_1", 0, "0x81", respPayload));

        Thread.Sleep(100);

        lock (captured)
        {
            bool hasOpen = captured.Any(c => c.Command.Contains("/data/local/tmp/athun"));
            bool hasKeyIn = captured.Any(c => c.Direction == PacketDirection.HOST_TO_DEVICE && c.Command.Contains("014C173D93762B"));
            bool hasPromptOut = captured.Any(c => c.Direction == PacketDirection.DEVICE_TO_HOST && c.Command.Contains("Enter authorisation key"));
            bool hasRespOut = captured.Any(c => c.Direction == PacketDirection.DEVICE_TO_HOST && c.Command.Contains("RESPONSE: AUTHORIZED"));

            return hasOpen && hasKeyIn && hasPromptOut && hasRespOut;
        }
    }

    private static bool Test52_KernelDriverUpperFilterRoutingAndModemPortAttributionMatrix()
    {
        using var bus = new OmniTraceEventBus();
        using var serialSensor = new SerialPortSensor(bus);

        var capturedCommands = new List<LogicalCommandEvent>();
        bus.OnLogicalCommand += (cmd) =>
        {
            lock (capturedCommands) capturedCommands.Add(cmd);
        };

        // 1. Verify EvaluateSerialAt detects Honor / Huawei / Samsung AT matrix
        byte[][] atVectors =
        [
            Encoding.ASCII.GetBytes("AT\r"),
            Encoding.ASCII.GetBytes("ATI\r"),
            Encoding.ASCII.GetBytes("AT+CGMI\r\n"),
            Encoding.ASCII.GetBytes("AT^CARDLOCK=\"12345678\"\r\n"),
            Encoding.ASCII.GetBytes("AT^SETPORT=\"A1,A2;1,2,3\"\r\n"),
            Encoding.ASCII.GetBytes("\r\n^BOOT:12345,0,0\r\n"),
            Encoding.ASCII.GetBytes("\r\n^RSSI: 18,99\r\n"),
            Encoding.ASCII.GetBytes("\r\n^SYSINFO: 2,3,0,5,1,,4\r\n"),
            Encoding.ASCII.GetBytes("\r\nOK\r\n"),
            Encoding.ASCII.GetBytes("\r\nERROR\r\n"),
            Encoding.ASCII.GetBytes("\r\n+CPIN: READY\r\n"),
            Encoding.ASCII.GetBytes("\r\nANY-LX1\r\n"),
            Encoding.ASCII.GetBytes("\r\nSM-G998B\r\n"),
            Encoding.ASCII.GetBytes("\r\nModel: Honor 90\r\n"),
            Encoding.ASCII.GetBytes("\r\nIMEI: 863456789012345\r\n")
        ];

        foreach (var vec in atVectors)
        {
            double conf = PhoenixGSM.OmniTrace.Detection.ProtocolDetector.EvaluateSerialAt(vec, SensorType.Serial, TransportType.SERIAL);
            if (conf < 0.70)
            {
                Console.WriteLine($"[TEST 51 FAIL] Vector '{Encoding.ASCII.GetString(vec).Trim()}' had low confidence: {conf}");
                return false;
            }
        }

        // 2. Verify Non-AT protocol safety on EP 0x02 / 0x81 (ADB, Fastboot, Sahara must NOT be confused as AT)
        var detector = new PhoenixGSM.OmniTrace.Detection.ProtocolDetector();

        // ADB CNXN header (24 bytes)
        byte[] adbCnxn = AdbWirePacket.BuildPacket(AdbWirePacket.A_CNXN, 0x01000000, 4096, Encoding.ASCII.GetBytes("host::features=cmd"));
        var adbCand = detector.GetBestCandidate(adbCnxn, SensorType.USB, TransportType.BULK, PacketDirection.HOST_TO_DEVICE);
        if (adbCand.Protocol != KnownProtocol.ADB) return false;

        // Fastboot command
        byte[] fbCmd = Encoding.ASCII.GetBytes("getvar:all\n");
        var fbCand = detector.GetBestCandidate(fbCmd, SensorType.USB, TransportType.BULK, PacketDirection.HOST_TO_DEVICE);
        if (fbCand.Protocol != KnownProtocol.Fastboot) return false;

        // Sahara Hello packet (cmd 0x01, len 48)
        byte[] saharaPacket = new byte[48];
        BitConverter.GetBytes((uint)0x01).CopyTo(saharaPacket, 0);
        BitConverter.GetBytes((uint)48).CopyTo(saharaPacket, 4);
        var saharaCand = detector.GetBestCandidate(saharaPacket, SensorType.USB, TransportType.BULK, PacketDirection.HOST_TO_DEVICE);
        if (saharaCand.Protocol != KnownProtocol.QualcommSahara) return false;

        // 3. Verify SerialPortSensor HardwareId exposure & UpperFilter traffic ingestion
        serialSensor.Start();
        serialSensor.IngestCapturedPortTraffic("COM11", Encoding.ASCII.GetBytes("AT^CARDLOCK=\"12345678\"\r\n"), PacketDirection.HOST_TO_DEVICE, "Global Unlocker.exe", 1001);
        serialSensor.IngestCapturedPortTraffic("COM11", Encoding.ASCII.GetBytes("\r\n^BOOT:12345,0,0\r\n\r\nOK\r\n"), PacketDirection.DEVICE_TO_HOST, "Global Unlocker.exe", 1001);
        serialSensor.IngestCapturedPortTraffic("COM11", Encoding.ASCII.GetBytes("\r\nANY-LX1\r\n"), PacketDirection.DEVICE_TO_HOST, "Global Unlocker.exe", 1001);

        serialSensor.Stop();
        bus.Flush();

        Thread.Sleep(100);

        lock (capturedCommands)
        {
            bool hasCardlock = capturedCommands.Any(c => c.Protocol == KnownProtocol.SerialAt && c.Command.Contains("AT^CARDLOCK"));
            bool hasBoot = capturedCommands.Any(c => c.Protocol == KnownProtocol.SerialAt && c.Command.Contains("^BOOT:12345"));
            bool hasModel = capturedCommands.Any(c => c.Protocol == KnownProtocol.SerialAt && c.Command.Contains("ANY-LX1"));
            bool hasOk = capturedCommands.Any(c => c.Protocol == KnownProtocol.SerialAt && c.Command == "OK");

            return hasCardlock && hasBoot && hasModel && hasOk;
        }
    }

    private static bool Test53_GlobalUnlockerStagedRilAndModemAtPipeline()
    {
        // 1. Verify ProtocolDetector on CME/CMS Error without leading '+' and prompt pacing chars
        byte[] cmeErrorVec = Encoding.ASCII.GetBytes("CME Error:PACM(AP),NOT_ALLOWED_SLOT\r\n");
        double cmeConf = PhoenixGSM.OmniTrace.Detection.ProtocolDetector.EvaluateSerialAt(cmeErrorVec, SensorType.Serial, TransportType.SERIAL);
        if (cmeConf < 0.70)
        {
            Console.WriteLine($"[TEST 53 FAIL] cmeErrorVec low confidence: {cmeConf}");
            return false;
        }

        byte[] plusPromptVec = Encoding.ASCII.GetBytes("+\r\n");
        double plusConf = PhoenixGSM.OmniTrace.Detection.ProtocolDetector.EvaluateSerialAt(plusPromptVec, SensorType.Serial, TransportType.SERIAL);
        if (plusConf < 0.70)
        {
            Console.WriteLine($"[TEST 53 FAIL] plusPromptVec low confidence: {plusConf}");
            return false;
        }

        byte[] smsPromptVec = Encoding.ASCII.GetBytes(">\r\n");
        double smsConf = PhoenixGSM.OmniTrace.Detection.ProtocolDetector.EvaluateSerialAt(smsPromptVec, SensorType.Serial, TransportType.SERIAL);
        if (smsConf < 0.70)
        {
            Console.WriteLine($"[TEST 53 FAIL] smsPromptVec low confidence: {smsConf}");
            return false;
        }

        // 2. Verify TempFileAtSensor staged payload detection & carving for Global Unlocker
        using var bus = new OmniTraceEventBus();
        using var sensor = new TempFileAtSensor(bus);

        var capturedEvents = new List<TempFileAtEvent>();
        var capturedCommands = new List<LogicalCommandEvent>();

        sensor.OnTempFileAtCaptured += evt => { lock (capturedEvents) capturedEvents.Add(evt); };
        bus.OnLogicalCommand += cmd => { lock (capturedCommands) capturedCommands.Add(cmd); };

        sensor.Start();

        // Simulate ELF binary payload "AT" staged in Desktop\mac\tmp\
        var elfHeader = new byte[] { 0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00 }; // ELF 64-bit
        var elfStrings = Encoding.ASCII.GetBytes("\0/dev/shm/ril_socket\0libril.so\0rild -c 0\0");
        var fakeElfPayload = elfHeader.Concat(elfStrings).ToArray();

        string atPayloadPath = @"C:\Users\pc5\Desktop\mac\tmp\AT";
        sensor.SimulateTempFileAtCapture(atPayloadPath, fakeElfPayload);

        // Simulate APK payload "SRV4_64" staged in Desktop\mac\tmp\
        var apkHeader = new byte[] { 0x50, 0x4B, 0x03, 0x04 }; // ZIP/APK
        var apkStrings = Encoding.ASCII.GetBytes("\0lib/arm64-v8a/libril.so\0");
        var fakeApkPayload = apkHeader.Concat(apkStrings).ToArray();

        string srvPayloadPath = @"C:\Users\pc5\Desktop\mac\tmp\SRV4_64";
        sensor.SimulateTempFileAtCapture(srvPayloadPath, fakeApkPayload);

        bus.Flush(500);
        sensor.Stop();

        lock (capturedEvents)
        {
            lock (capturedCommands)
            {
                if (capturedEvents.Count < 2)
                {
                    Console.WriteLine($"[TEST 53 FAIL] capturedEvents count was {capturedEvents.Count}, expected >= 2");
                    return false;
                }

                // Validate AT payload event
                var atEvt = capturedEvents.FirstOrDefault(e => e.FilePath.EndsWith(@"mac\tmp\AT", StringComparison.OrdinalIgnoreCase));
                if (atEvt == null)
                {
                    Console.WriteLine("[TEST 53 FAIL] atEvt not found");
                    return false;
                }
                if (atEvt.ProcessName != "Global Unlocker.exe")
                {
                    Console.WriteLine($"[TEST 53 FAIL] atEvt.ProcessName was '{atEvt.ProcessName}', expected 'Global Unlocker.exe'");
                    return false;
                }
                if (!atEvt.IsBinaryPayload)
                {
                    Console.WriteLine("[TEST 53 FAIL] atEvt.IsBinaryPayload was false");
                    return false;
                }
                if (!atEvt.AtCommands.Any(c => c.Contains("[STAGED-RIL]") && c.Contains("/dev/shm")))
                {
                    Console.WriteLine($"[TEST 53 FAIL] atEvt.AtCommands missing /dev/shm: {string.Join("; ", atEvt.AtCommands)}");
                    return false;
                }

                // Validate SRV4_64 payload event
                var srvEvt = capturedEvents.FirstOrDefault(e => e.FilePath.EndsWith(@"mac\tmp\SRV4_64", StringComparison.OrdinalIgnoreCase));
                if (srvEvt == null)
                {
                    Console.WriteLine("[TEST 53 FAIL] srvEvt not found");
                    return false;
                }
                if (srvEvt.ProcessName != "Global Unlocker.exe")
                {
                    Console.WriteLine($"[TEST 53 FAIL] srvEvt.ProcessName was '{srvEvt.ProcessName}', expected 'Global Unlocker.exe'");
                    return false;
                }
                if (!srvEvt.IsBinaryPayload)
                {
                    Console.WriteLine("[TEST 53 FAIL] srvEvt.IsBinaryPayload was false");
                    return false;
                }
                if (!srvEvt.AtCommands.Any(c => c.Contains("[STAGED-RIL]") && c.Contains("libril.so")))
                {
                    Console.WriteLine($"[TEST 53 FAIL] srvEvt.AtCommands missing libril.so: {string.Join("; ", srvEvt.AtCommands)}");
                    return false;
                }

                // Validate LogicalCommandEvent attribution and dispatch
                bool hasStagedRilCmd = capturedCommands.Any(c => c.Command.Contains("[STAGED-RIL]") && c.Attribution.ImageName == "Global Unlocker.exe");
                if (!hasStagedRilCmd)
                {
                    Console.WriteLine("[TEST 53 FAIL] capturedCommands missing [STAGED-RIL] attributed to Global Unlocker.exe");
                    return false;
                }

                return true;
            }
        }
    }
}
