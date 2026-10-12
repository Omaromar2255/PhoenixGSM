using System;
using System.Text;
using System.Threading;
using PhoenixGSM.OmniTrace.Apple.Decoders;
using PhoenixGSM.OmniTrace.Apple.Models;
using PhoenixGSM.OmniTrace.Bus;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.Tests;

public static partial class Program
{
    public static bool Test42_AppleUsbmuxdAndLockdownNormalMode()
    {
        using var bus = new OmniTraceEventBus();
        LogicalCommandEvent? capturedCmd = null;
        using var countdown = new ManualResetEventSlim(false);

        bus.OnLogicalCommand += cmd =>
        {
            if (cmd.Protocol == KnownProtocol.AppleLockdown || cmd.Protocol == KnownProtocol.AppleUsbmuxd)
            {
                capturedCmd = cmd;
                countdown.Set();
            }
        };

        // 1. Simulate usbmuxd 16-byte header with XML Plist GetValue query
        string xmlPayload = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n" +
            "<plist version=\"1.0\"><dict>\n" +
            "<key>Request</key><string>GetValue</string>\n" +
            "<key>Key</key><string>UniqueDeviceID</string>\n" +
            "<key>UniqueDeviceID</key><string>00008030-001234567890ABCD</string>\n" +
            "<key>ProductType</key><string>iPhone12,1</string>\n" +
            "<key>SerialNumber</key><string>DNQX1234F182</string>\n" +
            "</dict></plist>";

        byte[] payloadBytes = Encoding.UTF8.GetBytes(xmlPayload);
        uint totalLen = (uint)(16 + payloadBytes.Length);
        byte[] packet = new byte[totalLen];

        BitConverter.GetBytes(totalLen).CopyTo(packet, 0);       // Length
        BitConverter.GetBytes((uint)1).CopyTo(packet, 4);        // Version
        BitConverter.GetBytes(AppleUsbmuxdDecoder.USBMUXD_MSG_PLIST).CopyTo(packet, 8); // Message
        BitConverter.GetBytes((uint)101).CopyTo(packet, 12);     // Tag
        payloadBytes.CopyTo(packet, 16);

        var raw = RawCaptureEvent.Create(
            sequence: 1,
            sensor: SensorType.VirtualProxy,
            transport: TransportType.TCP,
            direction: PacketDirection.HOST_TO_DEVICE,
            device: "APPLE_IPHONE_01",
            session: "MUX_SESS_01",
            iface: 0,
            endpoint: "TCP_27015",
            payload: packet
        );

        bus.Publish(raw);
        bool ok = countdown.Wait(3000);

        if (!ok || capturedCmd == null) return false;
        if (!capturedCmd.Details.TryGetValue("AppleMode", out var mode) || mode != "Normal") return false;
        if (!capturedCmd.Details.TryGetValue("ProductType", out var prod) || prod != "iPhone12,1") return false;
        if (!capturedCmd.Details.TryGetValue("SerialNumber", out var sn) || sn != "DNQX1234F182") return false;

        return true;
    }

    public static bool Test43_AppleRecoveryModeIbootCommands()
    {
        using var bus = new OmniTraceEventBus();
        LogicalCommandEvent? idCmd = null;
        LogicalCommandEvent? getenvCmd = null;
        int count = 0;
        using var countdown = new ManualResetEventSlim(false);

        bus.OnLogicalCommand += cmd =>
        {
            if (cmd.Protocol == KnownProtocol.AppleRecovery)
            {
                if (cmd.Command.Contains("Hardware ID")) idCmd = cmd;
                if (cmd.Command.Contains("getenv")) getenvCmd = cmd;
                if (Interlocked.Increment(ref count) >= 2) countdown.Set();
            }
        };

        // 1. Simulate iBoot USB Serial Number descriptor string
        string ibootDesc = "CPID:8015 CPRV:11 BDID:0A ECID:0000060D4B14B4A8 CPFM:03 SROT:01 SRTG:[iBoot-4075.40.16] MODE:Recovery";
        byte[] descBytes = Encoding.ASCII.GetBytes(ibootDesc);

        bus.Publish(RawCaptureEvent.Create(
            sequence: 2,
            sensor: SensorType.USB,
            transport: TransportType.BULK,
            direction: PacketDirection.DEVICE_TO_HOST,
            device: "USB\\VID_05AC&PID_1281\\0000060D4B14B4A8",
            session: "IBOOT_SESS_01",
            iface: 0,
            endpoint: "0x81",
            payload: descBytes
        ));

        // 2. Simulate irecovery command "getenv auto-boot"
        string getenvStr = "getenv auto-boot\r\n";
        byte[] getenvBytes = Encoding.ASCII.GetBytes(getenvStr);

        bus.Publish(RawCaptureEvent.Create(
            sequence: 3,
            sensor: SensorType.USB,
            transport: TransportType.BULK,
            direction: PacketDirection.HOST_TO_DEVICE,
            device: "USB\\VID_05AC&PID_1281\\0000060D4B14B4A8",
            session: "IBOOT_SESS_02",
            iface: 0,
            endpoint: "0x01",
            payload: getenvBytes
        ));

        bool ok = countdown.Wait(3000);
        if (!ok || idCmd == null || getenvCmd == null) return false;

        if (!idCmd.Details.TryGetValue("ECID", out var ecid) || ecid != "0000060D4B14B4A8") return false;
        if (!idCmd.Details.TryGetValue("CPID", out var cpid) || cpid != "8015") return false;
        if (!getenvCmd.Command.Contains("auto-boot")) return false;

        return true;
    }

    public static bool Test44_AppleDfuAndCheckm8Exploit()
    {
        using var bus = new OmniTraceEventBus();
        LogicalCommandEvent? pwnedCmd = null;
        using var countdown = new ManualResetEventSlim(false);

        bus.OnLogicalCommand += cmd =>
        {
            if (cmd.Protocol == KnownProtocol.AppleDfu)
            {
                pwnedCmd = cmd;
                countdown.Set();
            }
        };

        // Simulate checkm8 pwned DFU descriptor string
        string pwnedDesc = "CPID:8010 CPRV:11 BDID:00 ECID:000005296BE3C668 CPFM:03 SROT:01 PWND:[checkm8] MODE:DFU";
        byte[] pwnedBytes = Encoding.ASCII.GetBytes(pwnedDesc);

        bus.Publish(RawCaptureEvent.Create(
            sequence: 4,
            sensor: SensorType.USB,
            transport: TransportType.CONTROL,
            direction: PacketDirection.DEVICE_TO_HOST,
            device: "USB\\VID_05AC&PID_1227\\000005296BE3C668",
            session: "DFU_PWN_SESS_01",
            iface: 0,
            endpoint: "0x00",
            payload: pwnedBytes
        ));

        bool ok = countdown.Wait(3000);
        if (!ok || pwnedCmd == null) return false;

        if (!pwnedCmd.Details.TryGetValue("AppleMode", out var mode) || mode != "PwnedDfu") return false;
        if (!pwnedCmd.Details.TryGetValue("ECID", out var ecid) || ecid != "000005296BE3C668") return false;
        if (!pwnedCmd.Details.TryGetValue("ExploitToken", out var tok) || !tok.Contains("checkm8")) return false;

        return true;
    }

    public static bool Test45_AppleRamdiskSshAndActivationExtraction()
    {
        using var bus = new OmniTraceEventBus();
        LogicalCommandEvent? sshBannerCmd = null;
        LogicalCommandEvent? mountCmd = null;
        int count = 0;
        using var countdown = new ManualResetEventSlim(false);

        bus.OnLogicalCommand += cmd =>
        {
            if (cmd.Protocol == KnownProtocol.AppleRamdiskSsh)
            {
                if (cmd.Command.Contains("SSH-2.0")) sshBannerCmd = cmd;
                if (cmd.Command.Contains("mount_apfs")) mountCmd = cmd;
                if (Interlocked.Increment(ref count) >= 2) countdown.Set();
            }
        };

        // 1. Simulate SSH protocol handshake banner
        string banner = "SSH-2.0-OpenSSH_8.4\r\n";
        byte[] bannerBytes = Encoding.ASCII.GetBytes(banner);

        bus.Publish(RawCaptureEvent.Create(
            sequence: 5,
            sensor: SensorType.VirtualProxy,
            transport: TransportType.TCP,
            direction: PacketDirection.DEVICE_TO_HOST,
            device: "IPHONE_RAMDISK_SSH",
            session: "SSH_SESS_01",
            iface: 0,
            endpoint: "TCP_2222_IN",
            payload: bannerBytes
        ));

        // 2. Simulate Ramdisk mount command
        string mountStr = "mount_apfs /dev/disk0s1s1 /mnt1\n";
        byte[] mountBytes = Encoding.ASCII.GetBytes(mountStr);

        bus.Publish(RawCaptureEvent.Create(
            sequence: 6,
            sensor: SensorType.VirtualProxy,
            transport: TransportType.TCP,
            direction: PacketDirection.HOST_TO_DEVICE,
            device: "IPHONE_RAMDISK_SSH",
            session: "SSH_SESS_02",
            iface: 0,
            endpoint: "TCP_2222_OUT",
            payload: mountBytes
        ));

        bool ok = countdown.Wait(3000);
        if (!ok || sshBannerCmd == null || mountCmd == null) return false;

        if (!mountCmd.Details.TryGetValue("AppleMode", out var mode) || mode != "RamdiskSsh") return false;
        if (!mountCmd.Command.Contains("mount_apfs")) return false;

        return true;
    }

    public static bool Test46_ApplePurpleDiagSysCfgOverSerial()
    {
        using var bus = new OmniTraceEventBus();
        LogicalCommandEvent? syscfgCmd = null;
        using var countdown = new ManualResetEventSlim(false);

        bus.OnLogicalCommand += cmd =>
        {
            if (cmd.Protocol == KnownProtocol.ApplePurpleDiag)
            {
                syscfgCmd = cmd;
                countdown.Set();
            }
        };

        // Simulate SysCfg print command over CDC Serial
        string syscfgStr = "syscfg print SrNm\r\n";
        byte[] syscfgBytes = Encoding.ASCII.GetBytes(syscfgStr);

        bus.Publish(RawCaptureEvent.Create(
            sequence: 7,
            sensor: SensorType.Serial,
            transport: TransportType.SERIAL,
            direction: PacketDirection.HOST_TO_DEVICE,
            device: "COM15_APPLE_DIAG",
            session: "DIAG_SESS_01",
            iface: 0,
            endpoint: "COM15",
            payload: syscfgBytes
        ));

        bool ok = countdown.Wait(3000);
        if (!ok || syscfgCmd == null) return false;

        if (!syscfgCmd.Details.TryGetValue("AppleMode", out var mode) || mode != "PurpleDiag") return false;
        if (!syscfgCmd.Details.TryGetValue("Parameter", out var param) || param != "SerialNumber") return false;

        return true;
    }

    public static bool Test47_AppleUsbmuxdProxyAndMultiDeviceTransition()
    {
        using var bus = new OmniTraceEventBus();
        using var proxy = new PhoenixGSM.OmniTrace.Apple.Sensors.AppleUsbmuxdProxy(bus, listenPort: 27018, targetPort: 27015);

        proxy.Start();
        bool isRunningOrBound = proxy.IsRunning || proxy.IsPortBoundByAnotherProcess;
        proxy.Stop();

        return isRunningOrBound;
    }

    public static bool Test51_AppleRamdiskSessionWatcherWorkspaceTracking()
    {
        using var bus = new OmniTraceEventBus();
        using var watcher = new PhoenixGSM.OmniTrace.Apple.Sensors.AppleRamdiskSessionWatcher(bus);

        var eventsReceived = new List<LogicalCommandEvent>();
        bus.OnLogicalCommand += cmd =>
        {
            if (cmd.Protocol == KnownProtocol.AppleRamdiskSsh)
            {
                lock (eventsReceived) eventsReceived.Add(cmd);
            }
        };

        // Create temporary directory mimicking SK APPLE PRO workspace
        string tempDir = Path.Combine(Path.GetTempPath(), "PhoenixTest_Ramdisk_" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(tempDir);
        string x64Dir = Path.Combine(tempDir, "x64");
        Directory.CreateDirectory(x64Dir);
        string utilsDir = Path.Combine(x64Dir, "utils");
        Directory.CreateDirectory(utilsDir);
        string resultDir = Path.Combine(x64Dir, "hello_work", "result");
        Directory.CreateDirectory(resultDir);

        try
        {
            // Stage a mount script
            string scriptPath = Path.Combine(x64Dir, "remote_mount_dynamic.sh");
            File.WriteAllText(scriptPath, "#!/bin/sh\nmount_apfs /dev/disk0s1s1 /mnt1\n/usr/sbin/nvram -d oblit-inprogress\n");

            // Stage a summary.txt file
            string summaryPath = Path.Combine(resultDir, "summary.txt");
            File.WriteAllText(summaryPath, "iEZPro Summary\nOK:\n  + stage upload complete\n  + restore activation_record verified\n  + comm center Activated ticket applied\n");

            // Mock iproxy executable path
            string fakeIproxyExe = Path.Combine(utilsDir, "iproxy.exe");
            File.WriteAllText(fakeIproxyExe, "MZ");

            // Trigger OnIproxyLaunched
            watcher.OnIproxyLaunched(8716, 6040, "2222:22", Path.Combine(tempDir, "SK APPLE PRO.exe"), fakeIproxyExe);

            // Give async tasks a brief moment
            Thread.Sleep(500);

            lock (eventsReceived)
            {
                bool hasTunnel = eventsReceived.Any(e => e.Details.TryGetValue("AppleOperation", out var op) && op == "Ramdisk:TunnelStarted");
                bool hasScript = eventsReceived.Any(e => e.Details.TryGetValue("AppleOperation", out var op) && op.Contains("remote_mount_dynamic.sh"));
                bool hasStep = eventsReceived.Any(e => e.Details.TryGetValue("AppleOperation", out var op) && op == "Ramdisk:StepCompleted");

                return hasTunnel && hasScript && hasStep;
            }
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }
}
