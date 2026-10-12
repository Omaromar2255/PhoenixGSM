using System;
using System.IO;
using System.Text;
using System.Threading;
using PhoenixGSM.OmniTrace.Bus;
using PhoenixGSM.OmniTrace.Models;
using PhoenixGSM.OmniTrace.TechnicianAudit;

namespace PhoenixGSM.OmniTrace.Tests;

public static partial class Program
{
    public static bool Test61_TechnicianAuditAdbShellInterception()
    {
        using var layer = new TechnicianPhoneCommandAuditLayer();
        TechnicianAuditRecord? capturedRecord = null;
        layer.OnCommandAudited += rec => capturedRecord = rec;

        // Simulate ADB shell command sent from UnlockTool.exe to client phone
        var record = layer.AuditOutboundCommand(
            rawCommand: "OPEN -> shell:pm uninstall -k --user 0 com.samsung.klmsagent",
            protocol: "ADB",
            mode: "Normal",
            targetDevice: "ADB:R58M123456",
            technicianTool: "UnlockTool.exe",
            processId: 5412);

        if (record == null) return false;
        if (record.PureCommand != "pm uninstall -k --user 0 com.samsung.klmsagent") return false;
        if (record.Protocol != "ADB") return false;
        if (record.Mode != "Normal / ADB") return false;
        if (record.TechnicianTool != "UnlockTool.exe") return false;
        if (string.IsNullOrEmpty(record.Sha256Hash)) return false;
        if (capturedRecord == null || capturedRecord.Id != record.Id) return false;
        if (layer.AdbCount != 1) return false;

        return true;
    }

    public static bool Test62_TechnicianAuditAtModemInterception()
    {
        using var layer = new TechnicianPhoneCommandAuditLayer();

        var record = layer.AuditOutboundCommand(
            rawCommand: "[MODEM-USB] OUT: AT+KICOMP=1,0\r\n",
            protocol: "AT-MODEM",
            mode: "Modem / Diag",
            targetDevice: "COM15",
            technicianTool: "Chimera.exe",
            processId: 8120);

        if (record == null) return false;
        if (record.PureCommand != "AT+KICOMP=1,0") return false;
        if (record.TargetDeviceOrPort != "COM15") return false;
        if (record.Mode != "Modem / Diag") return false;
        if (layer.AtCount != 1) return false;

        return true;
    }

    public static bool Test63_TechnicianAuditMtkBromAndPreloader()
    {
        using var layer = new TechnicianPhoneCommandAuditLayer();
        byte[] bromHandshake = [0xA0, 0x0A, 0x50, 0x05];

        var record = layer.AuditOutboundCommand(
            rawCommand: "BROM_HANDSHAKE_START",
            protocol: "MTK-BROM",
            mode: "MTK BROM",
            targetDevice: "USB\\VID_0E8D&PID_0003",
            technicianTool: "TFTUnlock.exe",
            processId: 9024,
            payloadBytes: bromHandshake);

        if (record == null) return false;
        if (!record.HexPayload.Contains("A0 0A 50 05")) return false;
        if (record.Mode != "MTK BROM") return false;
        if (layer.MtkCount != 1) return false;

        return true;
    }

    public static bool Test64_TechnicianAuditQualcommEdlFirehose()
    {
        using var layer = new TechnicianPhoneCommandAuditLayer();
        string firehoseXml = "<?xml version=\"1.0\" ?><data><program SECTOR_SIZE_IN_BYTES=\"512\" num_partition_sectors=\"2048\" physical_partition_number=\"0\" start_sector=\"0\" filename=\"boot.img\"/></data>";

        var record = layer.AuditOutboundCommand(
            rawCommand: firehoseXml,
            protocol: "QCOM-FIREHOSE",
            mode: "Qualcomm EDL 9008",
            targetDevice: "COM21",
            technicianTool: "QFIL.exe",
            processId: 4420);

        if (record == null) return false;
        if (!record.PureCommand.Contains("<program")) return false;
        if (record.Mode != "Qualcomm EDL 9008") return false;
        if (record.RiskLevel != "PARTITION WRITE") return false;
        if (layer.EdlCount != 1) return false;

        return true;
    }

    public static bool Test65_TechnicianAuditAppleDfuAndRecovery()
    {
        using var layer = new TechnicianPhoneCommandAuditLayer();

        var record = layer.AuditOutboundCommand(
            rawCommand: "irecovery -c setenv boot-args \"-v serial=3\"",
            protocol: "APPLE-RECOVERY",
            mode: "Apple Recovery",
            targetDevice: "AppleMobileDevice (DFU)",
            technicianTool: "3uTools.exe",
            processId: 6712);

        if (record == null) return false;
        if (!record.PureCommand.Contains("setenv boot-args")) return false;
        if (record.Mode != "Apple Recovery") return false;
        if (layer.AppleCount != 1) return false;

        return true;
    }

    public static bool Test66_TechnicianAuditDiskStorePersistence()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "TechAuditTest_" + Guid.NewGuid().ToString("N"));
        try
        {
            using (var layer = new TechnicianPhoneCommandAuditLayer(bus: null, customLogDirectory: tempDir))
            {
                layer.AuditOutboundCommand(
                    rawCommand: "reboot bootloader",
                    protocol: "FASTBOOT",
                    mode: "Fastboot",
                    targetDevice: "fastboot:982312",
                    technicianTool: "UnlockTool.exe",
                    processId: 3311);

                layer.AuditOutboundCommand(
                    rawCommand: "OPEN -> shell:getprop ro.build.version.release",
                    protocol: "ADB",
                    mode: "Normal",
                    targetDevice: "ADB:R58M123",
                    technicianTool: "sk_unlock.exe",
                    processId: 4422);

                layer.Flush();
            }

            // Verify files exist on disk
            string jsonlFile = Path.Combine(tempDir, $"TechnicianAudit_{DateTime.UtcNow:yyyyMMdd}.jsonl");
            string logFile = Path.Combine(tempDir, $"TechnicianAudit_{DateTime.UtcNow:yyyyMMdd}.log");

            if (!File.Exists(jsonlFile)) return false;
            if (!File.Exists(logFile)) return false;

            string jsonlContent = File.ReadAllText(jsonlFile);
            string logContent = File.ReadAllText(logFile);

            if (!jsonlContent.Contains("reboot bootloader")) return false;
            if (!jsonlContent.Contains("getprop ro.build.version.release")) return false;
            if (!logContent.Contains("FASTBOOT")) return false;
            if (!logContent.Contains("sk_unlock.exe:4422")) return false;

            return true;
        }
        finally
        {
            try { if (Directory.Exists(tempDir)) Directory.Delete(tempDir, true); } catch { }
        }
    }

    public static bool Test67_TechnicianAuditResponseToggleDisabledVsEnabled()
    {
        var bus = new OmniTraceEventBus();
        using var layer = new TechnicianPhoneCommandAuditLayer(bus);

        // 1. When toggle is FALSE (default)
        if (layer.CaptureDeviceResponses != false) return false;

        bus.ReportLogicalCommand(new LogicalCommandEvent
        {
            Command = "<< OK",
            Direction = PacketDirection.DEVICE_TO_HOST,
            Protocol = KnownProtocol.SerialAt,
            DeviceIdentity = "COM15",
            Attribution = new ProcessAttributionMetadata { ImageName = "UnlockTool.exe", ProcessId = 5412 }
        });

        if (layer.InboundResponsesCount != 0) return false;
        if (layer.TotalAuditedCount != 0) return false;

        // 2. When toggle is TRUE (enabled)
        layer.CaptureDeviceResponses = true;

        bus.ReportLogicalCommand(new LogicalCommandEvent
        {
            Command = "<< OK",
            Direction = PacketDirection.DEVICE_TO_HOST,
            Protocol = KnownProtocol.SerialAt,
            DeviceIdentity = "COM15",
            Attribution = new ProcessAttributionMetadata { ImageName = "UnlockTool.exe", ProcessId = 5412 }
        });

        if (layer.InboundResponsesCount != 1) return false;
        if (layer.TotalAuditedCount != 1) return false;

        return true;
    }

    public static bool Test68_TechnicianAuditAtModemResponseInterceptionAndPairing()
    {
        using var layer = new TechnicianPhoneCommandAuditLayer();
        layer.CaptureDeviceResponses = true;

        // 1. Outbound AT Command
        var cmd = layer.AuditOutboundCommand(
            rawCommand: "AT+CGMM\r\n",
            protocol: "AT-MODEM",
            mode: "Modem / Diag",
            targetDevice: "COM15",
            technicianTool: "UnlockTool.exe",
            processId: 5412);

        if (cmd == null) return false;
        if (cmd.PureCommand != "AT+CGMM") return false;
        if (cmd.IsResponse != false) return false;
        if (cmd.DirectionSymbol != ">>") return false;

        // 2. Inbound Phone Response
        var resp = layer.AuditInboundResponse(
            rawResponse: "Samsung SM-G998B\r\nOK",
            protocol: "AT-MODEM",
            targetDevice: "COM15");

        if (resp == null) return false;
        if (resp.IsResponse != true) return false;
        if (resp.DirectionSymbol != "<<") return false;
        if (resp.PureCommand != "Samsung SM-G998B\r\nOK") return false;
        if (resp.RelatedCommandId != cmd.Id) return false;
        if (resp.RelatedCommandText != "AT+CGMM") return false;
        if (resp.TechnicianTool != "UnlockTool.exe") return false; // Inherited from paired command
        if (resp.TechnicianProcessId != 5412) return false;
        if (resp.RiskLevel != "SUCCESS / OK") return false;

        // Verify command record updated with device reply
        if (cmd.DeviceResponse != "Samsung SM-G998B\r\nOK") return false;
        if (cmd.ResponseTimestamp == null) return false;

        // Verify counters
        if (layer.OutboundCommandsCount != 1) return false;
        if (layer.InboundResponsesCount != 1) return false;
        if (layer.AtCount != 2) return false;

        return true;
    }

    public static bool Test69_TechnicianAuditAdbShellResponseInterception()
    {
        using var layer = new TechnicianPhoneCommandAuditLayer();
        layer.CaptureDeviceResponses = true;

        // 1. Outbound ADB Command
        var cmd = layer.AuditOutboundCommand(
            rawCommand: "OPEN -> shell:id",
            protocol: "ADB",
            mode: "Normal",
            targetDevice: "ADB:R58M123",
            technicianTool: "Chimera.exe",
            processId: 6712);

        if (cmd == null || cmd.PureCommand != "id") return false;

        // 2. Inbound ADB Response
        var resp = layer.AuditInboundResponse(
            rawResponse: "<< uid=0(root) gid=0(root) groups=0(root) context=u:r:su:s0",
            protocol: "ADB",
            targetDevice: "ADB:R58M123");

        if (resp == null) return false;
        if (resp.PureCommand != "uid=0(root) gid=0(root) groups=0(root) context=u:r:su:s0") return false;
        if (resp.RelatedCommandId != cmd.Id) return false;
        if (resp.RelatedCommandText != "id") return false;
        if (resp.RiskLevel != "ROOT / PRIVILEGED") return false;
        if (cmd.DeviceResponse != "uid=0(root) gid=0(root) groups=0(root) context=u:r:su:s0") return false;
        if (layer.AdbCount != 2) return false;

        return true;
    }

    public static bool Test70_TechnicianAuditMtkBromAndPreloaderResponse()
    {
        using var layer = new TechnicianPhoneCommandAuditLayer();
        layer.CaptureDeviceResponses = true;

        byte[] bromHandshake = [0xA0, 0x0A, 0x50, 0x05];
        var cmd = layer.AuditOutboundCommand(
            rawCommand: "BROM_HANDSHAKE_START",
            protocol: "MTK-BROM",
            mode: "MTK BROM",
            targetDevice: "USB\\VID_0E8D&PID_0003",
            technicianTool: "TFTUnlock.exe",
            processId: 9024,
            payloadBytes: bromHandshake);

        if (cmd == null) return false;

        // Phone responds with BROM sync ACK: 0x5F 0xF5 0xAF 0xFA
        byte[] bromAck = [0x5F, 0xF5, 0xAF, 0xFA];
        var resp = layer.AuditInboundResponse(
            rawResponse: "BROM_ACK",
            protocol: "MTK-BROM",
            mode: "MTK BROM",
            targetDevice: "USB\\VID_0E8D&PID_0003",
            payloadBytes: bromAck);

        if (resp == null) return false;
        if (!resp.HexPayload.Contains("5F F5 AF FA")) return false;
        if (resp.RelatedCommandId != cmd.Id) return false;
        if (resp.RiskLevel != "SUCCESS / OK") return false;
        if (layer.MtkCount != 2) return false;

        return true;
    }

    public static bool Test71_TechnicianAuditQualcommEdlFirehoseResponse()
    {
        using var layer = new TechnicianPhoneCommandAuditLayer();
        layer.CaptureDeviceResponses = true;

        string firehoseCmd = "<?xml version=\"1.0\" ?><data><program SECTOR_SIZE_IN_BYTES=\"512\" num_partition_sectors=\"2048\" physical_partition_number=\"0\" start_sector=\"0\" filename=\"boot.img\"/></data>";
        var cmd = layer.AuditOutboundCommand(
            rawCommand: firehoseCmd,
            protocol: "QCOM-FIREHOSE",
            mode: "Qualcomm EDL 9008",
            targetDevice: "COM21",
            technicianTool: "QFIL.exe",
            processId: 4420);

        if (cmd == null) return false;

        string firehoseResp = "<?xml version=\"1.0\" ?><data><response value=\"ACK\" rawmode=\"false\" /></data>";
        var resp = layer.AuditInboundResponse(
            rawResponse: firehoseResp,
            protocol: "QCOM-FIREHOSE",
            mode: "Qualcomm EDL 9008",
            targetDevice: "COM21");

        if (resp == null) return false;
        if (!resp.PureCommand.Contains("<response value=\"ACK\"")) return false;
        if (resp.RelatedCommandId != cmd.Id) return false;
        if (resp.RiskLevel != "SUCCESS / OK") return false;
        if (cmd.DeviceResponse == null || !cmd.DeviceResponse.Contains("value=\"ACK\"")) return false;
        if (layer.EdlCount != 2) return false;

        return true;
    }

    public static bool Test72_TechnicianAuditFastbootResponseInterception()
    {
        using var layer = new TechnicianPhoneCommandAuditLayer();
        layer.CaptureDeviceResponses = true;

        var cmd = layer.AuditOutboundCommand(
            rawCommand: "getvar version",
            protocol: "FASTBOOT",
            mode: "Fastboot",
            targetDevice: "fastboot:982312",
            technicianTool: "UnlockTool.exe",
            processId: 3311);

        if (cmd == null) return false;

        // OKAY response
        var respOk = layer.AuditInboundResponse(
            rawResponse: "OKAY [ 0.045s]",
            protocol: "FASTBOOT",
            targetDevice: "fastboot:982312");

        if (respOk == null) return false;
        if (respOk.PureCommand != "OKAY [ 0.045s]") return false;
        if (respOk.RiskLevel != "SUCCESS / OK") return false;

        // FAIL response scenario
        var respFail = layer.AuditInboundResponse(
            rawResponse: "FAIL (bootloader is locked)",
            protocol: "FASTBOOT",
            targetDevice: "fastboot:982312");

        if (respFail == null) return false;
        if (respFail.RiskLevel != "ERROR / FAIL") return false;
        if (layer.FastbootCount != 3) return false;

        return true;
    }

    public static bool Test73_TechnicianAuditDiskStorePersistenceWithResponses()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "TechAuditRespTest_" + Guid.NewGuid().ToString("N"));
        try
        {
            using (var layer = new TechnicianPhoneCommandAuditLayer(bus: null, customLogDirectory: tempDir))
            {
                layer.CaptureDeviceResponses = true;

                // 1. AT command & response
                var cmd1 = layer.AuditOutboundCommand(
                    rawCommand: "AT+DEVCONINFO\r\n",
                    protocol: "AT-MODEM",
                    mode: "Modem / Diag",
                    targetDevice: "COM15",
                    technicianTool: "UnlockTool.exe",
                    processId: 5412);

                var resp1 = layer.AuditInboundResponse(
                    rawResponse: "<< +DEVCONINFO: 1, 0, 0\r\nOK",
                    protocol: "AT-MODEM",
                    targetDevice: "COM15");

                // 2. ADB command & response
                var cmd2 = layer.AuditOutboundCommand(
                    rawCommand: "OPEN -> shell:getprop ro.serialno",
                    protocol: "ADB",
                    mode: "Normal",
                    targetDevice: "ADB:R58M999",
                    technicianTool: "Chimera.exe",
                    processId: 6712);

                var resp2 = layer.AuditInboundResponse(
                    rawResponse: "<< R58M99999",
                    protocol: "ADB",
                    targetDevice: "ADB:R58M999");

                layer.Flush();
            }

            // Verify files on disk
            string jsonlFile = Path.Combine(tempDir, $"TechnicianAudit_{DateTime.UtcNow:yyyyMMdd}.jsonl");
            string logFile = Path.Combine(tempDir, $"TechnicianAudit_{DateTime.UtcNow:yyyyMMdd}.log");

            if (!File.Exists(jsonlFile)) return false;
            if (!File.Exists(logFile)) return false;

            string jsonlContent = File.ReadAllText(jsonlFile);
            string logContent = File.ReadAllText(logFile);

            // Log file assertions:
            // Must contain both >> (outbound) and << (inbound) symbols
            if (!logContent.Contains(">> AT+DEVCONINFO")) return false;
            if (!logContent.Contains("<< +DEVCONINFO: 1, 0, 0")) return false;
            if (!logContent.Contains(">> getprop ro.serialno")) return false;
            if (!logContent.Contains("<< R58M99999")) return false;
            if (!logContent.Contains("[In Response To #")) return false;

            // JSONL assertions:
            if (!jsonlContent.Contains("\"IsResponse\":false")) return false;
            if (!jsonlContent.Contains("\"IsResponse\":true")) return false;
            if (!jsonlContent.Contains("\"PureCommand\":\"AT+DEVCONINFO\"")) return false;
            if (!jsonlContent.Contains("DEVCONINFO")) return false;

            return true;
        }
        finally
        {
            try { if (Directory.Exists(tempDir)) Directory.Delete(tempDir, true); } catch { }
        }
    }
}
