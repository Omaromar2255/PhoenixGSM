using System;
using System.Buffers.Binary;
using System.IO;
using System.Text;
using System.Threading;
using PhoenixGSM.OmniTrace.Bus;
using PhoenixGSM.OmniTrace.Models;
using PhoenixGSM.OmniTrace.ToolSourceInterception;

namespace PhoenixGSM.OmniTrace.Tests;

public static partial class Program
{
    public static bool Test74_ToolSourceMtpCommandInterception()
    {
        // Construct MTP SendObject container (12B header + parameters)
        // Length=16, Type=1 (Command), OpCode=0x100D (SendObject), TransId=0x1234
        byte[] mtpPayload = new byte[16];
        BinaryPrimitives.WriteUInt32LittleEndian(mtpPayload.AsSpan(0, 4), 16);
        BinaryPrimitives.WriteUInt16LittleEndian(mtpPayload.AsSpan(4, 2), 1); // Command
        BinaryPrimitives.WriteUInt16LittleEndian(mtpPayload.AsSpan(6, 2), 0x100D); // SendObject
        BinaryPrimitives.WriteUInt32LittleEndian(mtpPayload.AsSpan(8, 4), 0x1234); // TransId
        BinaryPrimitives.WriteUInt32LittleEndian(mtpPayload.AsSpan(12, 4), 0x00010001); // Param1

        bool parsed = MtpSourceInterceptor.TryParseMtpCommand(
            mtpPayload,
            toolName: "UnlockTool.exe",
            pid: 4012,
            parentPid: 1000,
            endpoint: "MTP USB Interface",
            mechanism: "DeviceIoControl",
            out var record);

        if (!parsed || record == null) return false;
        if (record.Mode != ToolSourceMode.Mtp) return false;
        if (!record.PureCommand.Contains("SendObject")) return false;
        if (record.RiskLevel != "WARNING") return false;
        if (record.ToolName != "UnlockTool.exe") return false;
        if (record.ProcessId != 4012) return false;
        if (record.PayloadSize != 16) return false;

        return true;
    }

    public static bool Test75_ToolSourceMtkBromHandshakeAndCommandInterception()
    {
        // 1. Handshake Sync (0xA0 0x0A 0x50 0x05)
        byte[] syncBytes = [0xA0, 0x0A, 0x50, 0x05];
        bool syncParsed = MtkBromSourceInterceptor.TryParseMtkCommand(
            syncBytes,
            toolName: "UnlockTool.exe",
            pid: 5020,
            parentPid: 1000,
            endpoint: "USB\\VID_0E8D&PID_0003",
            mechanism: "libusb_bulk_transfer",
            out var syncRecord);

        if (!syncParsed || syncRecord == null) return false;
        if (syncRecord.Mode != ToolSourceMode.MtkBrom) return false;
        if (!syncRecord.PureCommand.Contains("MTK_BROM_HANDSHAKE")) return false;

        // 2. CMD_GET_HW_CODE (0xD8)
        byte[] hwCmd = [0xD8];
        bool hwParsed = MtkBromSourceInterceptor.TryParseMtkCommand(
            hwCmd,
            toolName: "SP_Flash_Tool.exe",
            pid: 6100,
            parentPid: 1000,
            endpoint: "USB\\VID_0E8D&PID_0003",
            mechanism: "DeviceIoControl",
            out var hwRecord);

        if (!hwParsed || hwRecord == null) return false;
        if (!hwRecord.PureCommand.Contains("CMD_GET_HW_CODE")) return false;

        // 3. DA Operation ERASE_FRP
        byte[] daPayload = Encoding.ASCII.GetBytes("DA_CMD_ERASE_FRP_PARTITION_BLOCK");
        bool daParsed = MtkBromSourceInterceptor.TryParseMtkCommand(
            daPayload,
            toolName: "Chimera.exe",
            pid: 7200,
            parentPid: 1000,
            endpoint: "MTK High Speed Port",
            mechanism: "WinUsb_WritePipe",
            out var daRecord);

        if (!daParsed || daRecord == null) return false;
        if (!daRecord.PureCommand.Contains("ERASE_FRP")) return false;
        if (daRecord.RiskLevel != "CRITICAL") return false;

        return true;
    }

    public static bool Test76_ToolSourceSamsungOdinLokeProtocolInterception()
    {
        // 1. Odin / Loke Magic Handshake
        byte[] odinMagic = "ODIN"u8.ToArray();
        bool magicParsed = OdinSourceInterceptor.TryParseOdinCommand(
            odinMagic,
            toolName: "Odin3_v3.14.exe",
            pid: 8800,
            parentPid: 1000,
            endpoint: "SAMSUNG Mobile USB CDC",
            mechanism: "DeviceIoControl",
            out var magicRecord);

        if (!magicParsed || magicRecord == null) return false;
        if (magicRecord.Mode != ToolSourceMode.SamsungOdin) return false;
        if (!magicRecord.PureCommand.Contains("ODIN_HANDSHAKE")) return false;

        // 2. PIT Request (0x64 'd')
        byte[] pitReq = [0x64];
        bool pitParsed = OdinSourceInterceptor.TryParseOdinCommand(
            pitReq,
            toolName: "SamFwFRPTool.exe",
            pid: 9100,
            parentPid: 1000,
            endpoint: "SAMSUNG Mobile USB CDC",
            mechanism: "DeviceIoControl",
            out var pitRecord);

        if (!pitParsed || pitRecord == null) return false;
        if (!pitRecord.PureCommand.Contains("PIT_REQUEST")) return false;

        // 3. Flash Partition Start (0x65 'e' + "BOOT")
        byte[] flashStart = [0x65, (byte)'B', (byte)'O', (byte)'O', (byte)'T', 0];
        bool flashParsed = OdinSourceInterceptor.TryParseOdinCommand(
            flashStart,
            toolName: "Odin3_v3.14.exe",
            pid: 8800,
            parentPid: 1000,
            endpoint: "SAMSUNG Mobile USB CDC",
            mechanism: "DeviceIoControl",
            out var flashRecord);

        if (!flashParsed || flashRecord == null) return false;
        if (!flashRecord.PureCommand.Contains("FLASH_PARTITION_START")) return false;
        if (!flashRecord.PureCommand.Contains("BOOT")) return false;
        if (flashRecord.RiskLevel != "CRITICAL") return false;

        return true;
    }

    public static bool Test77_ToolSourceSerialPortAtCommandInterception()
    {
        // 1. Samsung Factory Reset Bypass AT Command
        byte[] atCmd1 = "AT+FACTORST=0,0\r\n"u8.ToArray();
        bool parsed1 = PortSourceInterceptor.TryParsePortCommand(
            atCmd1,
            toolName: "UnlockTool.exe",
            pid: 3300,
            parentPid: 1000,
            endpoint: "\\\\.\\COM14",
            mechanism: "WriteFile_COM",
            out var rec1);

        if (!parsed1 || rec1 == null) return false;
        if (rec1.Mode != ToolSourceMode.SerialPort) return false;
        if (!rec1.PureCommand.Contains("AT+FACTORST=0,0")) return false;
        if (rec1.RiskLevel != "CRITICAL") return false;

        // 2. MediaTek IMEI Repair AT Command
        byte[] atCmd2 = "AT+EGMR=1,7,\"352012345678901\"\r\n"u8.ToArray();
        bool parsed2 = PortSourceInterceptor.TryParsePortCommand(
            atCmd2,
            toolName: "MiracleBox.exe",
            pid: 4400,
            parentPid: 1000,
            endpoint: "\\\\.\\COM7",
            mechanism: "WriteFile_COM",
            out var rec2);

        if (!parsed2 || rec2 == null) return false;
        if (!rec2.PureCommand.Contains("AT+EGMR=1,7")) return false;
        if (rec2.RiskLevel != "CRITICAL") return false;

        return true;
    }

    public static bool Test78_ToolSourceQualcommDiagHdlcInterception()
    {
        // Qualcomm Diag HDLC frame: 0x7E 0x26 (NV Write) 0x00 0x7E
        byte[] diagFrame = [0x7E, 0x26, 0x00, 0x00, 0x7E];
        bool parsed = PortSourceInterceptor.TryParsePortCommand(
            diagFrame,
            toolName: "QFIL.exe",
            pid: 5500,
            parentPid: 1000,
            endpoint: "\\\\.\\COM3",
            mechanism: "WriteFile_COM",
            out var rec);

        if (!parsed || rec == null) return false;
        if (rec.Mode != ToolSourceMode.SerialPort) return false;
        if (!rec.PureCommand.Contains("QCOM_DIAG")) return false;
        if (!rec.PureCommand.Contains("DIAG_NV_WRITE_F")) return false;
        if (rec.RiskLevel != "CRITICAL") return false;

        return true;
    }

    public static bool Test79_ToolSourceApiHookEngineRoutingAndFallback()
    {
        using var engine = new ToolSourceApiHookEngine();
        ToolSourceCommandRecord? captured = null;
        engine.OnCommandCaptured += r => captured = r;

        // Ingest unparsed payload (Universal Fallback)
        byte[] unknownBytes = [0xAA, 0xBB, 0xCC, 0xDD];
        var rec = engine.IngestApiCall(
            pid: 7700,
            parentPid: 1000,
            toolName: "UnknownGsmTool.exe",
            apiName: "DeviceIoControl",
            endpoint: "\\\\.\\Device0",
            payload: unknownBytes);

        if (rec == null) return false;
        if (rec.Mode != ToolSourceMode.Universal) return false;
        if (rec.ToolName != "UnknownGsmTool.exe") return false;
        if (captured == null || captured.Id != rec.Id) return false;
        if (engine.CallsCaptured != 1) return false;

        return true;
    }

    public static bool Test80_ToolSourceOrchestratorDiscoveryAndPersistence()
    {
        string testLogDir = Path.Combine(Path.GetTempPath(), "PhoenixGSM_TSCI_Test_" + Guid.NewGuid().ToString("N"));
        try
        {
            var bus = new OmniTraceEventBus();
            using var orchestrator = new ToolSourceInterceptionOrchestrator(bus, testLogDir);
            orchestrator.Start();

            // Ingest sample commands across all 4 modes
            orchestrator.IngestCommand(1001, 1000, "UnlockTool.exe", "DeviceIoControl", "MTP", [0x0C, 0, 0, 0, 1, 0, 0x01, 0x10, 1, 0, 0, 0]);
            orchestrator.IngestCommand(1002, 1000, "UnlockTool.exe", "libusb_bulk_transfer", "USB\\VID_0E8D&PID_0003", [0xA0, 0x0A, 0x50, 0x05]);
            orchestrator.IngestCommand(1003, 1000, "Odin3.exe", "DeviceIoControl", "SAMSUNG", [0x64]);
            orchestrator.IngestCommand(1004, 1000, "Chimera.exe", "WriteFile_COM", "\\\\.\\COM5", "AT+FACTORST=0,0\r\n"u8.ToArray());

            if (orchestrator.TotalCapturedCount != 4) return false;
            if (orchestrator.MtpCount != 1) return false;
            if (orchestrator.MtkCount != 1) return false;
            if (orchestrator.OdinCount != 1) return false;
            if (orchestrator.PortCount != 1) return false;

            // Flush logger
            orchestrator.AutoLogger.Flush();

            // Verify files created on disk
            string[] logFiles = Directory.GetFiles(testLogDir);
            if (logFiles.Length == 0) return false;

            return true;
        }
        finally
        {
            try { Directory.Delete(testLogDir, recursive: true); } catch { }
        }
    }
}
