using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using PhoenixGSM.OmniTrace.Bus;
using PhoenixGSM.OmniTrace.Decoders;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.Tests;

public static partial class Program
{
    private static bool Test37_MtpMtkSpdEdlProtocolDecodingAndPipeline()
    {
        // -------------------------------------------------------------------
        // 1. MTP / PTP PROTOCOL VALIDATION
        // -------------------------------------------------------------------
        // Standard MTP GET_DEVICE_INFO command container (12 bytes)
        byte[] mtpCmdBytes = new byte[12];
        BitConverter.GetBytes((uint)12).CopyTo(mtpCmdBytes, 0);     // Container Length
        BitConverter.GetBytes((ushort)1).CopyTo(mtpCmdBytes, 4);    // Type: COMMAND
        BitConverter.GetBytes((ushort)0x1001).CopyTo(mtpCmdBytes, 6); // Code: GET_DEVICE_INFO
        BitConverter.GetBytes((uint)1).CopyTo(mtpCmdBytes, 8);      // Transaction ID

        double mtpConf = MtpDecoder.EvaluateMtp(mtpCmdBytes);
        if (mtpConf < 0.90) return false;

        var mtpDecoded = MtpDecoder.DecodePacket(mtpCmdBytes);
        if (mtpDecoded == null || mtpDecoded.OperationName != "GET_DEVICE_INFO" || mtpDecoded.ContainerType != 1) return false;

        // MTP FRP Push URL Data block
        string testUrl = "https://www.youtube.com/bypass_frp";
        byte[] urlAscii = Encoding.ASCII.GetBytes(testUrl);
        byte[] mtpDataBytes = new byte[12 + urlAscii.Length];
        BitConverter.GetBytes((uint)mtpDataBytes.Length).CopyTo(mtpDataBytes, 0);
        BitConverter.GetBytes((ushort)2).CopyTo(mtpDataBytes, 4); // Type: DATA
        BitConverter.GetBytes((ushort)0x1001).CopyTo(mtpDataBytes, 6);
        BitConverter.GetBytes((uint)1).CopyTo(mtpDataBytes, 8);
        urlAscii.CopyTo(mtpDataBytes, 12);

        var mtpDataDecoded = MtpDecoder.DecodePacket(mtpDataBytes);
        if (mtpDataDecoded == null || !mtpDataDecoded.ExtractedText.Contains("bypass_frp")) return false;

        // -------------------------------------------------------------------
        // 2. MEDIATEK (MTK) BROM & DA PROTOCOL VALIDATION
        // -------------------------------------------------------------------
        // BROM Start Sync Ping from Host
        byte[] bromPing = [0xA0, 0x0A, 0x50, 0x05];
        double mtkPingConf = MtkProtocolDecoder.EvaluateMtk(bromPing);
        if (mtkPingConf < 0.90) return false;

        var mtkPingDecoded = MtkProtocolDecoder.DecodePacket(bromPing, PacketDirection.HOST_TO_DEVICE);
        if (mtkPingDecoded == null || mtkPingDecoded.CommandName != "BROM_HANDSHAKE_START" || mtkPingDecoded.Stage != "BROM") return false;

        // BROM Device ACK
        byte[] bromAck = [0x5F, 0xF5, 0xAF, 0xFA];
        var mtkAckDecoded = MtkProtocolDecoder.DecodePacket(bromAck, PacketDirection.DEVICE_TO_HOST);
        if (mtkAckDecoded == null || mtkAckDecoded.CommandName != "BROM_HANDSHAKE_ACK") return false;

        // BROM HW Code identification response for MT6765 (Helio P35)
        byte[] mtkHwResp = [0xD4, 0x07, 0x68, 0x00];
        var mtkHwDecoded = MtkProtocolDecoder.DecodePacket(mtkHwResp, PacketDirection.DEVICE_TO_HOST);
        if (mtkHwDecoded == null || mtkHwDecoded.HardwareCode != 0x0768 || !mtkHwDecoded.ChipName.Contains("MT6765")) return false;

        // DA Write Partition Command
        byte[] mtkDaBytes = new byte[32];
        mtkDaBytes[0] = 0x32; // DA_WRITE_PARTITION
        Encoding.ASCII.GetBytes("boot").CopyTo(mtkDaBytes, 4);
        var mtkDaDecoded = MtkProtocolDecoder.DecodePacket(mtkDaBytes, PacketDirection.HOST_TO_DEVICE);
        if (mtkDaDecoded == null || mtkDaDecoded.Stage != "DA" || mtkDaDecoded.CommandName != "DA_WRITE_PARTITION" || mtkDaDecoded.Details["TargetPartition"] != "boot") return false;

        // -------------------------------------------------------------------
        // 3. UNISOC / SPREADTRUM (SPD) BSL & FDL PROTOCOL VALIDATION
        // -------------------------------------------------------------------
        // HDLC Framed BSL_CMD_CONNECT (0x0001)
        byte[] spdConnect = [0x7E, 0x00, 0x01, 0x00, 0x00, 0x7E];
        double spdConf = SpdFdlDecoder.EvaluateSpd(spdConnect);
        if (spdConf < 0.90) return false;

        var spdConnDecoded = SpdFdlDecoder.DecodePacket(spdConnect);
        if (spdConnDecoded == null || spdConnDecoded.CommandType != 0x0001 || spdConnDecoded.CommandName != "BSL_CMD_CONNECT") return false;

        // HDLC Framed BSL_REP_VER (0x0081) with chip string "SC9863A"
        byte[] spdVer = [0x7E, 0x00, 0x81, 0x00, 0x07, (byte)'S', (byte)'C', (byte)'9', (byte)'8', (byte)'6', (byte)'3', (byte)'A', 0x7E];
        var spdVerDecoded = SpdFdlDecoder.DecodePacket(spdVer);
        if (spdVerDecoded == null || spdVerDecoded.CommandType != 0x0081 || spdVerDecoded.VersionOrChipString != "SC9863A") return false;

        // -------------------------------------------------------------------
        // 4. QUALCOMM EDL 9008 (SAHARA & FIREHOSE XML) VALIDATION
        // -------------------------------------------------------------------
        // Sahara Phase: 48-byte SAHARA_HELLO_REQ
        byte[] saharaHello = new byte[48];
        BitConverter.GetBytes((uint)0x01).CopyTo(saharaHello, 0); // SAHARA_HELLO_REQ
        BitConverter.GetBytes((uint)48).CopyTo(saharaHello, 4);   // Length 48
        BitConverter.GetBytes((uint)2).CopyTo(saharaHello, 8);    // Version 2

        double saharaConf = QualcommEdlDecoder.EvaluateSahara(saharaHello);
        if (saharaConf < 0.95) return false;

        var saharaDecoded = QualcommEdlDecoder.DecodePacket(saharaHello);
        if (saharaDecoded == null || saharaDecoded.Phase != "SAHARA" || saharaDecoded.Action != "SAHARA_HELLO_REQ") return false;

        // Firehose XML Phase: Program command
        string firehoseXml = "<?xml version=\"1.0\" ?><data><program filename=\"boot.img\" num_partition_sectors=\"65536\" physical_partition_number=\"0\" start_sector=\"2048\"/></data>";
        byte[] firehoseBytes = Encoding.UTF8.GetBytes(firehoseXml);

        double firehoseConf = QualcommEdlDecoder.EvaluateFirehose(firehoseBytes);
        if (firehoseConf < 0.95) return false;

        var firehoseDecoded = QualcommEdlDecoder.DecodePacket(firehoseBytes);
        if (firehoseDecoded == null || firehoseDecoded.Phase != "FIREHOSE" || !firehoseDecoded.Action.Contains("PROGRAM") || firehoseDecoded.TargetPartitionOrFile != "boot.img") return false;

        // -------------------------------------------------------------------
        // 5. FULL PIPELINE DISPATCH & EVENT BUS INTEGRATION
        // -------------------------------------------------------------------
        using var bus = new OmniTraceEventBus();
        var capturedCommands = new List<LogicalCommandEvent>();
        bus.OnLogicalCommand += cmd =>
        {
            lock (capturedCommands) capturedCommands.Add(cmd);
        };

        // Dispatch MTP
        bus.ProcessSingleEvent(RawCaptureEvent.Create(
            1, SensorType.USB, TransportType.BULK, PacketDirection.HOST_TO_DEVICE,
            "SAMSUNG_MTP_DEVICE", "MTP_SESS", 0, "0x01", mtpCmdBytes));

        // Dispatch MTK
        bus.ProcessSingleEvent(RawCaptureEvent.Create(
            2, SensorType.Serial, TransportType.SERIAL, PacketDirection.HOST_TO_DEVICE,
            "MTK_PRELOADER_COM15", "MTK_SESS", 0, "COM15", bromPing));

        // Dispatch SPD
        bus.ProcessSingleEvent(RawCaptureEvent.Create(
            3, SensorType.Serial, TransportType.SERIAL, PacketDirection.HOST_TO_DEVICE,
            "SPD_DIAG_COM21", "SPD_SESS", 0, "COM21", spdConnect));

        // Dispatch Qualcomm Firehose
        bus.ProcessSingleEvent(RawCaptureEvent.Create(
            4, SensorType.USB, TransportType.BULK, PacketDirection.HOST_TO_DEVICE,
            "QUALCOMM_EDL_9008", "EDL_SESS", 0, "0x01", firehoseBytes));

        bus.Flush(500);

        lock (capturedCommands)
        {
            var mtpEvt = capturedCommands.FirstOrDefault(c => c.Protocol == KnownProtocol.Mtp);
            var mtkEvt = capturedCommands.FirstOrDefault(c => c.Protocol == KnownProtocol.MtkBrom);
            var spdEvt = capturedCommands.FirstOrDefault(c => c.Protocol == KnownProtocol.SpreadtrumFdl);
            var edlEvt = capturedCommands.FirstOrDefault(c => c.Protocol == KnownProtocol.QualcommFirehose);

            if (mtpEvt == null || mtkEvt == null || spdEvt == null || edlEvt == null) return false;
            if (mtpEvt.Confidence < 0.90 || mtkEvt.Confidence < 0.90 || spdEvt.Confidence < 0.90 || edlEvt.Confidence < 0.90) return false;
            if (!edlEvt.Details.ContainsKey("filename") || edlEvt.Details["filename"] != "boot.img") return false;

            return true;
        }
    }
}
