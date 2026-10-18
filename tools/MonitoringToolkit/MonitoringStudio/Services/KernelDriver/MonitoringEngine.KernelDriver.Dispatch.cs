using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using PhoenixGSM.MonitoringStudio.Models;

namespace PhoenixGSM.MonitoringStudio.Services;

public partial class MonitoringEngine
{
    private void ProcessCapturedKernelPacket(
        PhoenixGSM.UsbMonitor.UsbDriverClient.KernelUsbPacket pkt,
        byte[] chunk,
        string dir,
        string epHex,
        PhoenixGSM.OmniTrace.Models.PacketDirection pDir,
        bool isUpperFilterPort)
    {
        bool isAdbHeader = chunk.Length >= 24 && PhoenixGSM.UsbMonitor.Protocol.AdbProtocolParser.ValidateHeader(chunk, 0, out _, out _, out _, out _, out _);
        bool isSahara = chunk.Length >= 8 && PhoenixGSM.OmniTrace.Decoders.QualcommEdlDecoder.EvaluateSahara(chunk) >= 0.8;
        bool isFirehose = chunk.Length >= 5 && (Encoding.ASCII.GetString(chunk[..Math.Min(chunk.Length, 64)]).StartsWith("<?xml", StringComparison.OrdinalIgnoreCase) || Encoding.ASCII.GetString(chunk[..Math.Min(chunk.Length, 64)]).Contains("<data>"));
        string rawAsciiPreview = chunk.Length > 0 ? Encoding.ASCII.GetString(chunk[..Math.Min(chunk.Length, 128)]) : "";

        string cleanLine = chunk.Length > 0 ? Encoding.ASCII.GetString(chunk).Trim('\r', '\n', '\t', '\0', ' ') : "";
        string cleanLineTrimmed = cleanLine.Trim();

        // Compute non-printable ratio early to prevent binary ELF chunks from polluting interactive shell commands
        int nonPrintableCount = 0;
        bool hasElfMagic = false;
        for (int i = 0; i < chunk.Length; i++)
        {
            byte b = chunk[i];
            if (b < 0x20 && b != 9 && b != 10 && b != 13 && b != 0) nonPrintableCount++;
            else if (b > 0x7E) nonPrintableCount++;
            if (i + 3 < chunk.Length && chunk[i] == 0x7F && chunk[i + 1] == 0x45 && chunk[i + 2] == 0x4C && chunk[i + 3] == 0x46)
            {
                hasElfMagic = true;
            }
        }
        double nonPrintableRatio = chunk.Length > 0 ? (double)nonPrintableCount / chunk.Length : 0.0;
        bool isBinaryPayloadChunk = hasElfMagic || nonPrintableRatio > 0.20 ||
                                    cleanLineTrimmed.Contains(",33188DATA", StringComparison.Ordinal) ||
                                    cleanLineTrimmed.Contains(",33261DATA", StringComparison.Ordinal) ||
                                    rawAsciiPreview.Contains("ELF");

        // Detect ADB Sync start/stop transitions BEFORE evaluating interactive shell commands
        bool isSyncOpen = cleanLineTrimmed.Equals("sync:", StringComparison.OrdinalIgnoreCase) ||
                          rawAsciiPreview.StartsWith("sync:", StringComparison.OrdinalIgnoreCase);

        if (isAdbHeader || isSyncOpen ||
            cleanLineTrimmed.StartsWith("shell:", StringComparison.OrdinalIgnoreCase) ||
            rawAsciiPreview.StartsWith("shell:", StringComparison.OrdinalIgnoreCase) ||
            rawAsciiPreview.Contains("shell:") || rawAsciiPreview.Contains("sync:"))
        {
            _isAdbSessionActive = true;
        }

        bool isAdbSyncToken = isSyncOpen ||
                              rawAsciiPreview.StartsWith("STAT", StringComparison.Ordinal) ||
                              rawAsciiPreview.StartsWith("SEND", StringComparison.Ordinal) ||
                              rawAsciiPreview.StartsWith("RECV", StringComparison.Ordinal) ||
                              rawAsciiPreview.StartsWith("DATA", StringComparison.Ordinal) ||
                              rawAsciiPreview.StartsWith("DONE", StringComparison.Ordinal) ||
                              rawAsciiPreview.StartsWith("DENT", StringComparison.Ordinal) ||
                              rawAsciiPreview.StartsWith("LIST", StringComparison.Ordinal) ||
                              cleanLineTrimmed.Contains(",33188DATA", StringComparison.Ordinal) ||
                              cleanLineTrimmed.Contains(",33261DATA", StringComparison.Ordinal);

        // Ignore internal background archiver commands (.phx_keep_) so they never pollute the user log
        if (rawAsciiPreview.Contains(".phx_keep_", StringComparison.OrdinalIgnoreCase) ||
            cleanLineTrimmed.Contains(".phx_keep_", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        if (isSyncOpen || rawAsciiPreview.StartsWith("STAT", StringComparison.Ordinal) ||
            rawAsciiPreview.StartsWith("SEND", StringComparison.Ordinal) ||
            cleanLineTrimmed.Contains(",33188", StringComparison.Ordinal) ||
            cleanLineTrimmed.Contains(",33206", StringComparison.Ordinal) ||
            cleanLineTrimmed.Contains(",33261", StringComparison.Ordinal) ||
            cleanLineTrimmed.Contains(",33279", StringComparison.Ordinal))
        {
            _isInsideFileSyncTransfer = true;
            _activeInteractiveShellCommand = string.Empty;
        }

        // Feed outbound non-shell packets into SmartFilePushArchiver BEFORE evaluating isAdbInteractiveCmd/isAdbStream
        if (dir == "OUT" && !isUpperFilterPort && !(isAdbHeader && chunk.Length == 24) &&
            !cleanLineTrimmed.StartsWith("shell:", StringComparison.OrdinalIgnoreCase))
        {
            _smartFileArchiver.ProcessOutboundSyncOrBulkChunk(chunk, dir, epHex, pkt.ActualLength, out _);
            if (_smartFileArchiver.IsInsideTransfer)
            {
                _isInsideFileSyncTransfer = true;
            }
        }

        // Track channel state transitions for explicit shell commands
        if (!isBinaryPayloadChunk && !isAdbSyncToken &&
            (cleanLineTrimmed.StartsWith("shell:", StringComparison.OrdinalIgnoreCase) ||
             rawAsciiPreview.StartsWith("shell:", StringComparison.OrdinalIgnoreCase)))
        {
            string sCmd = cleanLineTrimmed.StartsWith("shell:", StringComparison.OrdinalIgnoreCase)
                ? cleanLineTrimmed
                : rawAsciiPreview[rawAsciiPreview.IndexOf("shell:", StringComparison.OrdinalIgnoreCase)..].Split(new[] { '\0', '\r', '\n' })[0].Trim();

            _activeInteractiveShellCommand = sCmd;
            _isInsideFileSyncTransfer = false;

            if (sCmd.Contains("/data/local/tmp/AT", StringComparison.OrdinalIgnoreCase) &&
                !sCmd.Contains("chmod ", StringComparison.OrdinalIgnoreCase))
            {
                _lastActiveAtBinaryCommand = sCmd;
            }

            if (_smartFileArchiver.CheckShellCommandForInlineFileOrFlush(sCmd, 0, "adb.exe", out var shellRec) && shellRec != null)
            {
                EmitCapturedPushedFile(shellRec, epHex);
            }
        }
        else if (!isBinaryPayloadChunk && (cleanLineTrimmed.Contains("chmod ") || rawAsciiPreview.Contains("chmod ")))
        {
            _isInsideFileSyncTransfer = false;
            if (_smartFileArchiver.CheckShellCommandForInlineFileOrFlush(cleanLineTrimmed, 0, "adb.exe", out var chmodRec) && chmodRec != null)
            {
                EmitCapturedPushedFile(chmodRec, epHex);
            }
        }

        // Flush getprop aggregator if idle or another command is seen
        if (_isAggregatingGetprop)
        {
            if ((DateTime.UtcNow - _lastGetpropChunkTime).TotalMilliseconds > 400 ||
                cleanLineTrimmed.StartsWith("shell:") || cleanLineTrimmed.StartsWith("<<") ||
                cleanLineTrimmed.StartsWith("AT") || cleanLineTrimmed.StartsWith("SEND"))
            {
                FlushGetpropSummary(epHex, dir);
            }
        }

        bool isFastboot = !isBinaryPayloadChunk && (
                          rawAsciiPreview.StartsWith("getvar:", StringComparison.OrdinalIgnoreCase) ||
                          rawAsciiPreview.StartsWith("flash:", StringComparison.OrdinalIgnoreCase) ||
                          rawAsciiPreview.StartsWith("erase:", StringComparison.OrdinalIgnoreCase) ||
                          rawAsciiPreview.StartsWith("download:", StringComparison.OrdinalIgnoreCase) ||
                          rawAsciiPreview.StartsWith("boot", StringComparison.OrdinalIgnoreCase) ||
                          rawAsciiPreview.StartsWith("reboot", StringComparison.OrdinalIgnoreCase) ||
                          rawAsciiPreview.StartsWith("continue", StringComparison.OrdinalIgnoreCase) ||
                          rawAsciiPreview.StartsWith("oem ", StringComparison.OrdinalIgnoreCase) ||
                          rawAsciiPreview.StartsWith("flashing ", StringComparison.OrdinalIgnoreCase));

        bool isAdbSync = isAdbSyncToken ||
                         rawAsciiPreview.StartsWith("OKAY", StringComparison.Ordinal) ||
                         rawAsciiPreview.StartsWith("FAIL", StringComparison.Ordinal);

        // Hex RIL IPC detection: includes 12-char RIL headers like 060100120000 and >=16-char hex tokens
        bool isCleanHexString = !isBinaryPayloadChunk &&
                                cleanLineTrimmed.Length >= 12 &&
                                cleanLineTrimmed.Length % 2 == 0 &&
                                cleanLineTrimmed.All(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'));

        bool isAdbRilIpc = !isBinaryPayloadChunk && !isAdbSync && !_isInsideFileSyncTransfer && (
                           isCleanHexString ||
                           cleanLineTrimmed.StartsWith("060100", StringComparison.OrdinalIgnoreCase) ||
                           cleanLineTrimmed.StartsWith("120D00", StringComparison.OrdinalIgnoreCase) ||
                           cleanLineTrimmed.StartsWith("514200", StringComparison.OrdinalIgnoreCase) ||
                           cleanLineTrimmed.StartsWith("516400", StringComparison.OrdinalIgnoreCase) ||
                           cleanLineTrimmed.StartsWith("010100", StringComparison.OrdinalIgnoreCase) ||
                           cleanLineTrimmed.StartsWith("010300", StringComparison.OrdinalIgnoreCase) ||
                           rawAsciiPreview.StartsWith("1163000501", StringComparison.OrdinalIgnoreCase) ||
                           rawAsciiPreview.StartsWith("06090004", StringComparison.OrdinalIgnoreCase) ||
                           rawAsciiPreview.StartsWith("07170004", StringComparison.OrdinalIgnoreCase) ||
                           rawAsciiPreview.StartsWith("1163005F", StringComparison.OrdinalIgnoreCase) ||
                           rawAsciiPreview.StartsWith("116300", StringComparison.OrdinalIgnoreCase) ||
                           cleanLineTrimmed.StartsWith("1163000501", StringComparison.OrdinalIgnoreCase) ||
                           cleanLineTrimmed.StartsWith("06090004", StringComparison.OrdinalIgnoreCase) ||
                           cleanLineTrimmed.StartsWith("07170004", StringComparison.OrdinalIgnoreCase) ||
                           cleanLineTrimmed.StartsWith("3E257A2C", StringComparison.OrdinalIgnoreCase) ||
                           cleanLineTrimmed.StartsWith("AF6DBB85", StringComparison.OrdinalIgnoreCase) ||
                           cleanLineTrimmed.StartsWith("62E83911", StringComparison.OrdinalIgnoreCase) ||
                           cleanLineTrimmed.StartsWith("<<", StringComparison.Ordinal) ||
                           (chunk.Length >= 4 && chunk.Length <= 64 && chunk[0] == 0x11 && chunk[1] == 0x63));

        bool isAsciiText = chunk.Length > 0 && !isBinaryPayloadChunk &&
                           chunk.All(b => b == 0 || b == 9 || b == 10 || b == 13 || (b >= 32 && b < 127));

        bool isInteractiveShellActive = !string.IsNullOrEmpty(_activeInteractiveShellCommand) || !string.IsNullOrEmpty(_lastActiveAtBinaryCommand);

        // Clean Interactive / Shell Command Rule in OUT direction:
        // Strictly excludes binary ELF chunks, ADB Sync tokens (STAT/SEND/DATA/DONE), and bare '/data/local/tmp/AT' path from STAT
        bool isBareSyncPath = _isInsideFileSyncTransfer && cleanLineTrimmed.Equals("/data/local/tmp/AT", StringComparison.OrdinalIgnoreCase);
        bool isAdbInteractiveCmd = dir == "OUT" &&
                                   !isAdbHeader &&
                                   !isBinaryPayloadChunk &&
                                   !_isInsideFileSyncTransfer &&
                                   !isAdbSync &&
                                   !isBareSyncPath &&
                                   chunk.Length > 0 &&
                                   cleanLineTrimmed.Length > 0 &&
                                   !cleanLineTrimmed.Equals("host::", StringComparison.OrdinalIgnoreCase) &&
                                   (isAsciiText || isAdbRilIpc ||
                                    cleanLineTrimmed.StartsWith("shell:", StringComparison.OrdinalIgnoreCase) ||
                                    cleanLineTrimmed.StartsWith("usb:", StringComparison.OrdinalIgnoreCase) ||
                                    cleanLineTrimmed.StartsWith("reboot:", StringComparison.OrdinalIgnoreCase) ||
                                    cleanLineTrimmed.StartsWith("<<", StringComparison.Ordinal));

        // Detect Socket Bridges and Android 11+ Binder Bridges
        bool isSocketBridgeChannel = !isBinaryPayloadChunk && (
                                     !string.IsNullOrEmpty(_activeSocketBridgeChannel) ||
                                     PhoenixGSM.OmniTrace.Decoders.AdbSmartSocketDecoder.IsSocketBridgeChannel(cleanLineTrimmed) ||
                                     PhoenixGSM.OmniTrace.Decoders.AdbSmartSocketDecoder.IsModernAndroidService(cleanLineTrimmed) ||
                                     cleanLineTrimmed.StartsWith("tcp:", StringComparison.OrdinalIgnoreCase) ||
                                     cleanLineTrimmed.StartsWith("localabstract:", StringComparison.OrdinalIgnoreCase) ||
                                     cleanLineTrimmed.StartsWith("abb:", StringComparison.OrdinalIgnoreCase));

        bool isAppPrivilegeCmd = !isBinaryPayloadChunk && PhoenixGSM.OmniTrace.Decoders.AdbSmartSocketDecoder.IsAppPrivilegeCommand(cleanLineTrimmed);

        // Detect getprop property stream lines
        bool isGetpropOutput = !isBinaryPayloadChunk && (
                               cleanLineTrimmed.Contains("]: [") ||
                               (rawAsciiPreview.Contains("]: [") && !cleanLineTrimmed.StartsWith("AT", StringComparison.OrdinalIgnoreCase)) ||
                               (cleanLineTrimmed.StartsWith("[ro.") || cleanLineTrimmed.StartsWith("[gsm.") || cleanLineTrimmed.StartsWith("[sys.") || cleanLineTrimmed.StartsWith("[ril.")));

        // Check if incoming packet is a readable phone response in ADB mode
        string cleanedInboundText = CleanInboundPhoneResponse(chunk);
        bool isReadableInboundAdbResponse = dir == "IN" &&
                                            !isAdbHeader &&
                                            !isAdbSync &&
                                            !_isInsideFileSyncTransfer &&
                                            !isBinaryPayloadChunk &&
                                            isInteractiveShellActive &&
                                            cleanedInboundText.Length >= 2 &&
                                            !cleanedInboundText.StartsWith("STAT", StringComparison.Ordinal);

        bool isAdbStream = !isAdbRilIpc && !isAdbInteractiveCmd && !isBinaryPayloadChunk && (
                           isGetpropOutput ||
                           isReadableInboundAdbResponse ||
                           cleanLineTrimmed == "]" ||
                           cleanLineTrimmed.Contains("0x0000") ||
                           cleanLineTrimmed.Equals("Enforcing", StringComparison.OrdinalIgnoreCase) ||
                           cleanLineTrimmed.Equals("Permissive", StringComparison.OrdinalIgnoreCase) ||
                           cleanLineTrimmed.Contains("0x4948", StringComparison.OrdinalIgnoreCase) ||
                           cleanLineTrimmed.Contains("0x4f4c", StringComparison.OrdinalIgnoreCase) ||
                           cleanLineTrimmed.Contains("0x494d", StringComparison.OrdinalIgnoreCase) ||
                           cleanLineTrimmed.Contains("Product Name", StringComparison.OrdinalIgnoreCase) ||
                           cleanLineTrimmed.Contains("Product Model", StringComparison.OrdinalIgnoreCase) ||
                           cleanLineTrimmed.Contains("Build  Number", StringComparison.OrdinalIgnoreCase) ||
                           cleanLineTrimmed.Contains("Serial Number", StringComparison.OrdinalIgnoreCase) ||
                           cleanLineTrimmed.Contains("Device IMEI", StringComparison.OrdinalIgnoreCase) ||
                           cleanLineTrimmed.Contains("Android Ver", StringComparison.OrdinalIgnoreCase) ||
                           cleanLineTrimmed.Contains("Security Patch", StringComparison.OrdinalIgnoreCase) ||
                           cleanLineTrimmed.Contains("UID 1000", StringComparison.OrdinalIgnoreCase) ||
                           cleanLineTrimmed.Contains("uid=", StringComparison.OrdinalIgnoreCase) ||
                           cleanLineTrimmed.Contains("package:", StringComparison.OrdinalIgnoreCase) ||
                           cleanLineTrimmed.Contains("Failure [", StringComparison.OrdinalIgnoreCase) ||
                           cleanLineTrimmed.Contains("Connection refused", StringComparison.OrdinalIgnoreCase) ||
                           cleanLineTrimmed.Contains("AuthKey Encrypt", StringComparison.OrdinalIgnoreCase) ||
                           cleanLineTrimmed.Contains("restarting in USB mode", StringComparison.OrdinalIgnoreCase) ||
                           cleanLineTrimmed.StartsWith("usb:", StringComparison.OrdinalIgnoreCase) ||
                           cleanLineTrimmed.Contains("device::ro.product.", StringComparison.OrdinalIgnoreCase) ||
                           cleanLineTrimmed.Equals("OK\n\n\n#", StringComparison.Ordinal) ||
                           cleanLineTrimmed.Equals("#OK", StringComparison.Ordinal) ||
                           cleanLineTrimmed.Equals("OK", StringComparison.Ordinal) ||
                           cleanLineTrimmed.Equals("#", StringComparison.Ordinal) ||
                           cleanLineTrimmed.Equals("<<", StringComparison.Ordinal) ||
                           cleanLineTrimmed.Contains("****") ||
                           rawAsciiPreview.StartsWith("shell:", StringComparison.OrdinalIgnoreCase) ||
                           rawAsciiPreview.StartsWith("Result: Parcel(", StringComparison.OrdinalIgnoreCase) ||
                           rawAsciiPreview.StartsWith("[DEVICE_PROVISIONED]", StringComparison.OrdinalIgnoreCase) ||
                           rawAsciiPreview.StartsWith("while [ \"$(getprop", StringComparison.OrdinalIgnoreCase) ||
                           rawAsciiPreview.Contains("[ro.") ||
                           rawAsciiPreview.Contains("[init.svc.") ||
                           rawAsciiPreview.Contains("[persist.") ||
                           rawAsciiPreview.Contains("[dalvik.") ||
                           rawAsciiPreview.Contains("[sys.") ||
                           rawAsciiPreview.Contains("[ril.") ||
                           rawAsciiPreview.Contains("[gsm.") ||
                           rawAsciiPreview.Contains("rm: ") ||
                           rawAsciiPreview.Contains("Permission denied") ||
                           rawAsciiPreview.Contains("Operation not permitted") ||
                           rawAsciiPreview.Contains("records in") ||
                           rawAsciiPreview.Contains("records out") ||
                           rawAsciiPreview.Contains("E RILD") ||
                           rawAsciiPreview.Contains("D boot") ||
                           rawAsciiPreview.Contains(" D RIL") ||
                           rawAsciiPreview.Contains(" V RIL") ||
                           rawAsciiPreview.Contains(" I RIL") ||
                           rawAsciiPreview.Contains("OEM_HOOK_RAW", StringComparison.OrdinalIgnoreCase) ||
                           rawAsciiPreview.Contains("SAMSUNG AT Ril Command TOOL", StringComparison.OrdinalIgnoreCase) ||
                           rawAsciiPreview.Contains("Token AuthKey:", StringComparison.OrdinalIgnoreCase) ||
                           rawAsciiPreview.Contains("Enter AuthKey:", StringComparison.OrdinalIgnoreCase) ||
                           rawAsciiPreview.Contains("AuthKey : OK", StringComparison.OrdinalIgnoreCase) ||
                           rawAsciiPreview.Contains("AuthKey : FAIL", StringComparison.OrdinalIgnoreCase) ||
                           rawAsciiPreview.Contains("<<")
        );

        isUpperFilterPort = (pkt.TransferType == 4);
        bool isNonAtUsbProtocol = isAdbHeader || isAdbStream || isAdbRilIpc || isAdbInteractiveCmd || isAdbSync || isSahara || isFirehose || isFastboot || isSocketBridgeChannel;

        double atConf = chunk.Length > 0 
            ? PhoenixGSM.OmniTrace.Detection.ProtocolDetector.EvaluateSerialAt(chunk, PhoenixGSM.OmniTrace.Models.SensorType.Serial, PhoenixGSM.OmniTrace.Models.TransportType.SERIAL) 
            : 0.0;

        bool hasAdbOrPrintableKeywords = cleanLineTrimmed.Contains("Product", StringComparison.OrdinalIgnoreCase) ||
                                         cleanLineTrimmed.Contains("Token", StringComparison.OrdinalIgnoreCase) ||
                                         cleanLineTrimmed.Contains("AuthKey", StringComparison.OrdinalIgnoreCase) ||
                                         cleanLineTrimmed.Contains("****") ||
                                         cleanLineTrimmed.Contains("samsung", StringComparison.OrdinalIgnoreCase) ||
                                         cleanLineTrimmed.Contains("restarting in USB mode", StringComparison.OrdinalIgnoreCase) ||
                                         cleanLineTrimmed.Contains("<<") ||
                                         cleanLineTrimmed.StartsWith("shell:", StringComparison.OrdinalIgnoreCase) ||
                                         cleanLineTrimmed.StartsWith("/data/local/tmp", StringComparison.OrdinalIgnoreCase);

        bool isDeviceInAdb = (_isAdbSessionActive && !isUpperFilterPort) || isInteractiveShellActive || _isInsideFileSyncTransfer || isAdbHeader || isAdbStream || isAdbRilIpc || isAdbInteractiveCmd || hasAdbOrPrintableKeywords || isSocketBridgeChannel;

        double mtkConf = (chunk.Length > 0 && !isDeviceInAdb && !hasAdbOrPrintableKeywords)
            ? PhoenixGSM.OmniTrace.Decoders.MtkProtocolDecoder.EvaluateMtk(chunk)
            : 0.0;
        bool isMtk = mtkConf >= 0.70;

        // Absolute rule: Multi-byte buffer starting with 'P' (0x50) is NEVER MTK
        if (chunk.Length > 1 && (chunk[0] == 0x50 || chunk[0] == (byte)'P'))
        {
            isMtk = false;
            if (cleanLineTrimmed.StartsWith("Product Name", StringComparison.OrdinalIgnoreCase) || rawAsciiPreview.Contains("Product Name"))
            {
                isAdbStream = true;
            }
        }

        string cleanUpper = cleanLineTrimmed.ToUpperInvariant();
        bool isExplicitModemCmd = cleanUpper.StartsWith("AT+") || cleanUpper.StartsWith("AT*") ||
                                  cleanUpper.StartsWith("AT#") || cleanUpper.StartsWith("ATE") ||
                                  cleanUpper.StartsWith("ATI") || cleanUpper.StartsWith("ATD") ||
                                  cleanUpper.StartsWith("ATA") || cleanUpper.StartsWith("ATZ") ||
                                  cleanUpper.StartsWith("AT&") || cleanUpper == "AT" ||
                                  cleanUpper.StartsWith("+DEVCONINFO:") || cleanUpper.StartsWith("+CME ERROR:") ||
                                  cleanUpper.StartsWith("+CMS ERROR:") ||
                                  (isUpperFilterPort && (cleanUpper.StartsWith("+") || cleanUpper == "OK" || cleanUpper.StartsWith("ERROR")));

        bool isAt = !isMtk && !isNonAtUsbProtocol && !isAdbStream && !isAdbRilIpc && !isAdbInteractiveCmd && (
            isExplicitModemCmd ||
            (isUpperFilterPort && atConf >= 0.70 && !cleanLineTrimmed.Contains("]: [") && cleanLineTrimmed != "]")
        );

        KernelDiagLog($"PKT {dir} EP={epHex} TT={pkt.TransferType} len={pkt.ActualLength} cap={chunk.Length} isMtk={isMtk}({mtkConf:F2}) isAt={isAt} isUF={isUpperFilterPort} atConf={atConf:F2} ascii={isAsciiText} adb={isAdbHeader} sahara={isSahara} fh={isFirehose} fb={isFastboot} isShell={isInteractiveShellActive} | {Encoding.ASCII.GetString(chunk[..Math.Min(chunk.Length, 64)].Select(b => b >= 32 && b < 127 ? b : (byte)'.').ToArray())}");

        // Protocol Dispatching
        if (chunk.Length > 0 && isMtk)
        {
            HandleMtkPacket(pkt, chunk, dir, epHex, pDir, isUpperFilterPort, mtkConf, cleanLine);
        }
        else if (chunk.Length > 0 && isSocketBridgeChannel && !isAdbHeader && dir == "OUT")
        {
            HandleSocketBridgePacket(chunk, dir, epHex, cleanLine, cleanLineTrimmed);
        }
        else if (chunk.Length > 0 && isAppPrivilegeCmd && !isAdbHeader)
        {
            HandleAppPrivilegePacket(chunk, dir, epHex, cleanLine, cleanLineTrimmed);
        }
        else if (chunk.Length > 0 && (isAdbRilIpc || isAdbInteractiveCmd))
        {
            HandleAdbRilOrInteractivePacket(pkt, chunk, dir, epHex, pDir, isAdbRilIpc, cleanLine, cleanLineTrimmed);
        }
        else if (chunk.Length > 0 && isGetpropOutput)
        {
            HandleGetpropPacket(chunk, dir, epHex, cleanLine, cleanLineTrimmed);
        }
        else if (chunk.Length > 0 && isAdbStream)
        {
            HandleAdbStreamPacket(pkt, chunk, dir, epHex, pDir, isReadableInboundAdbResponse, cleanedInboundText, cleanLine);
        }
        else if (chunk.Length > 0 && isAt)
        {
            HandleAtOrModemPacket(pkt, chunk, dir, epHex, pDir, isAsciiText, atConf, cleanLine);
        }
        else
        {
            HandleAdbFrameOrRawUsbPacket(pkt, chunk, dir, epHex, pDir, isUpperFilterPort, isAdbHeader, isBinaryPayloadChunk, isAdbSyncToken, rawAsciiPreview, cleanLineTrimmed);
        }
    }
}
