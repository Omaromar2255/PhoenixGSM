using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using PhoenixGSM.MonitoringStudio.Models;
using PhoenixGSM.OmniTrace.Decoders;

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
        // Fast-drop periodic 15-byte binary telemetry / interrupt noise on EP 0x8D so it never floods the log or _adbParser
        if (dir == "IN" && epHex.Equals("0x8D", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        bool isAdbHeader = chunk.Length >= 24 && PhoenixGSM.UsbMonitor.Protocol.AdbProtocolParser.ValidateHeader(chunk, 0, out _, out _, out _, out _, out _);

        // 1. Check if packet is wrapped in ADB Shell Protocol v2 (5-byte header: [streamId:1B][len:4B]) used in modern PTY sessions
        byte[] effectiveChunk = chunk;
        bool isShellV2Packet = false;
        if (!isAdbHeader && !isUpperFilterPort && !_isInsideFileSyncTransfer &&
            ShellStreamReconstructor.TryUnpackShellV2Frames(chunk, out byte v2StreamId, out byte[] unpackedV2, out bool isV2ControlOnly, out _))
        {
            isShellV2Packet = true;
            _isAdbSessionActive = true;
            _isShellV2SessionActive = true;
            _isPtySessionActive = true;
            if (string.IsNullOrEmpty(_activeInteractiveShellCommand))
            {
                _activeInteractiveShellCommand = "shell,v2,pty:";
            }

            // Ignore pure terminal window resize (ID_WINDOW_SIZE_CHANGE = 5) or stdin-close control frames
            if (isV2ControlOnly)
            {
                return;
            }

            if (unpackedV2.Length > 0)
            {
                effectiveChunk = unpackedV2;
            }
        }

        bool isSahara = effectiveChunk.Length >= 8 && PhoenixGSM.OmniTrace.Decoders.QualcommEdlDecoder.EvaluateSahara(effectiveChunk) >= 0.8;
        bool isFirehose = effectiveChunk.Length >= 5 && (Encoding.ASCII.GetString(effectiveChunk[..Math.Min(effectiveChunk.Length, 64)]).StartsWith("<?xml", StringComparison.OrdinalIgnoreCase) || Encoding.ASCII.GetString(effectiveChunk[..Math.Min(effectiveChunk.Length, 64)]).Contains("<data>"));
        string rawAsciiPreview = effectiveChunk.Length > 0
            ? ShellStreamReconstructor.CleanTerminalOutput(Encoding.UTF8.GetString(effectiveChunk[..Math.Min(effectiveChunk.Length, 128)]))
            : "";

        string cleanLine = effectiveChunk.Length > 0
            ? ShellStreamReconstructor.CleanTerminalOutput(Encoding.UTF8.GetString(effectiveChunk)).Trim('\r', '\n', '\t', '\0', ' ')
            : "";
        string cleanLineTrimmed = cleanLine.Trim();

        // Compute non-printable ratio early (allowing PTY control bytes: ESC 0x1B, Backspace 0x08/0x7F, Ctrl-C/D/U/W)
        int nonPrintableCount = 0;
        bool hasElfMagic = false;
        for (int i = 0; i < effectiveChunk.Length; i++)
        {
            byte b = effectiveChunk[i];
            bool isPtyControlByte = b is 0x1B or 0x08 or 0x7F or 0x03 or 0x04 or 0x15 or 0x17;
            if (b < 0x20 && b != 9 && b != 10 && b != 13 && b != 0 && !isPtyControlByte) nonPrintableCount++;
            else if (b > 0x7E && b != 0x7F) nonPrintableCount++;
            if (i + 3 < effectiveChunk.Length && effectiveChunk[i] == 0x7F && effectiveChunk[i + 1] == 0x45 && effectiveChunk[i + 2] == 0x4C && effectiveChunk[i + 3] == 0x46)
            {
                hasElfMagic = true;
            }
        }
        double nonPrintableRatio = effectiveChunk.Length > 0 ? (double)nonPrintableCount / effectiveChunk.Length : 0.0;
        bool isBinaryPayloadChunk = hasElfMagic || (!isShellV2Packet && nonPrintableRatio > 0.20) ||
                                    cleanLineTrimmed.Contains(",33188DATA", StringComparison.Ordinal) ||
                                    cleanLineTrimmed.Contains(",33261DATA", StringComparison.Ordinal) ||
                                    rawAsciiPreview.Contains("ELF");

        // Detect ADB Sync start/stop transitions BEFORE evaluating interactive shell/PTY commands
        bool isSyncOpen = cleanLineTrimmed.Equals("sync:", StringComparison.OrdinalIgnoreCase) ||
                          rawAsciiPreview.StartsWith("sync:", StringComparison.OrdinalIgnoreCase);

        // Detect all Shell & PTY Open service headers (shell:, shell,v2,pty:, shell,v2,TERM=...,pty:, shell,pty:, pty:, exec:)
        string openSvcHdr = string.Empty;
        string openInnerCmd = string.Empty;
        bool openIsPty = false;
        bool openIsV2 = false;
        bool isShellOrPtyOpen = !isBinaryPayloadChunk &&
                                (ShellStreamReconstructor.IsShellOrPtyOpenService(cleanLineTrimmed, out openSvcHdr, out openInnerCmd, out openIsPty, out openIsV2) ||
                                 ShellStreamReconstructor.IsShellOrPtyOpenService(rawAsciiPreview, out openSvcHdr, out openInnerCmd, out openIsPty, out openIsV2));

        if (isAdbHeader || isSyncOpen || isShellOrPtyOpen || isShellV2Packet ||
            rawAsciiPreview.Contains("shell:") || rawAsciiPreview.Contains("shell,") ||
            rawAsciiPreview.Contains("pty:") || rawAsciiPreview.Contains("sync:"))
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
            _isPtySessionActive = false;
        }

        // Feed outbound non-shell packets into SmartFilePushArchiver BEFORE evaluating isAdbInteractiveCmd/isAdbStream
        if (dir == "OUT" && !isUpperFilterPort && !(isAdbHeader && chunk.Length == 24) &&
            !isShellOrPtyOpen && !isShellV2Packet)
        {
            _smartFileArchiver.ProcessOutboundSyncOrBulkChunk(chunk, dir, epHex, pkt.ActualLength, out _);
            _isInsideFileSyncTransfer = _smartFileArchiver.IsInsideTransfer;
        }

        // Track channel state transitions for explicit shell / PTY open commands
        if (!isBinaryPayloadChunk && !isAdbSyncToken && isShellOrPtyOpen)
        {
            string sCmd = !string.IsNullOrWhiteSpace(openInnerCmd)
                ? $"{openSvcHdr}{openInnerCmd}"
                : openSvcHdr;

            _activeInteractiveShellCommand = sCmd;
            _isPtySessionActive = openIsPty;
            _isShellV2SessionActive = openIsV2;
            _isInsideFileSyncTransfer = false;

            if (sCmd.Contains("/data/local/tmp/AT", StringComparison.OrdinalIgnoreCase) &&
                !sCmd.Contains("chmod ", StringComparison.OrdinalIgnoreCase))
            {
                _lastActiveAtBinaryCommand = _smartFileArchiver.GetActiveArtifactInstanceLabel("/data/local/tmp/AT");
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
                isShellOrPtyOpen || cleanLineTrimmed.StartsWith("<<") ||
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
                           (effectiveChunk.Length >= 4 && effectiveChunk.Length <= 64 && effectiveChunk[0] == 0x11 && effectiveChunk[1] == 0x63));

        bool isAsciiOrPtyText = effectiveChunk.Length > 0 && !isBinaryPayloadChunk &&
                                effectiveChunk.All(b => b == 0 || b == 9 || b == 10 || b == 13 ||
                                                        b == 0x1B || b == 0x08 || b == 0x7F || b == 0x03 || b == 0x04 || b == 0x15 || b == 0x17 ||
                                                        (b >= 32 && b < 127));

        bool isInteractiveShellActive = _isPtySessionActive ||
                                        !string.IsNullOrEmpty(_activeInteractiveShellCommand) ||
                                        !string.IsNullOrEmpty(_lastActiveAtBinaryCommand);

        // In PTY mode, a keystroke packet can be just "\r", "\n", Backspace (0x08/0x7F), or a single character!
        bool isPtyKeystrokePacket = _isPtySessionActive && dir == "OUT" && !isAdbHeader && !isAdbSync && !_isInsideFileSyncTransfer &&
                                    effectiveChunk.Length > 0 && isAsciiOrPtyText;

        // Clean Interactive / Shell / PTY Command Rule in OUT direction:
        bool isBareSyncPath = _isInsideFileSyncTransfer && cleanLineTrimmed.Equals("/data/local/tmp/AT", StringComparison.OrdinalIgnoreCase);
        bool isAdbInteractiveCmd = dir == "OUT" &&
                                   !isAdbHeader &&
                                   !isBinaryPayloadChunk &&
                                   !_isInsideFileSyncTransfer &&
                                   !isAdbSync &&
                                   !isBareSyncPath &&
                                   effectiveChunk.Length > 0 &&
                                   (cleanLineTrimmed.Length > 0 || isPtyKeystrokePacket) &&
                                   !cleanLineTrimmed.Equals("host::", StringComparison.OrdinalIgnoreCase) &&
                                   (isAsciiOrPtyText || isAdbRilIpc || isShellOrPtyOpen || isShellV2Packet ||
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

        // Check if incoming packet is a readable phone response in ADB / PTY mode
        string cleanedInboundText = CleanInboundPhoneResponse(effectiveChunk);
        bool isReadableInboundAdbResponse = dir == "IN" &&
                                            !isAdbHeader &&
                                            !isAdbSync &&
                                            !_isInsideFileSyncTransfer &&
                                            !isBinaryPayloadChunk &&
                                            isInteractiveShellActive &&
                                            cleanedInboundText.Length >= 1 &&
                                            !cleanedInboundText.StartsWith("STAT", StringComparison.Ordinal);

        bool isAdbStream = !isAdbRilIpc && !isAdbInteractiveCmd && !isBinaryPayloadChunk && (
                           isGetpropOutput ||
                           isReadableInboundAdbResponse ||
                           (dir == "IN" && isShellV2Packet) ||
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
                           isShellOrPtyOpen ||
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
        bool isNonAtUsbProtocol = isAdbHeader || isAdbStream || isAdbRilIpc || isAdbInteractiveCmd || isAdbSync || isSahara || isFirehose || isFastboot || isSocketBridgeChannel || isShellV2Packet;

        double atConf = effectiveChunk.Length > 0 
            ? PhoenixGSM.OmniTrace.Detection.ProtocolDetector.EvaluateSerialAt(effectiveChunk, PhoenixGSM.OmniTrace.Models.SensorType.Serial, PhoenixGSM.OmniTrace.Models.TransportType.SERIAL) 
            : 0.0;

        bool hasAdbOrPrintableKeywords = cleanLineTrimmed.Contains("Product", StringComparison.OrdinalIgnoreCase) ||
                                         cleanLineTrimmed.Contains("Token", StringComparison.OrdinalIgnoreCase) ||
                                         cleanLineTrimmed.Contains("AuthKey", StringComparison.OrdinalIgnoreCase) ||
                                         cleanLineTrimmed.Contains("****") ||
                                         cleanLineTrimmed.Contains("samsung", StringComparison.OrdinalIgnoreCase) ||
                                         cleanLineTrimmed.Contains("restarting in USB mode", StringComparison.OrdinalIgnoreCase) ||
                                         cleanLineTrimmed.Contains("<<") ||
                                         isShellOrPtyOpen ||
                                         cleanLineTrimmed.StartsWith("/data/local/tmp", StringComparison.OrdinalIgnoreCase);

        bool isDeviceInAdb = (_isAdbSessionActive && !isUpperFilterPort) || isInteractiveShellActive || _isInsideFileSyncTransfer || isAdbHeader || isAdbStream || isAdbRilIpc || isAdbInteractiveCmd || hasAdbOrPrintableKeywords || isSocketBridgeChannel;

        double mtkConf = (effectiveChunk.Length > 0 && !isDeviceInAdb && !hasAdbOrPrintableKeywords)
            ? PhoenixGSM.OmniTrace.Decoders.MtkProtocolDecoder.EvaluateMtk(effectiveChunk)
            : 0.0;
        bool isMtk = mtkConf >= 0.70;

        // Absolute rule: Multi-byte buffer starting with 'P' (0x50) is NEVER MTK
        if (effectiveChunk.Length > 1 && (effectiveChunk[0] == 0x50 || effectiveChunk[0] == (byte)'P'))
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

        // Protocol Dispatching
        if (effectiveChunk.Length > 0 && isMtk)
        {
            HandleMtkPacket(pkt, effectiveChunk, dir, epHex, pDir, isUpperFilterPort, mtkConf, cleanLine);
        }
        else if (effectiveChunk.Length > 0 && isSocketBridgeChannel && !isAdbHeader && dir == "OUT")
        {
            HandleSocketBridgePacket(effectiveChunk, dir, epHex, cleanLine, cleanLineTrimmed);
        }
        else if (effectiveChunk.Length > 0 && isAppPrivilegeCmd && !isAdbHeader)
        {
            HandleAppPrivilegePacket(effectiveChunk, dir, epHex, cleanLine, cleanLineTrimmed);
        }
        else if (effectiveChunk.Length > 0 && (isAdbRilIpc || isAdbInteractiveCmd))
        {
            HandleAdbRilOrInteractivePacket(pkt, effectiveChunk, dir, epHex, pDir, isAdbRilIpc, cleanLine, cleanLineTrimmed);
        }
        else if (effectiveChunk.Length > 0 && isGetpropOutput)
        {
            HandleGetpropPacket(effectiveChunk, dir, epHex, cleanLine, cleanLineTrimmed);
        }
        else if (effectiveChunk.Length > 0 && isAdbStream)
        {
            HandleAdbStreamPacket(pkt, effectiveChunk, dir, epHex, pDir, isReadableInboundAdbResponse, cleanedInboundText, cleanLine);
        }
        else if (effectiveChunk.Length > 0 && isAt)
        {
            HandleAtOrModemPacket(pkt, effectiveChunk, dir, epHex, pDir, isAsciiOrPtyText, atConf, cleanLine);
        }
        else
        {
            HandleAdbFrameOrRawUsbPacket(pkt, chunk, dir, epHex, pDir, isUpperFilterPort, isAdbHeader, isBinaryPayloadChunk, isAdbSyncToken, rawAsciiPreview, cleanLineTrimmed);
        }
    }
}
