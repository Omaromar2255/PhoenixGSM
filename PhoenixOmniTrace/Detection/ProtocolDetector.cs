using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.Detection;

/// <summary>
/// LAYER 7 — Protocol Detector
/// Confidence-based multi-candidate protocol analyzer.
/// Never assumes a single magic byte guarantees protocol. Returns a ranked list of candidates.
/// If decoding fails or no protocol matches with high confidence, Unknown is selected and data is preserved.
/// </summary>
public sealed class ProtocolDetector
{
    private static readonly uint[] AdbCommands =
    [
        AdbWirePacket.A_CNXN,
        AdbWirePacket.A_AUTH,
        AdbWirePacket.A_OPEN,
        AdbWirePacket.A_OKAY,
        AdbWirePacket.A_CLSE,
        AdbWirePacket.A_WRTE
    ];

    private static readonly string[] FastbootCommands =
    [
        "getvar:", "flash:", "erase:", "boot", "reboot", "continue", "download:",
        "oem ", "flashing ", "snapshot-update", "set_active:"
    ];

    private static readonly string[] FastbootResponses =
    [
        "OKAY", "FAIL", "DATA", "INFO"
    ];

    private static readonly string[] AdbSmartSocketPrefixes =
    [
        "host:", "host-serial:", "host-usb:", "host-local:", "shell:",
        "shell,v2:", "exec:", "sync:", "abb:", "abb_exec:", "track-devices"
    ];

    public List<ProtocolCandidate> DetectCandidates(ReadOnlySpan<byte> buffer, SensorType sensor, TransportType transport, PacketDirection direction)
    {
        var candidates = new List<ProtocolCandidate>();

        if (buffer.Length == 0)
        {
            candidates.Add(new ProtocolCandidate(KnownProtocol.Unknown, 0.01, "Empty payload"));
            return candidates;
        }

        // 1. Check ADB Wire Protocol
        double adbConfidence = EvaluateAdbWire(buffer);
        if (adbConfidence > 0)
        {
            candidates.Add(new ProtocolCandidate(KnownProtocol.ADB, adbConfidence, $"ADB Wire Framing (confidence={adbConfidence:P0})"));
        }

        // 2. Check ADB Smart Socket Protocol
        double smartSocketConfidence = EvaluateAdbSmartSocket(buffer);
        if (smartSocketConfidence > 0)
        {
            candidates.Add(new ProtocolCandidate(KnownProtocol.ADB, smartSocketConfidence, $"ADB Smart Socket Framing (confidence={smartSocketConfidence:P0})"));
        }

        // 2B. Check ADB Active Stream / RIL IPC / Sync Framing
        string previewAscii = Encoding.ASCII.GetString(buffer[..Math.Min(buffer.Length, 256)]);
        if (IsAdbRilIpc(buffer, previewAscii))
        {
            candidates.Add(new ProtocolCandidate(KnownProtocol.ADB, 0.98, "ADB RIL IPC Interactive Command (confidence=98%)"));
        }
        else if (IsAdbStreamOrAndroidSystemOutput(previewAscii))
        {
            candidates.Add(new ProtocolCandidate(KnownProtocol.ADB, 0.96, "ADB Stream / Android Shell Output (confidence=96%)"));
        }
        else if (IsAdbSyncPayload(buffer, previewAscii))
        {
            candidates.Add(new ProtocolCandidate(KnownProtocol.ADB, 0.95, "ADB Sync Protocol Framing (confidence=95%)"));
        }

        // 3. Check Fastboot Protocol
        double fbConfidence = EvaluateFastboot(buffer, direction);
        if (fbConfidence > 0)
        {
            candidates.Add(new ProtocolCandidate(KnownProtocol.Fastboot, fbConfidence, $"Fastboot ASCII Framing (confidence={fbConfidence:P0})"));
        }

        // 4. Check Qualcomm Firehose (XML)
        double firehoseConfidence = PhoenixGSM.OmniTrace.Decoders.QualcommEdlDecoder.EvaluateFirehose(buffer);
        if (firehoseConfidence > 0)
        {
            candidates.Add(new ProtocolCandidate(KnownProtocol.QualcommFirehose, firehoseConfidence, $"Qualcomm Firehose XML Framing (confidence={firehoseConfidence:P0})"));
        }

        // 5. Check Qualcomm Sahara (EDL Phase 1)
        double saharaConfidence = PhoenixGSM.OmniTrace.Decoders.QualcommEdlDecoder.EvaluateSahara(buffer);
        if (saharaConfidence > 0)
        {
            candidates.Add(new ProtocolCandidate(KnownProtocol.QualcommSahara, saharaConfidence, $"Qualcomm Sahara Packet (confidence={saharaConfidence:P0})"));
        }

        // 6. Check Qualcomm DIAG / HDLC
        double diagConfidence = EvaluateQualcommDiag(buffer);
        if (diagConfidence > 0)
        {
            candidates.Add(new ProtocolCandidate(KnownProtocol.QualcommDiag, diagConfidence, $"Qualcomm DIAG 0x7E Framing (confidence={diagConfidence:P0})"));
        }

        // 7. Check AT Commands
        double atConfidence = EvaluateSerialAt(buffer, sensor, transport);
        if (atConfidence > 0)
        {
            candidates.Add(new ProtocolCandidate(KnownProtocol.SerialAt, atConfidence, $"Serial AT Command Framing (confidence={atConfidence:P0})"));
        }

        // 8. Check MTK BROM / DA
        double mtkConfidence = PhoenixGSM.OmniTrace.Decoders.MtkProtocolDecoder.EvaluateMtk(buffer);
        if (mtkConfidence > 0)
        {
            candidates.Add(new ProtocolCandidate(KnownProtocol.MtkBrom, mtkConfidence, $"MTK Handshake Pattern (confidence={mtkConfidence:P0})"));
        }

        // 9. Check Unisoc / Spreadtrum (SPD) FDL
        double spdConfidence = PhoenixGSM.OmniTrace.Decoders.SpdFdlDecoder.EvaluateSpd(buffer);
        if (spdConfidence > 0)
        {
            candidates.Add(new ProtocolCandidate(KnownProtocol.SpreadtrumFdl, spdConfidence, $"Unisoc/SPD FDL Framing (confidence={spdConfidence:P0})"));
        }

        // 10. Check MTP / PTP Protocol
        double mtpConfidence = PhoenixGSM.OmniTrace.Decoders.MtpDecoder.EvaluateMtp(buffer);
        if (mtpConfidence > 0)
        {
            candidates.Add(new ProtocolCandidate(KnownProtocol.Mtp, mtpConfidence, $"MTP Container Framing (confidence={mtpConfidence:P0})"));
        }

        // 11. Samsung Odin
        double odinConfidence = EvaluateSamsungOdin(buffer);
        if (odinConfidence > 0)
        {
            candidates.Add(new ProtocolCandidate(KnownProtocol.SamsungOdin, odinConfidence, $"Samsung Odin / Thor Framing (confidence={odinConfidence:P0})"));
        }

        // 12. Check Apple iOS Protocols (usbmuxd, lockdown, recovery, dfu, ramdisk ssh, purple diag)
        PhoenixGSM.OmniTrace.Apple.Detection.AppleProtocolDetector.DetectCandidates(
            buffer, sensor, transport, direction, candidates);

        // 13. Check Host / Shell command execution or In-Process operation
        if (sensor == SensorType.Process)
        {
            if (direction == PacketDirection.INTERNAL)
            {
                candidates.Add(new ProtocolCandidate(KnownProtocol.InProcess, 1.0, "In-process direct servicing operation"));
            }
            else
            {
                candidates.Add(new ProtocolCandidate(KnownProtocol.HostCommand, 0.98, "Process execution sensor event"));
            }
        }
        else
        {
            double hostCmdConfidence = EvaluateHostCommand(buffer);
            if (hostCmdConfidence > 0)
            {
                candidates.Add(new ProtocolCandidate(KnownProtocol.HostCommand, hostCmdConfidence, $"Host CLI / Shell command execution (confidence={hostCmdConfidence:P0})"));
            }
        }

        // Always include Unknown fallback
        double bestKnown = candidates.Count > 0 ? candidates.Max(c => c.Confidence) : 0.0;
        double unknownConfidence = Math.Max(0.01, 1.0 - bestKnown);
        candidates.Add(new ProtocolCandidate(KnownProtocol.Unknown, unknownConfidence, "Fallback candidate for unclassified traffic"));

        // Sort descending by confidence
        candidates.Sort((a, b) => b.Confidence.CompareTo(a.Confidence));
        return candidates;
    }

    public ProtocolCandidate GetBestCandidate(ReadOnlySpan<byte> buffer, SensorType sensor, TransportType transport, PacketDirection direction)
    {
        var list = DetectCandidates(buffer, sensor, transport, direction);
        return list[0];
    }

    public static double EvaluateAdbWire(ReadOnlySpan<byte> buf)
    {
        if (buf.Length < 24) return 0.0;

        uint cmd = BitConverter.ToUInt32(buf[..4]);
        uint magic = BitConverter.ToUInt32(buf[20..24]);

        if ((cmd ^ 0xFFFFFFFF) == magic)
        {
            if (AdbCommands.Contains(cmd))
            {
                // Exact ADB Wire match
                uint dataLen = BitConverter.ToUInt32(buf[12..16]);
                if (buf.Length >= 24 + dataLen)
                {
                    // Check sum check
                    uint check = BitConverter.ToUInt32(buf[16..20]);
                    uint actualCheck = 0;
                    for (int i = 0; i < dataLen; i++) actualCheck += buf[24 + i];
                    if (check == actualCheck) return 0.99;
                }
                return 0.95;
            }
            return 0.60;
        }

        return 0.0;
    }

    private static double EvaluateAdbSmartSocket(ReadOnlySpan<byte> buf)
    {
        if (buf.Length < 5) return 0.0;

        // Check if first 4 bytes are hex chars
        bool isHex = true;
        for (int i = 0; i < 4; i++)
        {
            char c = (char)buf[i];
            if (!Uri.IsHexDigit(c))
            {
                isHex = false;
                break;
            }
        }

        if (!isHex) return 0.0;

        try
        {
            string hexStr = Encoding.ASCII.GetString(buf[..4]);
            int declaredLen = Convert.ToInt32(hexStr, 16);
            if (declaredLen <= 0 || declaredLen > 65536) return 0.0;

            string payloadPreview = Encoding.ASCII.GetString(buf[4..Math.Min(buf.Length, 4 + declaredLen)]);
            foreach (var prefix in AdbSmartSocketPrefixes)
            {
                if (payloadPreview.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    return 0.96;
                }
            }

            if (payloadPreview.StartsWith("OKAY", StringComparison.Ordinal) || payloadPreview.StartsWith("FAIL", StringComparison.Ordinal))
            {
                return 0.92;
            }

            return 0.65;
        }
        catch
        {
            return 0.0;
        }
    }

    public static double EvaluateFastboot(ReadOnlySpan<byte> buf, PacketDirection direction)
    {
        if (buf.Length < 4) return 0.0;

        string ascii = Encoding.ASCII.GetString(buf[..Math.Min(buf.Length, 64)]);

        // Disqualify if this matches ADB sync, ADB stream, or ADB RIL-IPC
        if (IsAdbStreamOrAndroidSystemOutput(ascii) || IsAdbSyncPayload(buf, ascii) || IsAdbRilIpc(buf, ascii))
        {
            return 0.0;
        }

        if (direction == PacketDirection.HOST_TO_DEVICE)
        {
            foreach (var cmd in FastbootCommands)
            {
                if (ascii.StartsWith(cmd, StringComparison.OrdinalIgnoreCase))
                {
                    return 0.95;
                }
            }
        }
        else
        {
            // Do not classify generic OKAY/DATA/FAIL responses as Fastboot unless they match Fastboot structure
            // and are NOT part of ADB sync (DATA, OKAY, STAT, DONE, FAIL)
            if (ascii.StartsWith("DATA", StringComparison.Ordinal))
            {
                // In Fastboot, DATA is followed by 8 hex digits, e.g. DATA00000800
                if (ascii.Length >= 12 && Uri.IsHexDigit(ascii[4]) && Uri.IsHexDigit(ascii[5]))
                    return 0.95;
                return 0.0; // In ADB sync, DATA is followed by binary 4-byte length
            }

            if (ascii.StartsWith("OKAY", StringComparison.Ordinal) ||
                ascii.StartsWith("FAIL", StringComparison.Ordinal) ||
                ascii.StartsWith("INFO", StringComparison.Ordinal))
            {
                // If it is 4 bytes exactly or followed by binary, it is ADB sync / binary token, not Fastboot ASCII
                if (buf.Length == 4 || (buf.Length > 4 && buf[4] < 0x20 && buf[4] != 0))
                    return 0.0;

                return 0.80;
            }
        }

        return 0.0;
    }

    public static bool IsAdbSyncPayload(ReadOnlySpan<byte> buf, string ascii)
    {
        if (buf.Length < 4) return false;
        if (ascii.StartsWith("DATA", StringComparison.Ordinal) ||
            ascii.StartsWith("STAT", StringComparison.Ordinal) ||
            ascii.StartsWith("SEND", StringComparison.Ordinal) ||
            ascii.StartsWith("RECV", StringComparison.Ordinal) ||
            ascii.StartsWith("DONE", StringComparison.Ordinal) ||
            ascii.StartsWith("DENT", StringComparison.Ordinal) ||
            ascii.StartsWith("LIST", StringComparison.Ordinal))
        {
            return true;
        }
        return false;
    }

    public static bool IsAdbStreamOrAndroidSystemOutput(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return false;

        // Android property outputs: [ro., [init.svc., [persist., [dalvik., [sys., [ril., [gsm.
        if (text.Contains("[ro.") || text.Contains("[init.svc.") || text.Contains("[persist.") ||
            text.Contains("[dalvik.") || text.Contains("[sys.") || text.Contains("[ril.") || text.Contains("[gsm."))
            return true;

        if (text.StartsWith("[") && text.Contains("]: ["))
            return true;

        // Linux shell error messages & dd records
        if (text.Contains("rm: ") || text.Contains("Permission denied") ||
            text.Contains("Operation not permitted") || text.Contains("records in") || text.Contains("records out"))
            return true;

        // Android logcat outputs
        if (text.Contains("E RILD") || text.Contains("D boot") || text.Contains("Result: Parcel(") ||
            text.Contains(" D RIL") || text.Contains(" V RIL") || text.Contains(" I RIL") || text.Contains("OEM_HOOK_RAW"))
            return true;

        // Samsung AT Ril Command TOOL interface & AuthKey prompts
        if (text.Contains("SAMSUNG AT Ril Command TOOL", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("Token AuthKey:", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("Enter AuthKey:", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("AuthKey : OK", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("AuthKey : FAIL", StringComparison.OrdinalIgnoreCase))
            return true;

        return false;
    }

    public static bool IsAdbRilIpc(ReadOnlySpan<byte> buf, string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return false;
        string trimmed = text.Trim();

        if (trimmed.StartsWith("1163000501", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("06090004", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("07170004", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("1163005F", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("116300", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("AuthKey", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (buf.Length >= 4 && buf[0] == 0x11 && buf[1] == 0x63)
        {
            return true;
        }

        return false;
    }

    private static double EvaluateQualcommFirehose(ReadOnlySpan<byte> buf)
    {
        if (buf.Length < 14) return 0.0;
        string text = Encoding.UTF8.GetString(buf[..Math.Min(buf.Length, 256)]);
        if (text.Contains("<?xml", StringComparison.OrdinalIgnoreCase) &&
           (text.Contains("<data", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("<configure", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("<program", StringComparison.OrdinalIgnoreCase)))
        {
            return 0.98;
        }
        return 0.0;
    }

    private static double EvaluateQualcommSahara(ReadOnlySpan<byte> buf)
    {
        if (buf.Length < 8) return 0.0;

        uint cmd = BitConverter.ToUInt32(buf[..4]);
        uint length = BitConverter.ToUInt32(buf[4..8]);

        // Sahara commands: 0x01=Hello, 0x02=HelloResp, 0x03=ReadData, 0x04=End, 0x05=Done, 0x07=MemoryDebug
        if (cmd is >= 0x01 and <= 0x08 && length is >= 8 and <= 1024)
        {
            if (cmd == 0x01 && length == 48) return 0.96; // Sahara hello is 48 bytes
            return 0.85;
        }

        return 0.0;
    }

    private static double EvaluateQualcommDiag(ReadOnlySpan<byte> buf)
    {
        if (buf.Length < 3 || buf.Length > 4096) return 0.0;

        // Framing 0x7E at boundaries:
        // If buffer is larger than 64 bytes, it MUST start AND end with 0x7E to prevent
        // uploaded files (e.g. ADB push payloads) from being misclassified as QualcommDiag frames.
        if (buf.Length > 64)
        {
            if (buf[0] == 0x7E && buf[^1] == 0x7E)
            {
                return 0.90;
            }
            return 0.0;
        }

        if (buf[0] == 0x7E && buf[^1] == 0x7E)
        {
            return 0.90;
        }
        if (buf[0] == 0x7E || buf[^1] == 0x7E)
        {
            return 0.65;
        }

        return 0.0;
    }

    public static double EvaluateSerialAt(ReadOnlySpan<byte> buf, SensorType? sensor = null, TransportType transport = TransportType.UNKNOWN)
    {
        if (buf.Length == 0) return 0.0;

        // Disqualify immediately if this matches ADB active stream, Android system output, or ADB RIL-IPC
        string checkAscii = Encoding.ASCII.GetString(buf[..Math.Min(buf.Length, 2048)]);
        if (IsAdbStreamOrAndroidSystemOutput(checkAscii) || IsAdbRilIpc(buf, checkAscii))
        {
            return 0.0;
        }

        // Skip leading whitespace / CR / LF / null bytes
        int start = 0;
        while (start < buf.Length && (buf[start] == '\r' || buf[start] == '\n' || buf[start] == ' ' || buf[start] == '\t' || buf[start] == 0))
        {
            start++;
        }
        if (start >= buf.Length) return 0.0;

        ReadOnlySpan<byte> trimmed = buf.Slice(start, Math.Min(buf.Length - start, 128));
        if (trimmed.Length == 0) return 0.0;

        string str = Encoding.ASCII.GetString(trimmed);

        // Check vendor-extended AT commands (AT+, AT^, AT%, AT$, AT*, AT#)
        if (str.StartsWith("AT^", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("AT$", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("AT%", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("AT*", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("AT#", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("AT+", StringComparison.OrdinalIgnoreCase))
        {
            return 0.98;
        }

        // Check general AT commands and repeat (AT, A/)
        if (str.StartsWith("AT", StringComparison.OrdinalIgnoreCase))
        {
            return 0.95;
        }
        if (str.StartsWith("A/", StringComparison.OrdinalIgnoreCase))
        {
            return 0.90;
        }
        if (str == "A" && (sensor == SensorType.Serial || transport == TransportType.SERIAL))
        {
            return 0.70;
        }
        if (trimmed.Length >= 3 && trimmed[0] == '+' && trimmed[1] == '+' && trimmed[2] == '+')
        {
            return 0.90;
        }

        // Huawei / Honor Unsolicited Indications & Status Notifications
        if (str.StartsWith("^BOOT", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("^RSSI", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("^MODE", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("^DSFLOWRPT", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("^HCSQ", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("^SYSINFO", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("^SETPORT", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("^CARDLOCK", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("^DATALOCK", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("^NDISSTATQRY", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("^SIMST", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("^SRVST", StringComparison.OrdinalIgnoreCase))
        {
            return 0.96;
        }

        // Multi-line script / File staging inspection (e.g. temp files containing AT scripts or comments)
        string previewText = Encoding.ASCII.GetString(buf[..Math.Min(buf.Length, 2048)]);
        if (previewText.Contains("AT+", StringComparison.OrdinalIgnoreCase) ||
            previewText.Contains("AT^", StringComparison.OrdinalIgnoreCase) ||
            previewText.Contains("AT%", StringComparison.OrdinalIgnoreCase) ||
            previewText.Contains("AT$", StringComparison.OrdinalIgnoreCase) ||
            previewText.Contains("AT*", StringComparison.OrdinalIgnoreCase) ||
            previewText.Contains("AT#", StringComparison.OrdinalIgnoreCase) ||
            previewText.Contains("AT&", StringComparison.OrdinalIgnoreCase) ||
            previewText.Contains("^BOOT", StringComparison.OrdinalIgnoreCase) ||
            previewText.Contains("^RSSI", StringComparison.OrdinalIgnoreCase) ||
            previewText.Contains("^MODE", StringComparison.OrdinalIgnoreCase) ||
            previewText.Contains("^DSFLOWRPT", StringComparison.OrdinalIgnoreCase) ||
            previewText.Contains("^HCSQ", StringComparison.OrdinalIgnoreCase) ||
            previewText.Contains("^SYSINFO", StringComparison.OrdinalIgnoreCase) ||
            previewText.Contains("^SETPORT", StringComparison.OrdinalIgnoreCase) ||
            previewText.Contains("^CARDLOCK", StringComparison.OrdinalIgnoreCase) ||
            previewText.Contains("^DATALOCK", StringComparison.OrdinalIgnoreCase) ||
            previewText.Contains("\nAT", StringComparison.OrdinalIgnoreCase) ||
            previewText.Contains("\rAT", StringComparison.OrdinalIgnoreCase))
        {
            return 0.95;
        }

        // Check UTF-16 encoded buffers
        if (buf.Length >= 4 && buf[1] == 0 && buf[3] == 0 && buf[0] != 0 && buf[2] != 0)
        {
            string u16Text = Encoding.Unicode.GetString(buf[..Math.Min(buf.Length, 2048)]);
            if (u16Text.Contains("AT+", StringComparison.OrdinalIgnoreCase) ||
                u16Text.Contains("AT^", StringComparison.OrdinalIgnoreCase) ||
                u16Text.Contains("AT%", StringComparison.OrdinalIgnoreCase) ||
                u16Text.Contains("AT&", StringComparison.OrdinalIgnoreCase) ||
                u16Text.Contains("\nAT", StringComparison.OrdinalIgnoreCase) ||
                u16Text.Contains("\rAT", StringComparison.OrdinalIgnoreCase))
            {
                return 0.95;
            }
        }

        // Check standard AT modem result codes
        if (str.StartsWith("OK", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("ERROR", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("+CME ERROR", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("CME ERROR", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("+CMS ERROR", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("CMS ERROR", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("RING", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("NO CARRIER", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("CONNECT", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("BUSY", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("NO DIALTONE", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("NO ANSWER", StringComparison.OrdinalIgnoreCase))
        {
            return 0.92;
        }

        // Serial transport prompt or pacing markers (+ or >)
        if ((sensor == SensorType.Serial || transport == TransportType.SERIAL) &&
            (trimmed.Length == 1 && (trimmed[0] == '+' || trimmed[0] == '>')))
        {
            return 0.90;
        }

        // Modem unsolicited and operational indications
        if (str.StartsWith("RDY", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("NORMAL POWER DOWN", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("UNDER_VOLTAGE", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("SIM PIN", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("SIM PUK", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("READY", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("CALL READY", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("SMS READY", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("SMS DONE", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("PB DONE", StringComparison.OrdinalIgnoreCase))
        {
            return 0.92;
        }

        // Numeric result codes in ATV0 mode: 0 (OK), 1 (CONNECT), 2 (RING), 3 (NO CARRIER), 4 (ERROR), 6 (NO DIALTONE), 7 (BUSY), 8 (NO ANSWER)
        if (trimmed.Length >= 1 && (trimmed[0] == '0' || trimmed[0] == '1' || trimmed[0] == '2' || trimmed[0] == '3' || trimmed[0] == '4' || trimmed[0] == '6' || trimmed[0] == '7' || trimmed[0] == '8'))
        {
            if (trimmed.Length == 1 || trimmed[1] == '\r' || trimmed[1] == '\n' || trimmed[1] == ' ')
            {
                return 0.90;
            }
        }

        // Check extended AT response prefix: +TAG: or +TAG or vendor prefixes: ^TAG, %TAG, $TAG, #TAG, *TAG, @TAG
        if (trimmed.Length >= 2 && (trimmed[0] == '+' || trimmed[0] == '^' || trimmed[0] == '%' || trimmed[0] == '$' || trimmed[0] == '#' || trimmed[0] == '*' || trimmed[0] == '@'))
        {
            if (char.IsLetter((char)trimmed[1]) || (trimmed.Length >= 3 && char.IsLetter((char)trimmed[2])))
            {
                return 0.92;
            }
        }

        // SMS prompt: > or > [space]
        if (trimmed[0] == '>' && (trimmed.Length == 1 || trimmed[1] == ' ' || trimmed[1] == '\r' || trimmed[1] == '\n'))
        {
            return 0.90;
        }

        // Check numeric IMEI / IMSI / Serial numbers (e.g. 14-16 digits IMEI or 15 digits IMSI returned by AT+CGSN / AT+CIMI)
        if (trimmed.Length >= 14)
        {
            bool allDigits = true;
            int digitCount = 0;
            for (int i = 0; i < trimmed.Length && trimmed[i] != '\r' && trimmed[i] != '\n' && trimmed[i] != ' '; i++)
            {
                if (!char.IsDigit((char)trimmed[i])) { allDigits = false; break; }
                digitCount++;
            }
            if (allDigits && digitCount is >= 14 and <= 16)
            {
                return 0.92;
            }
        }

        // Check if substring contains standard modem tokens (OK, ERROR, CME/CMS)
        if (str.Contains("OK\r", StringComparison.OrdinalIgnoreCase) ||
            str.Contains("OK\n", StringComparison.OrdinalIgnoreCase) ||
            str.EndsWith("OK", StringComparison.OrdinalIgnoreCase) ||
            str.Contains("ERROR\r", StringComparison.OrdinalIgnoreCase) ||
            str.Contains("ERROR\n", StringComparison.OrdinalIgnoreCase) ||
            str.EndsWith("ERROR", StringComparison.OrdinalIgnoreCase) ||
            str.Contains("+CME ERROR", StringComparison.OrdinalIgnoreCase) ||
            str.Contains("+CMS ERROR", StringComparison.OrdinalIgnoreCase))
        {
            return 0.88;
        }

        // Known manufacturer / chip responses on serial modem ports
        if (str.StartsWith("SAMSUNG", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("QUALCOMM", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("MEDIATEK", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("SPREADTRUM", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("HUAWEI", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("HONOR", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("QUECTEL", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("SIMCOM", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("FIBOCOM", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("TELIT", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("ZTE", StringComparison.OrdinalIgnoreCase))
        {
            return 0.92;
        }

        // Honor / Huawei / Samsung model number patterns (e.g. ANY-LX1, WKG-LX9, SM-G998B)
        if (str.StartsWith("ANY-", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("WKG-", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("H60-", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("LLD-", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("STK-", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("POT-", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("PRA-", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("FIG-", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("JSN-", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("VOG-", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("ELE-", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("YAL-", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("NOH-", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("NEN-", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("SM-", StringComparison.OrdinalIgnoreCase))
        {
            return 0.94;
        }

        // Device identification metadata headers
        if (str.StartsWith("Model:", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("Manufacturer:", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("Revision:", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("IMEI:", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("MEID:", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("SN:", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("Serial:", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("Baseband:", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("Firmware:", StringComparison.OrdinalIgnoreCase))
        {
            return 0.94;
        }

        // If the transport or sensor is explicitly Serial / Modem, any clean printable ASCII line is SerialAt
        if (sensor == SensorType.Serial || transport == TransportType.SERIAL)
        {
            bool isPrintableAscii = true;
            for (int i = 0; i < trimmed.Length && trimmed[i] != '\r' && trimmed[i] != '\n'; i++)
            {
                if (trimmed[i] < 32 || trimmed[i] > 126)
                {
                    isPrintableAscii = false;
                    break;
                }
            }
            if (isPrintableAscii && trimmed.Length >= 2)
            {
                return 0.88;
            }
        }

        // Clean ASCII line with CRLF or LF terminators (typical modem responses)
        bool hasLineTerminator = buf.Contains((byte)'\r') || buf.Contains((byte)'\n');
        if (hasLineTerminator)
        {
            bool isPrintableAscii = true;
            for (int i = 0; i < trimmed.Length && trimmed[i] != '\r' && trimmed[i] != '\n'; i++)
            {
                if (trimmed[i] < 32 || trimmed[i] > 126)
                {
                    isPrintableAscii = false;
                    break;
                }
            }
            if (isPrintableAscii && trimmed.Length >= 2)
            {
                return 0.85;
            }
        }

        return 0.0;
    }


    private static double EvaluateMtk(ReadOnlySpan<byte> buf)
    {
        if (buf.Length < 2) return 0.0;

        // BROM start sequences
        if (buf[0] == 0xA0 && buf[1] == 0x0A) return 0.90;
        if (buf[0] == 0xD0 || buf[0] == 0xD1 || buf[0] == 0xD2) return 0.70;

        return 0.0;
    }

    private static double EvaluateSamsungOdin(ReadOnlySpan<byte> buf)
    {
        if (buf.Length < 4) return 0.0;
        string ascii = Encoding.ASCII.GetString(buf[..Math.Min(buf.Length, 32)]);
        if (ascii.StartsWith("ODIN", StringComparison.Ordinal) ||
            ascii.StartsWith("LOKE", StringComparison.Ordinal) ||
            ascii.StartsWith("PIT", StringComparison.Ordinal))
        {
            return 0.95;
        }
        return 0.0;
    }

    private static double EvaluateHostCommand(ReadOnlySpan<byte> buf)
    {
        if (buf.Length < 2) return 0.0;
        string text = Encoding.ASCII.GetString(buf[..Math.Min(buf.Length, 128)]);
        string trimmed = text.TrimStart();
        if (trimmed.StartsWith("cmd.exe", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("powershell", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("pwsh", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("sc.exe", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("net.exe", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("reg.exe", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("curl", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("certutil", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("tar.exe", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("attrib", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("takeown", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("icacls", StringComparison.OrdinalIgnoreCase))
        {
            return 0.90;
        }

        return 0.0;
    }
}
