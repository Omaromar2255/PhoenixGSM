using System;
using System.Text;

namespace PhoenixOmniTrace.L24_SourceSentinel.Decoders;

public static class RawPayloadClassifier
{
    public static (string Category, string DecodedText) Classify(
        string apiName, 
        string targetResource, 
        uint ioctlCode, 
        ReadOnlySpan<byte> payload)
    {
        // 1. فحص إعدادات تهيئة المنفذ قبل إرسال الأمر عبر IOCTL
        if (apiName.Equals("NtDeviceIoControlFile", StringComparison.OrdinalIgnoreCase) || ioctlCode != 0)
        {
            if (SerialIoControlDecoder.IsKnownIoControl(ioctlCode))
            {
                var (cat, desc) = SerialIoControlDecoder.Decode(ioctlCode, payload, targetResource);
                return (cat, desc);
            }
        }

        if (payload.IsEmpty)
        {
            if (ioctlCode != 0)
                return ("Control Operation", $"استدعاء {apiName} على الهدف [{targetResource}] (IOCTL: 0x{ioctlCode:X8})");
            return ("Control Operation", $"استدعاء {apiName} على الهدف [{targetResource}]");
        }

        // 2. كشف مصافحة وأوامر MediaTek BROM / Preloader / XFlash
        if ((payload.Length == 1 && (payload[0] == 0xA0 || payload[0] == 0x0A || payload[0] == 0x50 || payload[0] == 0x05 || payload[0] == 0x5F || payload[0] == 0xF5 || payload[0] == 0xAF || payload[0] == 0xFA)) ||
            (payload.Length >= 4 && payload[0] == 0xA0 && payload[1] == 0x0A && payload[2] == 0x50 && payload[3] == 0x05) ||
            (payload.Length >= 4 && payload[0] == 0x5F && payload[1] == 0xF5 && payload[2] == 0xAF && payload[3] == 0xFA))
        {
            return ("MTK BROM Handshake", $"مصافحة معالج MediaTek BROM المباشرة ({Convert.ToHexString(payload)})");
        }

        if (payload.Length >= 12 && payload[0] == 0xEF && payload[1] == 0xEE && payload[2] == 0xEE && payload[3] == 0xFE)
        {
            int cmdId = BitConverter.ToInt32(payload.Slice(4, 4));
            int len = BitConverter.ToInt32(payload.Slice(8, 4));
            return ("MTK XFlash / DA Binary Packet", $"حزمة أمر MediaTek XFlash/DA2 ثنائية [CmdID: 0x{cmdId:X4}, الطول: {len} بايت]");
        }

        // فحص أوامر MTK BROM (فقط عندما لا تكون السلسلة نصية ASCII عادية)
        bool isTwoByteAscii = payload.Length > 1 && payload[0] is >= 0x20 and <= 0x7E && payload[1] is >= 0x20 and <= 0x7E;
        if (payload.Length >= 1 && !isTwoByteAscii)
        {
            byte cmd = payload[0];
            if (cmd == 0xD0) return ("MTK BROM Command", "أمر MTK BROM: قراءة إعدادات الحماية (Get Target Config: 0xD0)");
            if (cmd == 0xD1 || cmd == 0xC7) return ("MTK BROM Command", $"أمر MTK BROM: إرسال الـ Download Agent (Send DA: 0x{cmd:X2})");
            if (cmd == 0xD2 || cmd == 0xD5) return ("MTK BROM Command", $"أمر MTK BROM: القفز وتنفيذ DA بالذاكرة (Jump DA: 0x{cmd:X2})");
            if (cmd == 0xD4) return ("MTK BROM Command", "أمر MTK BROM: قراءة كود المعالج أو سجل 32-بت (Get HW Code / Read32: 0xD4)");
            if (cmd == 0xD6) return ("MTK BROM Command", "أمر MTK BROM: كتابة سجل 32-بت (Write32: 0xD6)");
            if (cmd == 0xD7) return ("MTK BROM Command", "أمر MTK BROM: إرسال الـ Download Agent (Send DA: 0xD7)");
            if (cmd == 0xD8) return ("MTK BROM Command", "أمر MTK BROM: القفز وتنفيذ DA بالذاكرة (Jump DA: 0xD8)");
            if (cmd == 0xDA) return ("MTK BROM Command", "أمر MTK BROM: قراءة سجل 16-بت / MEID (Read16: 0xDA)");
            if (cmd == 0xDC) return ("MTK BROM Command", "أمر MTK BROM: مصادقة الحماية SLA/DAA أو قراءة SOC_ID (0xDC)");
            if (cmd == 0xC1) return ("MTK BROM Command", "أمر MTK BROM: قراءة عنوان ذاكرة 32-بت مباشرة (CMD_READ32: 0xC1)");
            if (cmd == 0xC2) return ("MTK BROM Command", "أمر MTK BROM: كتابة عنوان ذاكرة 32-بت لتعطيل الحماية (CMD_WRITE32: 0xC2)");
        }

        // 3. كشف أوامر Qualcomm Sahara
        if (payload.Length >= 8 && !isTwoByteAscii)
        {
            uint saharaCmd = BitConverter.ToUInt32(payload[..4]);
            if (saharaCmd == 0x01) return ("Qualcomm Sahara", "بروتوكول Qualcomm Sahara: إشارة Hello (Command 0x01)");
            if (saharaCmd == 0x02) return ("Qualcomm Sahara", "بروتوكول Qualcomm Sahara: استجابة Hello Response (Command 0x02)");
            if (saharaCmd == 0x03) return ("Qualcomm Sahara", "بروتوكول Qualcomm Sahara: طلب قراءة بيانات (Read Data 0x03)");
            if (saharaCmd == 0x04) return ("Qualcomm Sahara", "بروتوكول Qualcomm Sahara: انتهاء التحميل (End Transfer 0x04)");
            if (saharaCmd == 0x07) return ("Qualcomm Sahara", "بروتوكول Qualcomm Sahara: أمر إعادة التشغيل (Reset 0x07)");
            if (saharaCmd == 0x08) return ("Qualcomm Sahara", "بروتوكول Qualcomm Sahara: وضع تفريغ الذاكرة (Memory Debug 0x08)");
        }

        // 4. كشف أوامر المودم القياسية والمصنعية (AT Commands & RIL IPC)
        string ascii = TryExtractPrintableAscii(payload);
        if (!string.IsNullOrWhiteSpace(ascii))
        {
            string trimmed = ascii.Trim();
            if (trimmed.StartsWith("AT", StringComparison.OrdinalIgnoreCase) || 
                trimmed.Contains("AT+", StringComparison.OrdinalIgnoreCase) ||
                trimmed.StartsWith("ATE", StringComparison.OrdinalIgnoreCase) ||
                trimmed.StartsWith("ATI", StringComparison.OrdinalIgnoreCase) ||
                trimmed.StartsWith("ATZ", StringComparison.OrdinalIgnoreCase))
            {
                return ("Modem AT Command", trimmed);
            }

            if (trimmed.StartsWith("+") || trimmed.Equals("OK", StringComparison.OrdinalIgnoreCase) ||
                trimmed.StartsWith("ERROR", StringComparison.OrdinalIgnoreCase))
            {
                return ("Modem Phone Response", trimmed);
            }

            if (trimmed.StartsWith("060100", StringComparison.OrdinalIgnoreCase) ||
                trimmed.StartsWith("120D00", StringComparison.OrdinalIgnoreCase) ||
                trimmed.StartsWith("514200", StringComparison.OrdinalIgnoreCase) ||
                trimmed.StartsWith("516400", StringComparison.OrdinalIgnoreCase))
            {
                return ("ADB RIL / AT IPC Command", trimmed);
            }

            // 5. كشف بروتوكول Qualcomm Firehose XML
            if (trimmed.Contains("<?xml", StringComparison.OrdinalIgnoreCase) || 
                (trimmed.Contains("<data>", StringComparison.OrdinalIgnoreCase) && trimmed.Contains("<program", StringComparison.OrdinalIgnoreCase)))
            {
                return ("Qualcomm Firehose XML", trimmed);
            }

            // 6. كشف أوامر الأنابيب والـ Shell والـ ADB المباشرة
            if (targetResource.Contains("Pipe", StringComparison.OrdinalIgnoreCase) || 
                trimmed.StartsWith("host:", StringComparison.OrdinalIgnoreCase) ||
                trimmed.StartsWith("shell:", StringComparison.OrdinalIgnoreCase) ||
                trimmed.StartsWith("sync:", StringComparison.OrdinalIgnoreCase) ||
                trimmed.StartsWith("usb:", StringComparison.OrdinalIgnoreCase) ||
                trimmed.StartsWith("reboot:", StringComparison.OrdinalIgnoreCase) ||
                trimmed.StartsWith("remount:", StringComparison.OrdinalIgnoreCase))
            {
                return ("Pipe / Shell Command", trimmed);
            }

            // 7. كشف أوامر بروتوكول Samsung Odin
            if (trimmed.StartsWith("ODIN", StringComparison.OrdinalIgnoreCase) || 
                trimmed.StartsWith("LOKE", StringComparison.OrdinalIgnoreCase) ||
                trimmed.Contains(".pit", StringComparison.OrdinalIgnoreCase))
            {
                return ("Samsung Odin Protocol", trimmed);
            }
        }

        // 8. كشف بروتوكول Spreadtrum / Unisoc BSL
        if (payload.Length >= 4 && payload[0] == 0x7E && payload[^1] == 0x7E)
        {
            byte bslType = payload[1];
            string bslDesc = bslType switch
            {
                0x00 => "BSL_CMD_CONNECT (مصافحة المعالج)",
                0x01 => "BSL_CMD_START_DATA (بدء إرسال البيانات)",
                0x02 => "BSL_CMD_MIDST_DATA (نقل حزم الفلاش)",
                0x03 => "BSL_CMD_END_DATA (إنهاء النقل)",
                0x04 => "BSL_CMD_EXEC_DATA (تنفيذ بالرام)",
                0x05 => "BSL_CMD_NORMAL_RESET (إعادة تشغيل)",
                _ => $"BSL_CMD 0x{bslType:X2}"
            };
            return ("Unisoc / SPD BSL Frame", $"إطار معالج Unisoc/Spreadtrum BSL: {bslDesc}");
        }

        // 9. كشف إطارات Qualcomm DIAG الثنائية (المؤطرة بـ 0x7E)
        if (payload.Length >= 3 && payload[^1] == 0x7E)
        {
            byte diagCmd = payload[0];
            if (diagCmd == 0x4B) return ("Qualcomm DIAG Packet", $"حزمة Qualcomm Diag Subsys (0x4B): {Convert.ToHexString(payload.Slice(0, Math.Min(payload.Length, 32)))}");
            if (diagCmd == 0x1D) return ("Qualcomm DIAG Packet", "استعلام إصدار كوالكوم DIAG (Version Request 0x1D)");
            if (diagCmd == 0x26 || diagCmd == 0x27) return ("Qualcomm DIAG Packet", "طلب كتابة/قراءة NV-RAM عبر DIAG");
            if (diagCmd == 0x29) return ("Qualcomm DIAG Packet", "أمر تحكم بالوضع (Mode Control / Reset 0x29)");
        }

        return ("Raw Binary / I/O Stream", string.IsNullOrWhiteSpace(ascii) ? $"[Binary Data: {payload.Length} Bytes] {Convert.ToHexString(payload.Slice(0, Math.Min(payload.Length, 32)))}" : ascii);
    }

    public static string TryExtractPrintableAscii(ReadOnlySpan<byte> buffer)
    {
        int limit = Math.Min(buffer.Length, 512);
        var sb = new StringBuilder(limit);
        int printableCount = 0;

        for (int i = 0; i < limit; i++)
        {
            byte b = buffer[i];
            if ((b >= 32 && b <= 126) || b == '\r' || b == '\n' || b == '\t')
            {
                sb.Append((char)b);
                printableCount++;
            }
        }

        return printableCount >= Math.Max(2, limit / 3) ? sb.ToString() : string.Empty;
    }
}
