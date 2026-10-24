using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PhoenixGSM.OmniTrace.Commands;

public static partial class PhoneCommandClassifier
{
    public static bool IsPhoneDeviceResponse(
        string command,
        string summary,
        string direction,
        string protocol,
        string categoryName,
        string additionalDetails = "")
    {
        string cmd = (command ?? "").Trim();
        string sum = (summary ?? "").Trim();
        string dir = (direction ?? "").Trim().ToUpperInvariant();
        string proto = (protocol ?? "").Trim();
        string cat = (categoryName ?? "").Trim();

        if (cat.Equals("Process", StringComparison.OrdinalIgnoreCase) ||
            cat.Equals("NetworkUrl", StringComparison.OrdinalIgnoreCase) ||
            cat.Equals("InProcess", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (sum.Contains("updater.exe", StringComparison.OrdinalIgnoreCase) ||
            sum.Contains("drvinst.exe", StringComparison.OrdinalIgnoreCase) ||
            cmd.Contains("GoogleUpdater", StringComparison.OrdinalIgnoreCase) ||
            sum.Contains("svchost.exe", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        bool isInbound = dir is "IN" or "DEV->HOST" or "<<" or "--" ||
                         sum.StartsWith("[ADB-STREAM] IN:", StringComparison.OrdinalIgnoreCase) ||
                         sum.StartsWith("[USB-RAW] IN", StringComparison.OrdinalIgnoreCase) ||
                         sum.StartsWith("[ADB-GETPROP-SUMMARY]", StringComparison.OrdinalIgnoreCase) ||
                         cmd.StartsWith("DATA IN", StringComparison.OrdinalIgnoreCase);

        if (cat.Equals("AdbProxy", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("ADB", StringComparison.OrdinalIgnoreCase) ||
            proto.Equals("RAW-BULK", StringComparison.OrdinalIgnoreCase))
        {
            // تجاهل محث الشل الفارغ المنفرد مثل "#" أو "$" حتى لا يقطع تسلسل الأوامر
            if (cmd is "#" or "$" || cmd.EndsWith(":/ $", StringComparison.Ordinal) || cmd.EndsWith(":/ #", StringComparison.Ordinal))
            {
                if (cmd.Length <= 16 && !cmd.Contains('\n'))
                    return false;
            }

            if (proto.Equals("ADB-RIL-IPC", StringComparison.OrdinalIgnoreCase))
            {
                return isInbound;
            }

            if (proto.Equals("ADB-STREAM", StringComparison.OrdinalIgnoreCase) ||
                sum.StartsWith("[ADB-GETPROP-SUMMARY]", StringComparison.OrdinalIgnoreCase))
            {
                if (cmd.StartsWith("device::ro.product.", StringComparison.OrdinalIgnoreCase)) return false;
                return true;
            }

            if (proto.Equals("RAW-BULK", StringComparison.OrdinalIgnoreCase) && isInbound)
            {
                if (sum.Contains("STAT...", StringComparison.Ordinal) ||
                    sum.Contains("vC=+", StringComparison.Ordinal))
                {
                    return false;
                }
                return true;
            }

            if (isInbound && (cmd.StartsWith("<<") ||
                              cmd.StartsWith("WRTE") ||
                              cmd.StartsWith("OKAY") ||
                              cmd.StartsWith("FAIL") ||
                              sum.Contains("<<") ||
                              sum.Contains("shell:")))
            {
                if (cmd is "CLSE" or "CNXN") return false;
                return true;
            }
            return isInbound && cmd.StartsWith("<<");
        }

        if (cat.Equals("SerialPort", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("AT", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("SERIAL", StringComparison.OrdinalIgnoreCase))
        {
            if (cmd.StartsWith("[") && cmd.Contains("]: [") && !isInbound)
                return false;

            if (cmd.StartsWith("OK", StringComparison.OrdinalIgnoreCase) ||
                cmd.StartsWith("ERROR", StringComparison.OrdinalIgnoreCase) ||
                cmd.StartsWith("+CME ERROR", StringComparison.OrdinalIgnoreCase) ||
                cmd.StartsWith("+CSQ:", StringComparison.OrdinalIgnoreCase) ||
                cmd.StartsWith("+CPIN:", StringComparison.OrdinalIgnoreCase) ||
                cmd.StartsWith("+CGMM:", StringComparison.OrdinalIgnoreCase) ||
                cmd.StartsWith("+GMM:", StringComparison.OrdinalIgnoreCase) ||
                sum.Contains("[MODEM-USB] IN", StringComparison.OrdinalIgnoreCase) ||
                (isInbound && cmd.StartsWith("<<")))
            {
                return true;
            }
            return isInbound && !cmd.StartsWith("RAW #");
        }

        if (proto.Contains("FASTBOOT", StringComparison.OrdinalIgnoreCase))
        {
            return isInbound ||
                   cmd.StartsWith("OKAY", StringComparison.OrdinalIgnoreCase) ||
                   cmd.StartsWith("FAIL", StringComparison.OrdinalIgnoreCase) ||
                   cmd.StartsWith("INFO", StringComparison.OrdinalIgnoreCase) ||
                   cmd.StartsWith("DATA", StringComparison.OrdinalIgnoreCase);
        }

        if (cat.Equals("MediaTek", StringComparison.OrdinalIgnoreCase) || proto.Contains("MTK", StringComparison.OrdinalIgnoreCase))
        {
            return isInbound || cmd is "DA_STATUS_OK" or "DA_STATUS_CONFIRM" or "DA_STATUS_FAIL" || sum.Contains("BROM ACK");
        }

        if (cat.Equals("QualcommEdl", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("SAHARA", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("FIREHOSE", StringComparison.OrdinalIgnoreCase))
        {
            return isInbound || cmd.Contains("<response") || cmd.Contains("ACK") || sum.Contains("HELLO_RESP");
        }

        if (cat.Equals("UnisocSpd", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("SPD", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("FDL", StringComparison.OrdinalIgnoreCase))
        {
            return isInbound || cmd.Contains("ACK") || sum.Contains("BSL_REP_ACK");
        }

        if (cat.Equals("AppleIos", StringComparison.OrdinalIgnoreCase))
        {
            return isInbound;
        }

        return false;
    }

    public static string? ExtractPureResponse(
        string command,
        string summary,
        string direction,
        string protocol,
        string categoryName,
        string payloadAscii = "",
        string additionalDetails = "")
    {
        if (!IsPhoneDeviceResponse(command, summary, direction, protocol, categoryName, additionalDetails))
            return null;

        // نستخدم payloadAscii أولاً لأنه يحتفظ بالنص الكامل غير المقتطع وبأسطره الأصلية
        string cmd = !string.IsNullOrWhiteSpace(payloadAscii) ? payloadAscii : (command ?? "");
        string sum = (summary ?? "").Trim();

        if ((command ?? "").Trim().Equals("GETPROP SUMMARY", StringComparison.OrdinalIgnoreCase))
        {
            return sum.Replace("[ADB-GETPROP-SUMMARY]", "").Trim();
        }

        if ((command ?? "").Trim().StartsWith("DATA IN", StringComparison.OrdinalIgnoreCase))
        {
            string rawResp = !string.IsNullOrWhiteSpace(payloadAscii) ? payloadAscii : sum;
            int colonIdx = rawResp.IndexOf(": ", StringComparison.Ordinal);
            if (rawResp.StartsWith("[USB-RAW]", StringComparison.OrdinalIgnoreCase) && colonIdx > 0)
            {
                rawResp = rawResp[(colonIdx + 2)..];
            }
            return CleanResponseTextPreservingLines(rawResp);
        }

        if (cmd.StartsWith("<<", StringComparison.OrdinalIgnoreCase))
            cmd = cmd[2..];

        if (cmd.StartsWith("[MODEM-USB] IN: ", StringComparison.OrdinalIgnoreCase))
            cmd = cmd["[MODEM-USB] IN: ".Length..];

        if (cmd.StartsWith("WRTE -> ", StringComparison.OrdinalIgnoreCase))
            cmd = cmd["WRTE -> ".Length..];

        return CleanResponseTextPreservingLines(cmd);
    }

    /// <summary>
    /// ينظف محارف التحكم غير المقروءة فقط مع الحفاظ التام 100% على الأسطر المتعددة (\n) والمسافات والـ Banner والتوكنات الطويلة بدون أي دمج بـ "|"
    /// </summary>
    private static string? CleanResponseTextPreservingLines(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;

        // إزالة محارف Null فقط مع الحفاظ على المسافات والأسطر
        string cleaned = text.Replace("\0", "").Trim('\r', '\n');
        if (string.IsNullOrWhiteSpace(cleaned)) return null;

        string trimmedCheck = cleaned.Trim();
        if (trimmedCheck is "#" or "$") return null;

        if (trimmedCheck.StartsWith("STAT...", StringComparison.Ordinal) ||
            trimmedCheck.StartsWith("vC=+", StringComparison.Ordinal) ||
            trimmedCheck.StartsWith("53 54 41 54", StringComparison.OrdinalIgnoreCase) ||
            trimmedCheck.StartsWith("53544154", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        // توحيد نهاية الأسطر إلى \n مع الحفاظ على الأسطر الفارغة التنسيقية والمحاذاة والـ Banner بالكامل
        string normalizedLines = cleaned.Replace("\r\n", "\n").Replace("\r", "\n");
        var rawLines = normalizedLines.Split('\n');
        var keptLines = new List<string>(rawLines.Length);

        foreach (var line in rawLines)
        {
            if (IsTransportProtocolSymbol(line))
                continue;

            keptLines.Add(line.TrimEnd());
        }

        string result = string.Join(Environment.NewLine, keptLines).Trim('\r', '\n');
        return string.IsNullOrWhiteSpace(result) ? null : result;
    }

    /// <summary>
    /// يعيد تجميع شرائح تدفق ADB-STREAM المتتالية (مثل التوكن البالغ 512 حرفاً المقسوم بين حزمتين 512B + 99B)
    /// بدون وضع "|" في وسط التوكن وبدون كسر الأسطر!
    /// </summary>
    public static string ReassembleMultilineStreamResponses(IReadOnlyList<string> chunks, string? commandEchoToSkip = null)
    {
        if (chunks == null || chunks.Count == 0) return string.Empty;

        var sb = new StringBuilder();
        string? prevChunk = null;

        foreach (var rawChunk in chunks)
        {
            if (string.IsNullOrWhiteSpace(rawChunk)) continue;
            string chunk = rawChunk.Replace("\r\n", "\n").Replace("\r", "\n").Trim('\n');
            if (string.IsNullOrWhiteSpace(chunk)) continue;

            // تجاهل صدى الأمر نفسه في بداية الرد (مثل /data/local/tmp/AT)
            if (!string.IsNullOrWhiteSpace(commandEchoToSkip) &&
                string.Equals(chunk.Trim(), commandEchoToSkip.Trim(), StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            // تجاهل التكرار الحرفي المباشر لنفس الشريحة
            if (prevChunk != null && string.Equals(prevChunk, chunk, StringComparison.Ordinal))
                continue;

            if (sb.Length == 0)
            {
                sb.Append(chunk);
            }
            else
            {
                // فحص ما إذا كانت الشريحة الحالية تكمل توكن Hex طويل انقسم بسبب حد الـ 512 بايت لحزمة USB!
                // مثال: الشريحة السابقة تنتهي بـ "...8DD7F251" والشريحة الحالية تبدأ بـ "4F324F0FA529..."
                bool prevEndsWithHexToken = EndsWithLongHexRun(sb, minHexChars: 32);
                bool currStartsWithHexContinuation = StartsWithHexContinuation(chunk, minHexChars: 8);

                if (prevEndsWithHexToken && currStartsWithHexContinuation)
                {
                    // دمج مباشر بدون أي مسافة وبدون سطر جديد وبدون "|" لإعادة التوكن قطعة واحدة 100%!
                    sb.Append(chunk.TrimStart());
                }
                else
                {
                    sb.AppendLine();
                    sb.Append(chunk);
                }
            }

            prevChunk = chunk;
        }

        return sb.ToString().Replace("\n", Environment.NewLine);
    }

    private static bool EndsWithLongHexRun(StringBuilder sb, int minHexChars)
    {
        if (sb.Length < minHexChars) return false;
        int count = 0;
        for (int i = sb.Length - 1; i >= 0; i--)
        {
            char c = sb[i];
            if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
            {
                count++;
                if (count >= minHexChars) return true;
            }
            else
            {
                break;
            }
        }
        return false;
    }

    private static bool StartsWithHexContinuation(string text, int minHexChars)
    {
        string t = text.TrimStart();
        if (t.Length < minHexChars) return false;
        int count = 0;
        foreach (char c in t)
        {
            if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
            {
                count++;
                if (count >= minHexChars) return true;
            }
            else
            {
                break;
            }
        }
        return false;
    }

    private static bool IsTransportProtocolSymbol(string line)
    {
        string t = line.Trim('\r', '\n', '\t', ' ', '\0', '.');
        if (t.Equals("STAT", StringComparison.OrdinalIgnoreCase) ||
            t.Equals("CLSE", StringComparison.OrdinalIgnoreCase) ||
            t.Equals("WRTE", StringComparison.OrdinalIgnoreCase) ||
            t.Equals("OKAY", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        string hexClean = t.Replace(" ", "");
        if (hexClean.StartsWith("53544154", StringComparison.OrdinalIgnoreCase) ||
            hexClean.StartsWith("434C5345", StringComparison.OrdinalIgnoreCase) ||
            hexClean.StartsWith("57525445", StringComparison.OrdinalIgnoreCase) ||
            hexClean.StartsWith("4F4B4159", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return false;
    }
}
