using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using PhoenixGSM.OmniTrace.Decoders;

namespace PhoenixGSM.OmniTrace.Commands;

public static partial class PhoneCommandClassifier
{
    public static bool IsCorruptedBinaryOrSyncNoise(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return true;
        string trimmed = text.Trim();

        // 1. Sync protocol control tokens & empty framing
        if (trimmed.Equals("sync:", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("STAT", StringComparison.Ordinal) ||
            trimmed.StartsWith("SEND", StringComparison.Ordinal) ||
            trimmed.StartsWith("DONE", StringComparison.Ordinal) ||
            trimmed.Contains("DONE?", StringComparison.Ordinal) ||
            trimmed.Equals("WRTEa", StringComparison.Ordinal) ||
            trimmed.Equals("OPEN -> WRTEa", StringComparison.OrdinalIgnoreCase) ||
            trimmed.Equals("WRTE -> WRTEa", StringComparison.OrdinalIgnoreCase) ||
            trimmed.Equals("host::", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // 2. ELF binary chunks leaked into text
        if (trimmed.Contains(",33188DATA", StringComparison.Ordinal) ||
            trimmed.Contains(",33261DATA", StringComparison.Ordinal) ||
            (trimmed.Contains("ELF") && (trimmed.Contains("Q?td") || trimmed.Contains("/system/"))) ||
            trimmed.Contains("/system/?bin/l", StringComparison.Ordinal))
        {
            return true;
        }

        // 3. Any non-whitespace control character (< 0x20 or >= 0x7F) or '?' replacement character
        bool isShellOrPtyOrAt = ShellStreamReconstructor.IsShellOrPtyOpenService(trimmed, out _, out _, out _, out _) ||
                                trimmed.StartsWith("shell:", StringComparison.OrdinalIgnoreCase) ||
                                trimmed.StartsWith("shell,", StringComparison.OrdinalIgnoreCase) ||
                                trimmed.StartsWith("pty:", StringComparison.OrdinalIgnoreCase) ||
                                trimmed.StartsWith("AT", StringComparison.OrdinalIgnoreCase);

        int questionCount = 0;
        foreach (char c in trimmed)
        {
            if (c < 0x20 && c != '\r' && c != '\n' && c != '\t')
                return true;
            if (c >= 0x7F)
                return true;
            if (c == '?')
                questionCount++;
        }

        if (questionCount > 0)
        {
            if (!isShellOrPtyOrAt && questionCount > 2) return true;
        }

        // السماح بإدخالات PTY التفاعلية المكونة من رقم أو حرف واحد (مثل اختيار 1 أو y أو w)
        if (trimmed.Length == 1 && !char.IsLetterOrDigit(trimmed[0]))
            return true;

        return false;
    }

    public static string ClassifyCommandTypeTag(
        string command,
        string protocol,
        string categoryName,
        string summary = "")
    {
        string cmd = (command ?? "").Trim();
        string proto = (protocol ?? "").Trim();
        string cat = (categoryName ?? "").Trim();

        bool isAtToolExecution = cmd.Equals("/data/local/tmp/AT", StringComparison.OrdinalIgnoreCase) ||
                                 cmd.StartsWith("/data/local/tmp/AT ", StringComparison.OrdinalIgnoreCase);

        if (cat.Equals("ArtifactVault", StringComparison.OrdinalIgnoreCase) ||
            proto.Equals("ADB-SYNC", StringComparison.OrdinalIgnoreCase) ||
            cmd.StartsWith("PUSH ", StringComparison.OrdinalIgnoreCase) ||
            (!cmd.StartsWith("shell", StringComparison.OrdinalIgnoreCase) &&
             !cmd.StartsWith("pty:", StringComparison.OrdinalIgnoreCase) &&
             !isAtToolExecution &&
             (cmd.StartsWith("/data/local/tmp/", StringComparison.OrdinalIgnoreCase) ||
              cmd.StartsWith("/sdcard/", StringComparison.OrdinalIgnoreCase))))
        {
            return "ADB-PUSH";
        }

        if (proto.Equals("ADB-RIL-IPC", StringComparison.OrdinalIgnoreCase) ||
            cmd.StartsWith("060100", StringComparison.OrdinalIgnoreCase) ||
            cmd.StartsWith("120D00", StringComparison.OrdinalIgnoreCase) ||
            cmd.StartsWith("514200", StringComparison.OrdinalIgnoreCase) ||
            cmd.StartsWith("516400", StringComparison.OrdinalIgnoreCase) ||
            (cmd.Length >= 64 && cmd.All(Uri.IsHexDigit)))
        {
            return "ADB-AT-RIL";
        }

        if (proto.Equals("ADB-PTY-CMD", StringComparison.OrdinalIgnoreCase) ||
            cmd.StartsWith("pty:", StringComparison.OrdinalIgnoreCase) ||
            cmd.Contains(",pty:", StringComparison.OrdinalIgnoreCase))
        {
            return "ADB-PTY";
        }

        if (cat.Equals("MediaTek", StringComparison.OrdinalIgnoreCase) || proto.Contains("MTK", StringComparison.OrdinalIgnoreCase))
        {
            return proto.Contains("DA", StringComparison.OrdinalIgnoreCase) ? "MTK-DA" : "MTK-BROM";
        }

        if (proto.Contains("FASTBOOT", StringComparison.OrdinalIgnoreCase))
        {
            return "FASTBOOT";
        }

        if (cat.Equals("QualcommEdl", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("FIREHOSE", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("SAHARA", StringComparison.OrdinalIgnoreCase))
        {
            return proto.Contains("FIREHOSE", StringComparison.OrdinalIgnoreCase) ? "QCOM-FIREHOSE" : "QCOM-SAHARA";
        }

        if (cat.Equals("UnisocSpd", StringComparison.OrdinalIgnoreCase) || proto.Contains("SPD", StringComparison.OrdinalIgnoreCase))
        {
            return "SPD-FDL";
        }

        if (cat.Equals("SerialPort", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("SERIAL", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("MODEM", StringComparison.OrdinalIgnoreCase) ||
            cmd.StartsWith("AT", StringComparison.OrdinalIgnoreCase))
        {
            if (proto.Contains("DIAG", StringComparison.OrdinalIgnoreCase)) return "QUALCOMM-DIAG";
            if (cat.Equals("TempFileAt", StringComparison.OrdinalIgnoreCase) || proto.Contains("STAGED", StringComparison.OrdinalIgnoreCase)) return "STAGED-AT-FILE";
            return "MODEM-AT";
        }

        if (cmd.StartsWith("usb:", StringComparison.OrdinalIgnoreCase) ||
            cmd.StartsWith("reboot", StringComparison.OrdinalIgnoreCase))
        {
            return "ADB-MODE";
        }

        if (cmd.Contains("/data/local/tmp/AT", StringComparison.OrdinalIgnoreCase) &&
            !cmd.Contains("chmod", StringComparison.OrdinalIgnoreCase))
        {
            return "ADB-AT-TOOL";
        }

        if (cmd.StartsWith("shell", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("ADB", StringComparison.OrdinalIgnoreCase) ||
            cat.Equals("AdbProxy", StringComparison.OrdinalIgnoreCase))
        {
            return "ADB-SHELL";
        }

        return !string.IsNullOrWhiteSpace(proto) ? proto.ToUpperInvariant() : "PHONE-CMD";
    }

    public static string DecodeInlineRilHexAnnotation(string pureCmd)
    {
        if (string.IsNullOrWhiteSpace(pureCmd)) return string.Empty;
        string clean = pureCmd.Trim();
        if (clean.Length < 12 || clean.Length > 256 || clean.Length % 2 != 0) return string.Empty;
        if (!clean.All(Uri.IsHexDigit)) return string.Empty;

        try
        {
            byte[] bytes = Convert.FromHexString(clean);
            var parts = new List<string>();
            var sb = new StringBuilder();
            foreach (byte b in bytes)
            {
                if (b >= 32 && b <= 126)
                {
                    sb.Append((char)b);
                }
                else
                {
                    if (sb.Length >= 3)
                    {
                        parts.Add(sb.ToString());
                    }
                    sb.Clear();
                }
            }
            if (sb.Length >= 3)
            {
                parts.Add(sb.ToString());
            }

            if (parts.Count > 0)
            {
                return $"[ASCII: {string.Join(" | ", parts.Distinct())}]";
            }
        }
        catch { }

        return string.Empty;
    }
}
