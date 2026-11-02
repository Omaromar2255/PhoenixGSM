using System;
using System.Text;
using System.Text.RegularExpressions;

namespace PhoenixOmniTrace.L24_SourceSentinel.Core;

public static partial class LiveHeapPatterns
{
    public static bool IsLikelyTruncatedAtFragment(string val)
    {
        if (val.StartsWith("AT+", StringComparison.OrdinalIgnoreCase) && val.Length <= 6 && !val.Contains('=') && !val.Contains('?'))
        {
            string cmdPart = val[3..].ToUpperInvariant();
            if (cmdPart is not ("CGMR" or "CGMI" or "CGMM" or "CGSN" or "CIMI" or "CPIN" or "CNUM" or "CLAC" or "CFUN" or "CSQ"))
                return true;
        }
        if (val.StartsWith("+CPIN:", StringComparison.OrdinalIgnoreCase) && val.EndsWith("<", StringComparison.Ordinal))
            return true;
        return false;
    }

    public static string StripInlineHtmlFormatting(string input)
    {
        if (string.IsNullOrEmpty(input) || !input.Contains('<'))
            return input;
        string replaced = input.Replace("<br>", "\n", StringComparison.OrdinalIgnoreCase)
                               .Replace("<br/>", "\n", StringComparison.OrdinalIgnoreCase)
                               .Replace("<br />", "\n", StringComparison.OrdinalIgnoreCase)
                               .Replace("</h3>", "\n", StringComparison.OrdinalIgnoreCase)
                               .Replace("&nbsp;", " ", StringComparison.OrdinalIgnoreCase)
                               .Replace("\0", "\n", StringComparison.Ordinal);
        string stripped = InlineHtmlTagsRegex.Replace(replaced, "");
        string joined = Regex.Replace(stripped, @"\.{3}\s*\r?\n\s*(OK(?:\s*\[\w+\])?|FAIL|COM\d+(?:\s*\[[^\r\n]+\])?|preloader_[^\r\n]+)", "... $1\n", RegexOptions.IgnoreCase);
        return MultiSpaceAfterDotsRegex.Replace(joined, "$1 ");
    }

    public static bool IsPureUiCosmeticOrDeviceInfoLine(string val)
    {
        if (string.IsNullOrWhiteSpace(val)) return true;
        if (val.StartsWith("Initializing usb", StringComparison.OrdinalIgnoreCase) ||
            val.StartsWith("Syncing with device", StringComparison.OrdinalIgnoreCase) ||
            val.StartsWith("Model Name :", StringComparison.OrdinalIgnoreCase) ||
            val.StartsWith("Product Name :", StringComparison.OrdinalIgnoreCase) ||
            val.StartsWith("Manufacturer :", StringComparison.OrdinalIgnoreCase) ||
            val.StartsWith("Platform :", StringComparison.OrdinalIgnoreCase) ||
            val.StartsWith("Android Version :", StringComparison.OrdinalIgnoreCase) ||
            val.StartsWith("Security Patch :", StringComparison.OrdinalIgnoreCase) ||
            val.StartsWith("Build ID :", StringComparison.OrdinalIgnoreCase) ||
            val.StartsWith("Build :", StringComparison.OrdinalIgnoreCase) ||
            val.StartsWith("Build Date :", StringComparison.OrdinalIgnoreCase) ||
            val.StartsWith("Vendor :", StringComparison.OrdinalIgnoreCase) ||
            val.StartsWith("Boot1 :", StringComparison.OrdinalIgnoreCase) ||
            val.Equals("BOOT DEVICE", StringComparison.OrdinalIgnoreCase) ||
            val.Equals("ERASE FRP", StringComparison.OrdinalIgnoreCase) ||
            val.Equals("FORMAT DATA", StringComparison.OrdinalIgnoreCase) ||
            val.Equals("FACTORY RESET", StringComparison.OrdinalIgnoreCase) ||
            val.Equals("READ BACK", StringComparison.OrdinalIgnoreCase) ||
            val.Equals("FLASH", StringComparison.OrdinalIgnoreCase) ||
            val.StartsWith("<h3", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }
        return false;
    }

    public static bool IsHtmlOrUiFormatNoise(string val)
    {
        return val.Contains("</li>", StringComparison.OrdinalIgnoreCase) ||
               val.Contains("<a href=", StringComparison.OrdinalIgnoreCase) ||
               val.Contains("<svg", StringComparison.OrdinalIgnoreCase) ||
               val.Equals("bgcolor", StringComparison.OrdinalIgnoreCase) ||
               val.Equals("bgcolor=", StringComparison.OrdinalIgnoreCase) ||
               val.Equals("bgcolor-color", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsWindowsSetupApiRebootNoise(string val)
    {
        return val.StartsWith("reboot: Could not ", StringComparison.OrdinalIgnoreCase) ||
               val.StartsWith("reboot: Query remove", StringComparison.OrdinalIgnoreCase) ||
               val.StartsWith("reboot: Device has ", StringComparison.OrdinalIgnoreCase) ||
               val.StartsWith("reboot: Marked as ", StringComparison.OrdinalIgnoreCase) ||
               val.StartsWith("reboot: Retrieve device", StringComparison.OrdinalIgnoreCase) ||
               val.StartsWith("reboot: Driver did not", StringComparison.OrdinalIgnoreCase) ||
               val.StartsWith("reboot: Unable to retrieve", StringComparison.OrdinalIgnoreCase) ||
               val.StartsWith("reboot: one or more files", StringComparison.OrdinalIgnoreCase) ||
               val.StartsWith("reboot: Unexpected while", StringComparison.OrdinalIgnoreCase) ||
               val.Equals("reboot:", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsChilkatOrDummyFileNoise(string val)
    {
        return val.Contains("CXDUMMYFILE.TXT", StringComparison.OrdinalIgnoreCase) ||
               val.Contains("TRUSTPOL.TXT", StringComparison.OrdinalIgnoreCase) ||
               val.Contains("AslLog_", StringComparison.OrdinalIgnoreCase) ||
               val.Contains("chilkatsoft.com", StringComparison.OrdinalIgnoreCase) ||
               val.Contains("AES_ENCRYPT == enc", StringComparison.OrdinalIgnoreCase);
    }

    public static string CleanToken(string input, bool allowNewLines = false, bool preserveUrlChars = false)
    {
        var sb = new StringBuilder(input.Length);
        foreach (char c in input)
        {
            if (c >= 32 && c <= 126)
                sb.Append(c);
            else if (allowNewLines && (c == '\r' || c == '\n' || c == '\t'))
                sb.Append(c);
            else
                break;
        }

        string cleaned = sb.ToString().Trim();
        bool isJsonObj = cleaned.StartsWith("{", StringComparison.Ordinal);
        if (!isJsonObj && !preserveUrlChars)
        {
            int jsonSep = cleaned.IndexOf("\",\"", StringComparison.Ordinal);
            if (jsonSep > 0)
                cleaned = cleaned[..jsonSep].Trim();
            cleaned = cleaned.Trim('"', '\'', ',', ';');
        }
        else if (preserveUrlChars && !isJsonObj)
        {
            cleaned = cleaned.Trim('"', '\'', ' ');
        }

        return cleaned;
    }

    public static bool IsCleanRamString(string value)
    {
        bool isJsonOrHttp = value.StartsWith("{", StringComparison.Ordinal) ||
                            value.StartsWith("http", StringComparison.OrdinalIgnoreCase) ||
                            value.StartsWith("POST ", StringComparison.OrdinalIgnoreCase) ||
                            value.StartsWith("GET ", StringComparison.OrdinalIgnoreCase);

        if (!isJsonOrHttp && (value.Contains("\",\"", StringComparison.Ordinal) || value.Contains("\", \"", StringComparison.Ordinal)))
            return false;

        if (value.Contains("????", StringComparison.Ordinal))
            return false;

        foreach (char c in value)
        {
            if (c < 0x20 || c > 0x7E)
            {
                if (c != '\r' && c != '\n' && c != '\t')
                    return false;
            }
        }

        if (value.Contains("<<"))
        {
            string trimmed = value.TrimStart();
            bool startsWithShellVerb = false;
            foreach (var verb in AllowedShellVerbs)
            {
                if (trimmed.StartsWith(verb, StringComparison.OrdinalIgnoreCase))
                {
                    startsWithShellVerb = true;
                    break;
                }
            }
            if (!startsWithShellVerb) return false;
        }

        return true;
    }
}
