using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace PhoenixGSM.OmniTrace.Sensors;

public sealed partial class TempFileAtSensor
{
    private static readonly Regex ScriptPrefixRegex = new(
        @"^(\s*)(SEND|SENDLINE|CMD|COMMAND|EXEC|WRITE|WRITE_PORT|TX|INPUT|OUT)\s*[:=]\s*(?<cmd>.*)$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex PortTargetPattern = new(
        @"(PORT|TARGET|DEVICE|MODEM|INTERFACE)\s*[:=]\s*(?<val>[A-Z0-9_\\\.\-]+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex BasicAtRegex = new(
        @"^AT(&[A-Z0-9]+|\\[A-Z0-9]+|[EZHIOVQLMXDS][0-9]*|\?[0-9]*)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public static bool IsCandidatePath(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath)) return false;

        string fileName = Path.GetFileName(filePath);
        string dirName = Path.GetDirectoryName(filePath) ?? "";

        // Check if any directory segment specifically represents an AT or staging folder
        string[] dirSegments = dirName.Split(
            new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar },
            StringSplitOptions.RemoveEmptyEntries);

        bool inStagingDir = dirSegments.Any(s =>
            s.Equals("AT", StringComparison.OrdinalIgnoreCase) ||
            s.StartsWith("AT_", StringComparison.OrdinalIgnoreCase) ||
            s.StartsWith("AT-", StringComparison.OrdinalIgnoreCase) ||
            s.Equals("staging", StringComparison.OrdinalIgnoreCase)) ||
            dirName.Contains(@"\mac\tmp", StringComparison.OrdinalIgnoreCase) ||
            dirName.Contains(@"/mac/tmp", StringComparison.OrdinalIgnoreCase) ||
            dirName.Contains(@"\mac\5", StringComparison.OrdinalIgnoreCase) ||
            dirName.Contains(@"/mac/5", StringComparison.OrdinalIgnoreCase) ||
            (dirName.EndsWith(@"\mac", StringComparison.OrdinalIgnoreCase) || dirName.EndsWith("/mac", StringComparison.OrdinalIgnoreCase));

        if (inStagingDir) return true;

        // Check if filename explicitly indicates AT or modem staging
        if (fileName.StartsWith("AT", StringComparison.OrdinalIgnoreCase) ||
            fileName.Contains("AT_", StringComparison.OrdinalIgnoreCase) ||
            fileName.Contains("_AT", StringComparison.OrdinalIgnoreCase) ||
            fileName.Contains("modem", StringComparison.OrdinalIgnoreCase) ||
            fileName.StartsWith("QTMP", StringComparison.OrdinalIgnoreCase) ||
            fileName.Equals("ndx", StringComparison.OrdinalIgnoreCase) ||
            fileName.StartsWith("SRV", StringComparison.OrdinalIgnoreCase) ||
            fileName.StartsWith("athun", StringComparison.OrdinalIgnoreCase) ||
            fileName.StartsWith("trd", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".at", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".atcmd", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".seq", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".modem", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // Common temp extensions used by GSM tools staging AT scripts
        string ext = Path.GetExtension(filePath);
        if (ext.Equals(".tmp", StringComparison.OrdinalIgnoreCase) ||
            ext.Equals(".txt", StringComparison.OrdinalIgnoreCase) ||
            ext.Equals(".bat", StringComparison.OrdinalIgnoreCase) ||
            ext.Equals(".cmd", StringComparison.OrdinalIgnoreCase) ||
            ext.Equals(".bin", StringComparison.OrdinalIgnoreCase) ||
            ext.Equals(".dat", StringComparison.OrdinalIgnoreCase) ||
            ext.Equals(".script", StringComparison.OrdinalIgnoreCase) ||
            ext.Equals(".cfg", StringComparison.OrdinalIgnoreCase) ||
            ext.Equals(".ini", StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrEmpty(ext))
        {
            return true;
        }

        return false;
    }

    private static byte[]? ReadFileWithRetry(string path, int maxRetries = 8, int delayMs = 15)
    {
        for (int i = 0; i < maxRetries; i++)
        {
            try
            {
                if (!File.Exists(path)) return null;

                var fi = new FileInfo(path);
                if (!fi.Exists) return null;
                if (fi.Length > MaxFileSizeBytes) return null;

                // Share ReadWrite | Delete to allow accessing files while tools are writing or deleting
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var ms = new MemoryStream();
                fs.CopyTo(ms);
                byte[] data = ms.ToArray();
                if (data.Length > 0) return data;

                // If file is 0 bytes (just created, writer hasn't written bytes yet), backoff and retry
                Thread.Sleep(delayMs * (i + 1));
            }
            catch (FileNotFoundException)
            {
                return null;
            }
            catch (DirectoryNotFoundException)
            {
                return null;
            }
            catch (IOException)
            {
                // File locked by creating tool, wait and retry
                Thread.Sleep(delayMs * (i + 1));
            }
            catch (UnauthorizedAccessException)
            {
                Thread.Sleep(delayMs * (i + 1));
            }
            catch
            {
                return null;
            }
        }

        return null;
    }

    public static string DecodeText(byte[] bytes)
    {
        if (bytes == null || bytes.Length == 0) return string.Empty;

        // Check BOM
        if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE)
        {
            return Encoding.Unicode.GetString(bytes, 2, bytes.Length - 2);
        }
        if (bytes.Length >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF)
        {
            return Encoding.BigEndianUnicode.GetString(bytes, 2, bytes.Length - 2);
        }
        if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
        {
            return Encoding.UTF8.GetString(bytes, 3, bytes.Length - 3);
        }

        // Heuristic for UTF-16 LE without BOM
        if (bytes.Length >= 4 && bytes[1] == 0 && bytes[3] == 0 && bytes[0] != 0 && bytes[2] != 0)
        {
            return Encoding.Unicode.GetString(bytes);
        }

        // Standard UTF-8 / ASCII fallback
        return Encoding.UTF8.GetString(bytes).TrimStart('\uFEFF');
    }

    public static bool IsBinaryBuffer(byte[] bytes)
    {
        if (bytes == null || bytes.Length == 0) return false;

        // Check if starts with UTF-16 BOM
        if (bytes.Length >= 2 && (
            (bytes[0] == 0xFF && bytes[1] == 0xFE) ||
            (bytes[0] == 0xFE && bytes[1] == 0xFF)))
        {
            return false;
        }

        // Check for genuine UTF-16 LE text (without BOM)
        // In UTF-16 LE text, ASCII letters have 0x00 on odd bytes, and even bytes must be printable ASCII
        if (bytes.Length >= 4 && bytes[1] == 0 && bytes[3] == 0 && bytes[0] >= 32 && bytes[0] <= 126 && bytes[2] >= 32 && bytes[2] <= 126)
        {
            int checkLimit = Math.Min(bytes.Length, 32);
            bool allPrintableWide = true;
            int textSamples = 0;
            for (int i = 0; i < checkLimit; i += 2)
            {
                if (i + 1 < bytes.Length)
                {
                    if (bytes[i + 1] != 0 || (bytes[i] < 32 && bytes[i] != '\r' && bytes[i] != '\n' && bytes[i] != '\t'))
                    {
                        allPrintableWide = false;
                        break;
                    }
                    textSamples++;
                }
            }
            if (allPrintableWide && textSamples >= 2)
            {
                return false;
            }
        }

        int checkLen = Math.Min(bytes.Length, 1024);
        int nullCount = 0;
        for (int i = 0; i < checkLen; i++)
        {
            if (bytes[i] == 0) nullCount++;
        }

        return nullCount > 0;
    }

    public static bool ExtractAtCommands(string content, out List<string> atCommands, out string targetHint)
    {
        atCommands = [];
        targetHint = "USB Modem Interface";

        if (string.IsNullOrWhiteSpace(content)) return false;

        // Check if content is hex-encoded AT command string (e.g. "41542B43..." or "41 54 2B ...")
        string trimmedContent = content.Trim();
        if (IsHexEncodedAt(trimmedContent, out string decodedHexText))
        {
            content = decodedHexText;
        }

        var lines = content.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.RemoveEmptyEntries);
        bool foundAt = false;

        foreach (var rawLine in lines)
        {
            string line = rawLine.Trim();
            if (string.IsNullOrEmpty(line)) continue;

            // Check comment lines
            if (line.StartsWith('#') || line.StartsWith("//") || line.StartsWith(';') ||
                line.StartsWith("REM ", StringComparison.OrdinalIgnoreCase) || line.StartsWith("--"))
            {
                // Inspect comment for target hints (e.g. # COM12 or ; Port=COM4)
                var portMatch = PortTargetPattern.Match(line);
                if (portMatch.Success)
                {
                    targetHint = $"USB Modem Interface ({portMatch.Groups["val"].Value})";
                }
                continue;
            }

            // Check Port directive
            var matchTarget = PortTargetPattern.Match(line);
            if (matchTarget.Success)
            {
                targetHint = $"USB Modem Interface ({matchTarget.Groups["val"].Value})";
            }

            // Check script prefix (SEND: AT+...)
            string candidate = line;
            var scriptMatch = ScriptPrefixRegex.Match(line);
            if (scriptMatch.Success)
            {
                candidate = scriptMatch.Groups["cmd"].Value.Trim();
            }

            // Strip surrounding quotes if present (e.g. "AT+CGMM\r")
            if (candidate.Length >= 2 &&
                ((candidate.StartsWith('"') && candidate.EndsWith('"')) ||
                 (candidate.StartsWith('\'') && candidate.EndsWith('\''))))
            {
                candidate = candidate[1..^1].Trim();
            }

            // Strip trailing \r, \n escape sequences if literal in string
            if (candidate.EndsWith(@"\r\n", StringComparison.Ordinal)) candidate = candidate[..^4].Trim();
            else if (candidate.EndsWith(@"\r", StringComparison.Ordinal) || candidate.EndsWith(@"\n", StringComparison.Ordinal)) candidate = candidate[..^2].Trim();

            // Strip trailing inline comments (e.g. AT+CGMM // model info) safely outside quotes
            candidate = StripInlineComment(candidate).Trim();

            // Validate if candidate is a real AT command
            if (IsAtCommand(candidate))
            {
                atCommands.Add(candidate);
                foundAt = true;
            }
        }

        return foundAt;
    }

    public static bool IsAtCommand(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return false;

        string trimmed = text.Trim();

        // Exact match basic
        if (trimmed.Equals("AT", StringComparison.OrdinalIgnoreCase) ||
            trimmed.Equals("+++", StringComparison.Ordinal) ||
            trimmed.Equals("A/", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // Standard extended and vendor prefixes
        if (trimmed.StartsWith("AT+", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("AT^", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("AT%", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("AT$", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("AT*", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("AT#", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("AT@", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("AT!", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("AT&", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("AT\\", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("AT_", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // Basic V.250 commands (ATE, ATZ, ATI, ATH, ATO, ATV, ATQ, ATL, ATM, ATX, ATD, ATS)
        if (BasicAtRegex.IsMatch(trimmed))
        {
            return true;
        }

        return false;
    }

    private static string StripInlineComment(string line)
    {
        if (string.IsNullOrEmpty(line)) return line;

        bool inQuote = false;
        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if (c == '"')
            {
                inQuote = !inQuote;
                continue;
            }

            if (!inQuote)
            {
                if (c == '/' && i + 1 < line.Length && line[i + 1] == '/')
                {
                    return line[..i];
                }
                if ((c == '#' || c == ';') && i > 0 && char.IsWhiteSpace(line[i - 1]))
                {
                    return line[..i];
                }
            }
        }

        return line;
    }

    private static bool IsHexEncodedAt(string text, out string decodedText)
    {
        decodedText = string.Empty;
        if (string.IsNullOrWhiteSpace(text) || text.Length < 4) return false;

        string cleanHex = text.Replace(" ", "").Replace("\r", "").Replace("\n", "").Replace("\t", "");
        if (cleanHex.Length % 2 != 0) return false;

        if (!cleanHex.StartsWith("4154", StringComparison.OrdinalIgnoreCase)) return false;

        try
        {
            byte[] bytes = Convert.FromHexString(cleanHex);
            decodedText = Encoding.ASCII.GetString(bytes);
            return decodedText.StartsWith("AT", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    public static List<string> ExtractPrintableStrings(byte[] buffer, int minLength = 4, int maxLength = 16384)
    {
        var strings = new List<string>();
        if (buffer == null || buffer.Length < minLength) return strings;
        var seen = new HashSet<string>(StringComparer.Ordinal);

        // 1. Carve ASCII & UTF-8 printable strings
        var sb = new StringBuilder();
        for (int i = 0; i < buffer.Length; i++)
        {
            byte b = buffer[i];
            if (b >= 32 && b <= 126)
            {
                sb.Append((char)b);
                if (sb.Length >= maxLength)
                {
                    string s = sb.ToString();
                    if (seen.Add(s)) strings.Add(s);
                    sb.Clear();
                }
            }
            else
            {
                if (sb.Length >= minLength)
                {
                    string s = sb.ToString();
                    if (seen.Add(s)) strings.Add(s);
                }
                sb.Clear();
            }
        }
        if (sb.Length >= minLength)
        {
            string s = sb.ToString();
            if (seen.Add(s)) strings.Add(s);
        }

        // 2. Carve UTF-16 LE (wide character) strings (Windows OLE, structured storage, compound temp files)
        sb.Clear();
        for (int i = 0; i < buffer.Length - 1; i += 2)
        {
            byte b0 = buffer[i];
            byte b1 = buffer[i + 1];
            if (b1 == 0 && b0 >= 32 && b0 <= 126)
            {
                sb.Append((char)b0);
                if (sb.Length >= maxLength)
                {
                    string s = sb.ToString();
                    if (seen.Add(s)) strings.Add(s);
                    sb.Clear();
                }
            }
            else
            {
                if (sb.Length >= minLength)
                {
                    string s = sb.ToString();
                    if (seen.Add(s)) strings.Add(s);
                }
                sb.Clear();
            }
        }
        if (sb.Length >= minLength)
        {
            string s = sb.ToString();
            if (seen.Add(s)) strings.Add(s);
        }

        return strings;
    }

    public static string IdentifyBinaryFormat(byte[] bytes, string fileName)
    {
        if (bytes == null || bytes.Length < 4) return $"Binary Payload ({fileName})";

        // Compound File Binary Format / OLE (e.g. Windows Temp Compound Storage, MS Office/Servicing tools)
        if (bytes.Length >= 8 && bytes[0] == 0xD0 && bytes[1] == 0xCF && bytes[2] == 0x11 && bytes[3] == 0xE0 &&
            bytes[4] == 0xA1 && bytes[5] == 0xB1 && bytes[6] == 0x1A && bytes[7] == 0xE1)
            return $"OLE Structured Storage Container ({fileName})";

        if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xD8)
            return $"JPEG/JFIF Image ({fileName})";
        if (bytes.Length >= 4 && bytes[0] == 0x89 && bytes[1] == 0x50 && bytes[2] == 0x4E && bytes[3] == 0x47)
            return $"PNG Image ({fileName})";
        if (bytes.Length >= 6 && bytes[0] == 0x37 && bytes[1] == 0x7A && bytes[2] == 0xBC && bytes[3] == 0xAF && bytes[4] == 0x27 && bytes[5] == 0x1C)
            return $"7-Zip Staged Container ({fileName})";
        if (bytes.Length >= 4 && bytes[0] == 0x7F && bytes[1] == 0x45 && bytes[2] == 0x4C && bytes[3] == 0x46)
            return $"ELF Linux/Android Executable ({fileName})";
        if (bytes.Length >= 4 && bytes[0] == 0x50 && bytes[1] == 0x4B && bytes[2] == 0x03 && bytes[3] == 0x04)
            return $"Android APK/ZIP Staged Archive ({fileName})";
        if (bytes.Length >= 2 && bytes[0] == 0x4D && bytes[1] == 0x5A)
            return $"PE Windows Executable ({fileName})";
        if (bytes.Length >= 5 && bytes[0] == 0x75 && bytes[1] == 0x73 && bytes[2] == 0x74 && bytes[3] == 0x61 && bytes[4] == 0x72)
            return $"TAR Archive ({fileName})";

        return $"Binary Modem/Exploit Payload ({fileName})";
    }
}
