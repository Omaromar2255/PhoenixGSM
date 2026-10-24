using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace PhoenixGSM.OmniTrace.Sensors;

public sealed partial class SmartFilePushArchiver
{
    public static readonly Regex SendPathAndModeRegex = new(
        @"((?:/data/local/tmp/|/data/|/sdcard/|/storage/|/system/|/vendor/|/tmp/)[A-Za-z0-9_\-\./]+),(\d+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public static readonly Regex StatPathRegex = new(
        @"(?:STAT|SEND).{0,8}?((?:/data/local/tmp/|/data/|/sdcard/|/storage/|/system/|/vendor/|/tmp/)[A-Za-z0-9_\-\./]+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Singleline);

    public static readonly Regex ShellFilePathRegex = new(
        @"((?:/data/local/tmp/|/data/system/)[A-Za-z0-9_\-\./]+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public static readonly Regex Base64EchoRegex = new(
        @"echo\s+['""]?([A-Za-z0-9+/=]{8,})['""]?\s*\|\s*(?:toybox\s+|busybox\s+)?base64\s+(?:-d|--decode)\s*>\s*([^\s;&|]+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>
    /// Matches direct streamed APK installation over ADB `exec:`, `shell:`, or Android 11+ `abb_exec:` / `abb:` channels:
    /// Examples:
    /// - `exec:cmd package 'install-write' -S 4521984 10293847 'base.apk' '-'`
    /// - `abb_exec:package install-write -S 4521984 10293847 base.apk -`
    /// - `exec:pm install -S 4521984`
    /// </summary>
    public static readonly Regex StreamedApkInstallWriteRegex = new(
        @"(?:exec:|shell:|abb_exec:|abb:).*?(?:install-write\b.*?-S\s+(\d+)\s+(\d+)\s+['""]?([^\s'""\-]+(?:\.apk)?)['""]?|pm\s+install\b.*?-S\s+(\d+))",
        RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Singleline);

    private static bool IsIgnoredNoiseFile(string pathOrName)
    {
        if (string.IsNullOrWhiteSpace(pathOrName)) return true;
        string fname = Path.GetFileName(pathOrName);
        if (string.IsNullOrWhiteSpace(fname)) return true;

        return fname.Equals("adb.log", StringComparison.OrdinalIgnoreCase) ||
               fname.StartsWith(".phx_keep_", StringComparison.OrdinalIgnoreCase) ||
               fname.StartsWith("phx_pull_", StringComparison.OrdinalIgnoreCase) ||
               fname.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase) ||
               fname.EndsWith(".etl", StringComparison.OrdinalIgnoreCase);
    }

    private static string BuildNumberedFileName(string originalFileName, int sequenceNumber)
    {
        if (sequenceNumber <= 1) return originalFileName;
        string ext = Path.GetExtension(originalFileName);
        string stem = Path.GetFileNameWithoutExtension(originalFileName);
        return string.IsNullOrEmpty(ext)
            ? $"{originalFileName}_{sequenceNumber}"
            : $"{stem}_{sequenceNumber}{ext}";
    }

    /// <summary>
    /// Converts internal Null-byte (`\0`) argument separators used by Android 11+ `abb:` / `abb_exec:` Binder bridge packets
    /// into spaces so the full command and `-S <size> <session> <apkName>` parameters are preserved.
    /// </summary>
    public static string DecodeAsciiPreservingAbbArguments(byte[] chunk, int maxLen = 0)
    {
        if (chunk == null || chunk.Length == 0) return string.Empty;
        int len = maxLen > 0 ? Math.Min(chunk.Length, maxLen) : chunk.Length;
        var sb = new StringBuilder(len);

        for (int i = 0; i < len; i++)
        {
            byte b = chunk[i];
            if (b == 0)
            {
                if (sb.Length > 0 && sb[^1] != ' ')
                {
                    sb.Append(' ');
                }
            }
            else if (b >= 32 && b < 127)
            {
                sb.Append((char)b);
            }
            else if (b == '\r' || b == '\n' || b == '\t')
            {
                sb.Append((char)b);
            }
        }

        return sb.ToString().Trim();
    }

    public static bool TryFindStructuredSendHeader(byte[] chunk, out int sendOffset, out string path, out string mode)
    {
        sendOffset = -1;
        path = string.Empty;
        mode = "33188";
        if (chunk == null || chunk.Length < 12) return false;

        int idx = FindAsciiTokenOffset(chunk, "SEND", 0, chunk.Length - 8);
        if (idx < 0 || idx + 8 > chunk.Length) return false;

        uint pathAndModeLen = BitConverter.ToUInt32(chunk, idx + 4);
        if (pathAndModeLen < 3 || pathAndModeLen > 512 || idx + 8 + pathAndModeLen > chunk.Length)
            return false;

        string spec = Encoding.ASCII.GetString(chunk, idx + 8, (int)pathAndModeLen);
        int commaIdx = spec.LastIndexOf(',');
        if (commaIdx <= 0) return false;

        string candidatePath = spec[..commaIdx].Trim();
        string candidateMode = spec[(commaIdx + 1)..].Trim();
        if (!candidatePath.StartsWith("/") || string.IsNullOrWhiteSpace(candidateMode))
            return false;

        sendOffset = idx;
        path = candidatePath;
        mode = candidateMode;
        return true;
    }

    private static int IndexOfSequence(ReadOnlySpan<byte> buffer, ReadOnlySpan<byte> pattern)
    {
        if (buffer.Length < pattern.Length || pattern.Length == 0) return -1;
        return buffer.IndexOf(pattern);
    }

    private static bool StartsWithAscii(byte[] chunk, string token)
    {
        if (chunk == null || chunk.Length < token.Length) return false;
        for (int i = 0; i < token.Length; i++)
        {
            if (chunk[i] != (byte)token[i]) return false;
        }
        return true;
    }

    private static int FindAsciiTokenOffset(byte[] chunk, string token, int start, int maxEnd)
    {
        if (chunk == null || maxEnd - start < token.Length) return -1;
        int limit = Math.Min(chunk.Length, maxEnd) - token.Length;
        for (int i = start; i <= limit; i++)
        {
            bool match = true;
            for (int j = 0; j < token.Length; j++)
            {
                if (chunk[i + j] != (byte)token[j])
                {
                    match = false;
                    break;
                }
            }
            if (match) return i;
        }
        return -1;
    }

    public static int FindDataHeaderOffset(byte[] chunk, int startOffset = 0)
    {
        if (chunk == null || chunk.Length < startOffset + 8) return -1;
        int maxSearch = chunk.Length - 8;
        for (int i = Math.Max(0, startOffset); i <= maxSearch; i++)
        {
            if (chunk[i] == 'D' && chunk[i + 1] == 'A' && chunk[i + 2] == 'T' && chunk[i + 3] == 'A')
            {
                return i;
            }
        }
        return -1;
    }

    public static int FindDoneTrailerOffset(byte[] chunk, int minOffset = 0)
    {
        if (chunk == null || chunk.Length < minOffset + 8) return -1;

        int exactPos = chunk.Length - 8;
        if (exactPos >= minOffset &&
            chunk[exactPos] == 'D' && chunk[exactPos + 1] == 'O' &&
            chunk[exactPos + 2] == 'N' && chunk[exactPos + 3] == 'E')
        {
            return exactPos;
        }

        for (int i = chunk.Length - 8; i >= minOffset; i--)
        {
            if (chunk[i] == 'D' && chunk[i + 1] == 'O' && chunk[i + 2] == 'N' && chunk[i + 3] == 'E')
            {
                return i;
            }
        }
        return -1;
    }

    private static bool IsAdbWireHeader(byte[] buffer, int offset)
    {
        if (buffer == null || offset + 24 > buffer.Length) return false;
        uint cmd = BitConverter.ToUInt32(buffer, offset);
        uint magic = BitConverter.ToUInt32(buffer, offset + 20);
        return (cmd ^ 0xFFFFFFFF) == magic;
    }

    public static byte[] StripDoneTrailer(byte[] data)
    {
        if (data == null || data.Length < 4) return data ?? [];
        int len = data.Length;
        if (len >= 8 && data[len - 8] == 'D' && data[len - 7] == 'O' && data[len - 6] == 'N' && data[len - 5] == 'E')
        {
            return data[..(len - 8)];
        }
        if (len >= 4 && data[len - 4] == 'D' && data[len - 3] == 'O' && data[len - 2] == 'N' && data[len - 1] == 'E')
        {
            return data[..(len - 4)];
        }
        return data;
    }

    private static bool IsMostlyPrintableAscii(byte[] data)
    {
        if (data == null || data.Length == 0) return false;
        int printable = 0;
        foreach (byte b in data)
        {
            if (b == 9 || b == 10 || b == 13 || (b >= 32 && b <= 126)) printable++;
        }
        return printable >= (data.Length * 3) / 4;
    }
}
