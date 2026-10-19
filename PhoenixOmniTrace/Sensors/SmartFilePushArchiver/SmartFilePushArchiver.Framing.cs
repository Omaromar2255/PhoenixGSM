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

    public static readonly Regex ExactSendPathAndModeRegex = new(
        @"^((?:/data/local/tmp/|/data/|/sdcard/|/storage/|/system/|/vendor/|/tmp/)[A-Za-z0-9_\-\./]+),(\d+)$",
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

    private static bool IsIgnoredNoiseFile(string pathOrName)
    {
        if (string.IsNullOrWhiteSpace(pathOrName)) return true;
        string fname = Path.GetFileName(pathOrName);
        if (string.IsNullOrWhiteSpace(fname)) return true;

        return fname.Equals("adb.log", StringComparison.OrdinalIgnoreCase) ||
               fname.StartsWith(".phx_keep_", StringComparison.OrdinalIgnoreCase) ||
               fname.StartsWith("phx_pull_", StringComparison.OrdinalIgnoreCase) ||
               fname.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase) ||
               fname.EndsWith(".tmp_write", StringComparison.OrdinalIgnoreCase) ||
               fname.EndsWith(".etl", StringComparison.OrdinalIgnoreCase);
    }

    public static string BuildNumberedFileName(string originalFileName, int uploadSequenceNumber)
    {
        if (string.IsNullOrWhiteSpace(originalFileName)) return $"pushed_file_{Math.Max(1, uploadSequenceNumber)}";
        if (uploadSequenceNumber <= 1) return originalFileName;

        string ext = Path.GetExtension(originalFileName);
        string stem = Path.GetFileNameWithoutExtension(originalFileName);
        if (string.IsNullOrEmpty(stem))
        {
            return $"{originalFileName}_{uploadSequenceNumber}";
        }

        return string.IsNullOrEmpty(ext)
            ? $"{stem}_{uploadSequenceNumber}"
            : $"{stem}_{uploadSequenceNumber}{ext}";
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

    /// <summary>
    /// Verifies whether a chunk contains a genuine ADB Sync SEND header ("SEND" + uint32 len + "/path,mode")
    /// when already inside a multi-packet binary transfer, preventing false splits on binary data.
    /// </summary>
    public static bool TryFindStructuredSendHeader(
        byte[] chunk,
        out int sendOffset,
        out string targetPath,
        out string mode)
    {
        sendOffset = -1;
        targetPath = string.Empty;
        mode = "33188";

        if (chunk == null || chunk.Length < 12) return false;

        for (int i = 0; i <= chunk.Length - 12; i++)
        {
            if (chunk[i] == (byte)'S' && chunk[i + 1] == (byte)'E' && chunk[i + 2] == (byte)'N' && chunk[i + 3] == (byte)'D')
            {
                uint pathModeLen = BitConverter.ToUInt32(chunk, i + 4);
                if (pathModeLen >= 4 && pathModeLen <= 512 && i + 8 + (int)pathModeLen <= chunk.Length)
                {
                    string candidate = Encoding.ASCII.GetString(chunk, i + 8, (int)pathModeLen).Trim('\0', ' ');
                    Match m = ExactSendPathAndModeRegex.Match(candidate);
                    if (m.Success)
                    {
                        sendOffset = i;
                        targetPath = m.Groups[1].Value.Trim();
                        mode = m.Groups[2].Value.Trim();
                        return true;
                    }
                }
            }
        }

        if (StartsWithAscii(chunk, "SEND"))
        {
            string ascii = Encoding.ASCII.GetString(chunk, 0, Math.Min(chunk.Length, 256));
            Match m = SendPathAndModeRegex.Match(ascii);
            if (m.Success && m.Index <= 12)
            {
                sendOffset = 0;
                targetPath = m.Groups[1].Value.Trim();
                mode = m.Groups[2].Value.Trim();
                return true;
            }
        }

        return false;
    }

    public static int FindDataHeaderOffset(byte[] chunk, int startOffset = 0)
    {
        if (chunk == null || chunk.Length < startOffset + 8) return -1;
        int maxSearch = chunk.Length - 8;
        for (int i = Math.Max(0, startOffset); i <= maxSearch; i++)
        {
            if (chunk[i] == 'D' && chunk[i + 1] == 'A' && chunk[i + 2] == 'T' && chunk[i + 3] == 'A')
            {
                uint dLen = BitConverter.ToUInt32(chunk, i + 4);
                if (dLen > 0 && dLen <= 64 * 1024 * 1024)
                {
                    return i;
                }
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
                int afterDone = i + 8;
                if (afterDone == chunk.Length) return i;
                if (afterDone + 4 <= chunk.Length)
                {
                    if ((chunk[afterDone] == 'S' && chunk[afterDone + 1] == 'E' && chunk[afterDone + 2] == 'N' && chunk[afterDone + 3] == 'D') ||
                        (chunk[afterDone] == 'S' && chunk[afterDone + 1] == 'T' && chunk[afterDone + 2] == 'A' && chunk[afterDone + 3] == 'T') ||
                        (chunk[afterDone] == 'Q' && chunk[afterDone + 1] == 'U' && chunk[afterDone + 2] == 'I' && chunk[afterDone + 3] == 'T') ||
                        IsAdbWireHeader(chunk, afterDone))
                    {
                        return i;
                    }
                }
            }
        }
        return -1;
    }

    private static bool IsAdbWireHeader(byte[] buffer, int offset)
    {
        if (buffer == null || offset + 24 > buffer.Length) return false;
        uint cmd = BitConverter.ToUInt32(buffer, offset);
        uint magic = BitConverter.ToUInt32(buffer, offset + 20);
        return (cmd ^ 0xFFFFFFFF) == magic &&
               (cmd == 0x4E584E43 || cmd == 0x4E45504F || cmd == 0x45545257 || cmd == 0x45534C43 || cmd == 0x59414B4F);
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
