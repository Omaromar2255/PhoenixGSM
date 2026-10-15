using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using PhoenixGSM.UsbMonitor.Models;

namespace PhoenixGSM.UsbMonitor.Protocol;

public class AdbProtocolParser
{
    public const uint A_SYNC = 0x434e5953; // "SYNC"
    public const uint A_CNXN = 0x4e584e43; // "CNXN"
    public const uint A_AUTH = 0x48545541; // "AUTH"
    public const uint A_OPEN = 0x4e45504f; // "OPEN"
    public const uint A_OKAY = 0x59414b4f; // "OKAY"
    public const uint A_CLSE = 0x45534c43; // "CLSE"
    public const uint A_WRTE = 0x45545257; // "WRTE"

    private const int HeaderLength = 24;
    private const uint MaxSanityPayloadLength = 4 * 1024 * 1024; // 4 MB

    // Fastboot command prefixes
    private static readonly string[] FastbootCommands =
    [
        "getvar:", "flash:", "erase:", "boot", "reboot", "continue", "download:",
        "oem ", "flashing ", "snapshot-update", "set_active:"
    ];

    // Stream buffers for ADB reassembly
    private readonly MemoryStream _hostBuffer = new();
    private readonly MemoryStream _deviceBuffer = new();
    private readonly object _lock = new();

    public static string GetCommandName(uint command) => command switch
    {
        A_CNXN => "CNXN",
        A_AUTH => "AUTH",
        A_OPEN => "OPEN",
        A_OKAY => "OKAY",
        A_WRTE => "WRTE",
        A_CLSE => "CLSE",
        A_SYNC => "SYNC",
        _ => "UNKNOWN"
    };

    public static bool IsKnownCommand(uint cmd)
    {
        return cmd is A_CNXN or A_AUTH or A_OPEN or A_OKAY or A_WRTE or A_CLSE or A_SYNC;
    }

    public static bool ValidateHeader(byte[] buffer, int offset, out uint cmd, out uint arg0, out uint arg1, out uint dataLen, out uint dataCheck)
    {
        cmd = arg0 = arg1 = dataLen = dataCheck = 0;
        if (offset + HeaderLength > buffer.Length) return false;

        cmd = BitConverter.ToUInt32(buffer, offset);
        arg0 = BitConverter.ToUInt32(buffer, offset + 4);
        arg1 = BitConverter.ToUInt32(buffer, offset + 8);
        dataLen = BitConverter.ToUInt32(buffer, offset + 12);
        dataCheck = BitConverter.ToUInt32(buffer, offset + 16);
        uint magic = BitConverter.ToUInt32(buffer, offset + 20);

        // ADB Protocol Invariant: magic MUST EQUAL command ^ 0xFFFFFFFF
        if ((cmd ^ 0xFFFFFFFF) != magic)
        {
            return false;
        }

        if (!IsKnownCommand(cmd))
        {
            return false;
        }

        if (dataLen > MaxSanityPayloadLength)
        {
            return false;
        }

        return true;
    }

    /// <summary>
    /// Processes incoming raw USB chunk from either Host-to-Device (OUT) or Device-to-Host (IN),
    /// handles fragmentation, partial frames, and non-ADB WinUSB / Fastboot / Qualcomm / MTK / Odin traffic.
    /// </summary>
    public List<AdbUsbFrame> ProcessChunk(
        byte[] chunk,
        string direction = "OUT",
        string device = "USB Device",
        string vid = "",
        string pid = "",
        int interfaceNum = 1,
        string endpoint = "")
    {
        if (chunk == null || chunk.Length == 0) return new List<AdbUsbFrame>();

        // If the chunk starts with a valid ADB header (magic == cmd ^ 0xFFFFFFFF), handle via ADB stream
        bool isAdbHeaderAtStart = ValidateHeader(chunk, 0, out _, out _, out _, out _, out _);

        // 1. Direct Non-ADB protocol fast-path check (only when not a valid ADB wire packet)
        if (!isAdbHeaderAtStart)
        {
            string asciiCheck = GetAsciiString(chunk);
            if (IsFastboot(asciiCheck, direction) ||
                asciiCheck.StartsWith("<?xml", StringComparison.OrdinalIgnoreCase) ||
                asciiCheck.Contains("<data>") ||
                asciiCheck.Contains("<response") ||
                (chunk.Length >= 8 && IsQualcommSahara(chunk, out _)) ||
                asciiCheck.StartsWith("ODIN", StringComparison.OrdinalIgnoreCase) ||
                asciiCheck.StartsWith("LOKE", StringComparison.OrdinalIgnoreCase))
            {
                return new List<AdbUsbFrame> { ClassifyNonAdbChunk(chunk, direction, device, vid, pid, interfaceNum, endpoint) };
            }
        }

        var frames = new List<AdbUsbFrame>();
        lock (_lock)
        {
            var stream = direction.Equals("OUT", StringComparison.OrdinalIgnoreCase) || direction.Contains("HOST")
                ? _hostBuffer
                : _deviceBuffer;

            stream.Write(chunk, 0, chunk.Length);
            byte[] buf = stream.ToArray();
            int readPos = 0;

            while (readPos < buf.Length)
            {
                // Check if remaining buffer is smaller than ADB header
                if (readPos + HeaderLength > buf.Length)
                {
                    // If the remaining bytes start with a known ADB command, keep buffering for header completion
                    int remainingLen = buf.Length - readPos;
                    if (remainingLen >= 4)
                    {
                        uint maybeCmd = BitConverter.ToUInt32(buf, readPos);
                        if (IsKnownCommand(maybeCmd))
                        {
                            break; // Wait for next transfer to complete header
                        }
                    }
                    else if (remainingLen > 0)
                    {
                        // Could be partial command prefix
                        break;
                    }

                    // Otherwise if no ADB header could possibly match and not partial, emit remainder if non-empty
                    if (readPos == 0 && buf.Length > 0)
                    {
                        frames.Add(ClassifyNonAdbChunk(buf, direction, device, vid, pid, interfaceNum, endpoint));
                        readPos = buf.Length;
                    }
                    break;
                }

                // Try validating header at readPos
                if (ValidateHeader(buf, readPos, out uint cmd, out uint arg0, out uint arg1, out uint dataLen, out uint dataCheck))
                {
                    int totalFrameLen = HeaderLength + (int)dataLen;
                    if (readPos + totalFrameLen <= buf.Length)
                    {
                        // Complete ADB frame found!
                        byte[] payload = new byte[dataLen];
                        if (dataLen > 0)
                        {
                            Array.Copy(buf, readPos + HeaderLength, payload, 0, dataLen);
                        }

                        var frame = new AdbUsbFrame
                        {
                            Timestamp = DateTime.UtcNow,
                            Direction = direction,
                            Protocol = "ADB",
                            Command = GetCommandName(cmd),
                            CommandRaw = cmd,
                            Arg0 = arg0,
                            Arg1 = arg1,
                            DataLength = dataLen,
                            DataCheck = dataCheck,
                            Payload = payload,
                            PayloadPreview = FormatPayloadPreview(cmd, arg0, payload),
                            HexPreview = FormatHex(payload, 32),
                            Device = device,
                            Vid = vid,
                            Pid = pid,
                            Interface = interfaceNum,
                            Endpoint = endpoint,
                            Transfer = "BULK"
                        };

                        frames.Add(frame);
                        readPos += totalFrameLen;
                        continue;
                    }
                    else
                    {
                        // Incomplete payload: wait for next transfer
                        break;
                    }
                }
                else
                {
                    // Scan forward to resynchronize stream on valid ADB header
                    readPos++;
                }
            }

            // Keep remaining unparsed bytes in stream
            stream.SetLength(0);
            if (readPos < buf.Length)
            {
                stream.Write(buf, readPos, buf.Length - readPos);
            }
        }

        return frames;
    }

    /// <summary>
    /// Classifies non-ADB USB payloads (Fastboot, Qualcomm Sahara/Firehose, Odin, MTK, WinUSB raw)
    /// </summary>
    public static AdbUsbFrame ClassifyNonAdbChunk(
        byte[] data,
        string direction,
        string device,
        string vid,
        string pid,
        int interfaceNum,
        string endpoint)
    {
        string protocol = "WINUSB_RAW";
        string command = "RAW";
        string payloadPreview = "";
        string hexPreview = FormatHex(data, 32);

        // 1. Fastboot ASCII protocol check
        string ascii = GetAsciiString(data);
        if (IsFastboot(ascii, direction))
        {
            protocol = "FASTBOOT";
            command = GetFastbootCommand(ascii);
            payloadPreview = ascii.Trim();
        }
        // 2. Qualcomm Firehose (XML) check
        else if (ascii.StartsWith("<?xml", StringComparison.OrdinalIgnoreCase) || ascii.Contains("<data>") || ascii.Contains("<response"))
        {
            protocol = "QUALCOMM_FIREHOSE";
            command = "XML_COMMAND";
            payloadPreview = TruncateString(ascii.Trim(), 4096);
        }
        // 3. Qualcomm Sahara check
        else if (data.Length >= 8 && IsQualcommSahara(data, out string saharaCmd))
        {
            protocol = "QUALCOMM_SAHARA";
            command = saharaCmd;
            payloadPreview = $"Sahara Packet ({command}), Length={data.Length} B";
        }
        // 4. Samsung Odin check
        else if (ascii.StartsWith("ODIN", StringComparison.OrdinalIgnoreCase) || ascii.StartsWith("LOKE", StringComparison.OrdinalIgnoreCase))
        {
            protocol = "SAMSUNG_ODIN";
            command = ascii.Length >= 4 ? ascii.Substring(0, 4) : "ODIN";
            payloadPreview = ascii.Trim();
        }
        // 5. MediaTek BROM / Preloader check
        else if (data.Length == 1 && (data[0] == 0xA0 || data[0] == 0x0A || data[0] == 0x50 || data[0] == 0x05))
        {
            protocol = "MTK_BROM";
            command = $"HANDSHAKE_0x{data[0]:X2}";
            payloadPreview = $"MediaTek BROM Handshake byte (0x{data[0]:X2})";
        }
        else
        {
            // Generic WinUSB / Raw USB transfer
            protocol = "WINUSB_RAW";
            command = "DATA";
            payloadPreview = !string.IsNullOrWhiteSpace(ascii) && ascii.Length >= 4 && ascii.All(c => !char.IsControl(c) || c == '\r' || c == '\n')
                ? TruncateString(ascii.Trim(), 4096)
                : $"{data.Length} bytes [{hexPreview}]";
        }

        return new AdbUsbFrame
        {
            Timestamp = DateTime.UtcNow,
            Direction = direction,
            Protocol = protocol,
            Command = command,
            DataLength = (uint)data.Length,
            Payload = data,
            PayloadPreview = payloadPreview,
            HexPreview = hexPreview,
            Device = device,
            Vid = vid,
            Pid = pid,
            Interface = interfaceNum,
            Endpoint = endpoint,
            Transfer = endpoint.StartsWith("0x00") ? "CONTROL" : "BULK"
        };
    }

    private static bool IsFastboot(string text, string direction)
    {
        if (string.IsNullOrWhiteSpace(text)) return false;

        if (direction.Equals("OUT", StringComparison.OrdinalIgnoreCase))
        {
            return FastbootCommands.Any(cmd => text.StartsWith(cmd, StringComparison.OrdinalIgnoreCase));
        }
        else
        {
            // Do not classify ADB sync responses as Fastboot
            if (text.StartsWith("DATA", StringComparison.Ordinal))
            {
                // In Fastboot, DATA is followed by 8 hex digits, e.g. DATA00000800
                return text.Length >= 12 && Uri.IsHexDigit(text[4]) && Uri.IsHexDigit(text[5]);
            }
            if (text.StartsWith("OKAY", StringComparison.Ordinal) ||
                text.StartsWith("FAIL", StringComparison.Ordinal) ||
                text.StartsWith("INFO", StringComparison.Ordinal))
            {
                // Must be longer than 4 bytes and clean ASCII to avoid false match on 4-byte ADB tokens
                return text.Length > 4 && text.All(c => c >= 0x20 && c <= 0x7E);
            }
            return false;
        }
    }

    private static string GetFastbootCommand(string text)
    {
        int colon = text.IndexOf(':');
        if (colon > 0) return text.Substring(0, colon);
        int space = text.IndexOf(' ');
        if (space > 0) return text.Substring(0, space);
        return text.Length > 8 ? text.Substring(0, 8) : text;
    }

    private static bool IsQualcommSahara(byte[] data, out string cmdName)
    {
        cmdName = "UNKNOWN";
        if (data == null || data.Length < 8) return false;

        // Check for ADB wire signatures or magic
        if (ValidateHeader(data, 0, out _, out _, out _, out _, out _)) return false;

        uint cmdId = BitConverter.ToUInt32(data, 0);
        uint pktLen = BitConverter.ToUInt32(data, 4);

        // For Sahara READ_DATA (cmdId == 0x03):
        // Must be exactly 20 bytes, pktLen == 20, and read size < 64MB
        if (cmdId == 0x03)
        {
            if (data.Length != 20 || pktLen != 20) return false;
            uint readSize = BitConverter.ToUInt32(data, 16);
            if (readSize == 0 || readSize > 64 * 1024 * 1024) return false;
        }

        if (pktLen == data.Length || (pktLen >= 8 && pktLen <= 1024 && data.Length >= pktLen))
        {
            cmdName = cmdId switch
            {
                0x01 => "HELLO",
                0x02 => "HELLO_RESP",
                0x03 => "READ_DATA",
                0x04 => "END_IMAGE_TX",
                0x05 => "DONE",
                0x06 => "DONE_RESP",
                0x07 => "RESET",
                0x08 => "RESET_RESP",
                0x09 => "MEMORY_DEBUG",
                0x0A => "MEMORY_READ",
                0x0B => "CMD_READY",
                0x0C => "CMD_SWITCH_MODE",
                0x0D => "CMD_EXEC",
                _ => ""
            };
            return !string.IsNullOrEmpty(cmdName);
        }

        return false;
    }

    private static string GetAsciiString(byte[] data)
    {
        if (data == null || data.Length == 0) return "";
        int len = Math.Min(data.Length, 256);
        var sb = new StringBuilder();
        for (int i = 0; i < len; i++)
        {
            byte b = data[i];
            if (b >= 32 && b <= 126) sb.Append((char)b);
            else if (b == '\r' || b == '\n' || b == '\t') sb.Append((char)b);
            else break;
        }
        return sb.ToString();
    }

    private static string FormatHex(byte[]? data, int maxBytes)
    {
        if (data == null || data.Length == 0) return "";
        int count = Math.Min(data.Length, maxBytes);
        var hex = BitConverter.ToString(data, 0, count).Replace("-", " ");
        if (data.Length > count) hex += $" ... ({data.Length} bytes total)";
        return hex;
    }

    private static string TruncateString(string s, int maxLen)
    {
        if (string.IsNullOrEmpty(s)) return "";
        var clean = s.Replace("\r\n", " ").Replace("\n", " ").Replace("\t", " ");
        if (clean.Length <= maxLen) return clean;
        return clean.Substring(0, maxLen - 3) + "...";
    }

    /// <summary>
    /// Resets the internal stream buffers.
    /// </summary>
    public void Reset()
    {
        lock (_lock)
        {
            _hostBuffer.SetLength(0);
            _deviceBuffer.SetLength(0);
        }
    }

    private static string FormatPayloadPreview(uint cmd, uint arg0, byte[] payload)
    {
        if (payload == null || payload.Length == 0) return "";

        // Privacy protection: Redact auth tokens, RSA keys, and cryptographic signatures
        if (cmd == A_AUTH)
        {
            return arg0 switch
            {
                1 => $"[AUTH TOKEN REDACTED ({payload.Length} bytes)]",
                2 => $"[AUTH RSA SIGNATURE REDACTED ({payload.Length} bytes)]",
                3 => $"[AUTH RSA PUBLIC KEY REDACTED ({payload.Length} bytes)]",
                _ => $"[AUTH SECRET REDACTED ({payload.Length} bytes)]"
            };
        }

        // For CNXN, OPEN, WRTE: try UTF-8 string decoding
        try
        {
            int len = payload.Length;
            while (len > 0 && (payload[len - 1] == 0 || payload[len - 1] == '\r' || payload[len - 1] == '\n')) len--;

            if (len <= 0) return "";

            string text = Encoding.UTF8.GetString(payload, 0, len);
            int printable = text.Count(c => !char.IsControl(c) || c == '\n' || c == '\r' || c == '\t');
            if (printable >= text.Length * 0.8)
            {
                return TruncateString(text, 4096);
            }
        }
        catch { }

        // Fallback to Hex preview for binary data
        return FormatHex(payload, 32);
    }
}
