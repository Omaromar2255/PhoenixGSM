using System;
using System.Collections.Generic;
using System.Text;

namespace PhoenixGSM.OmniTrace.Decoders;

public sealed class SmartSocketFrame
{
    public int DeclaredLength { get; set; }
    public string ServicePrefix { get; set; } = string.Empty;
    public string ServicePayload { get; set; } = string.Empty;
    public string RawText { get; set; } = string.Empty;
    public byte[] RawBytes { get; set; } = Array.Empty<byte>();
    public bool IsStatusResponse { get; set; }
    public bool IsOkay { get; set; }
    public bool IsSocketBridge { get; set; }
    public string BridgeClassification { get; set; } = string.Empty;
}

/// <summary>
/// LAYER 2B — ADB Smart Socket Decoder
/// Decodes 4-hex character length + payload format.
/// Preserves unknown services without dropping.
/// Enforces transport boundaries: avoids blind readPos++ sliding on unknown streams.
/// Identifies socket forwarded channels, Android 11+ abb binder bridges, and privilege bridge commands.
/// </summary>
public sealed class AdbSmartSocketDecoder
{
    public List<SmartSocketFrame> Decode(byte[] streamData, out int bytesConsumed)
    {
        var frames = new List<SmartSocketFrame>();
        bytesConsumed = 0;

        if (streamData == null || streamData.Length < 4)
        {
            return frames;
        }

        int offset = 0;
        int max = streamData.Length;

        while (offset + 4 <= max)
        {
            // Check for OKAY / FAIL 4-byte responses
            string fourByteStr = Encoding.ASCII.GetString(streamData, offset, 4);
            if (fourByteStr == "OKAY" || fourByteStr == "FAIL")
            {
                frames.Add(new SmartSocketFrame
                {
                    DeclaredLength = 4,
                    IsStatusResponse = true,
                    IsOkay = fourByteStr == "OKAY",
                    RawText = fourByteStr,
                    RawBytes = streamData[offset..(offset + 4)],
                    ServicePrefix = fourByteStr
                });
                offset += 4;
                bytesConsumed = offset;
                continue;
            }

            // Check if 4 characters are valid hex digits
            bool isHex = true;
            for (int i = 0; i < 4; i++)
            {
                char c = (char)streamData[offset + i];
                if (!Uri.IsHexDigit(c))
                {
                    isHex = false;
                    break;
                }
            }

            if (!isHex)
            {
                // Not a smart socket frame at boundary; stop parsing without blind sliding
                break;
            }

            int length = Convert.ToInt32(fourByteStr, 16);
            if (length < 0 || length > 1024 * 1024)
            {
                // Corrupt / oversized length
                break;
            }

            if (offset + 4 + length <= max)
            {
                byte[] payloadBytes = new byte[length];
                if (length > 0)
                {
                    Array.Copy(streamData, offset + 4, payloadBytes, 0, length);
                }

                string payloadStr = Encoding.UTF8.GetString(payloadBytes);
                var (prefix, body) = ParseServiceString(payloadStr);

                string classification = ClassifyService(payloadStr, out bool isBridge);

                frames.Add(new SmartSocketFrame
                {
                    DeclaredLength = length,
                    RawText = payloadStr,
                    RawBytes = payloadBytes,
                    ServicePrefix = prefix,
                    ServicePayload = body,
                    IsSocketBridge = isBridge,
                    BridgeClassification = classification
                });

                offset += 4 + length;
                bytesConsumed = offset;
            }
            else
            {
                // Incomplete frame in reassembly buffer, await remaining bytes
                break;
            }
        }

        return frames;
    }

    public static (string prefix, string body) ParseServiceString(string raw)
    {
        if (string.IsNullOrEmpty(raw)) return ("UNKNOWN", "");

        int colon = raw.IndexOf(':');
        if (colon > 0)
        {
            string pfx = raw[..colon];
            string bdy = raw[(colon + 1)..];
            return (pfx, bdy);
        }

        return ("UNKNOWN", raw);
    }

    public static bool IsSocketBridgeChannel(string service)
    {
        if (string.IsNullOrWhiteSpace(service)) return false;
        string s = service.Trim();
        return s.StartsWith("tcp:", StringComparison.OrdinalIgnoreCase) ||
               s.StartsWith("localabstract:", StringComparison.OrdinalIgnoreCase) ||
               s.StartsWith("localfilesystem:", StringComparison.OrdinalIgnoreCase) ||
               s.StartsWith("localreserved:", StringComparison.OrdinalIgnoreCase) ||
               s.StartsWith("abb:", StringComparison.OrdinalIgnoreCase) ||
               s.StartsWith("abb_exec:", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsModernAndroidService(string service)
    {
        if (string.IsNullOrWhiteSpace(service)) return false;
        string s = service.Trim();
        return s.StartsWith("abb:", StringComparison.OrdinalIgnoreCase) ||
               s.StartsWith("abb_exec:", StringComparison.OrdinalIgnoreCase) ||
               s.StartsWith("cmd ", StringComparison.OrdinalIgnoreCase) ||
               s.StartsWith("service call ", StringComparison.OrdinalIgnoreCase) ||
               s.Contains(";cmd ", StringComparison.OrdinalIgnoreCase) ||
               s.Contains(";service call ", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsAppPrivilegeCommand(string command)
    {
        if (string.IsNullOrWhiteSpace(command)) return false;
        return command.Contains("am start", StringComparison.OrdinalIgnoreCase) ||
               command.Contains("am startservice", StringComparison.OrdinalIgnoreCase) ||
               command.Contains("am broadcast", StringComparison.OrdinalIgnoreCase) ||
               command.Contains("pm grant", StringComparison.OrdinalIgnoreCase) ||
               command.Contains("appops set", StringComparison.OrdinalIgnoreCase) ||
               command.Contains("dpm set-device-owner", StringComparison.OrdinalIgnoreCase);
    }

    public static string ClassifyService(string raw, out bool isBridge)
    {
        isBridge = false;
        if (string.IsNullOrWhiteSpace(raw)) return string.Empty;

        string trimmed = raw.Trim();

        if (IsSocketBridgeChannel(trimmed))
        {
            isBridge = true;
            return "[ADB-SOCKET-BRIDGE]";
        }

        if (IsModernAndroidService(trimmed))
        {
            isBridge = true;
            return "[ADB-BINDER-BRIDGE]";
        }

        if (IsAppPrivilegeCommand(trimmed))
        {
            isBridge = true;
            return "[ADB-PRIVILEGE-CMD]";
        }

        return string.Empty;
    }
}
