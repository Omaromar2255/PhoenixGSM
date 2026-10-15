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
}

/// <summary>
/// LAYER 2B — ADB Smart Socket Decoder
/// Decodes 4-hex character length + payload format.
/// Preserves unknown services without dropping.
/// Enforces transport boundaries: avoids blind readPos++ sliding on unknown streams.
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

                frames.Add(new SmartSocketFrame
                {
                    DeclaredLength = length,
                    RawText = payloadStr,
                    RawBytes = payloadBytes,
                    ServicePrefix = prefix,
                    ServicePayload = body
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

    private static (string prefix, string body) ParseServiceString(string raw)
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
}
