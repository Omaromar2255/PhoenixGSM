using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.Decoders;

/// <summary>
/// Information model for a decoded MTP / PTP protocol transaction.
/// </summary>
public sealed class MtpDecodedPacket
{
    public uint ContainerLength { get; set; }
    public ushort ContainerType { get; set; }
    public ushort Code { get; set; }
    public uint TransactionId { get; set; }
    public string OperationName { get; set; } = string.Empty;
    public string TypeName { get; set; } = string.Empty;
    public uint[] Parameters { get; set; } = [];
    public string ExtractedText { get; set; } = string.Empty;
    public byte[] DataPayload { get; set; } = [];
    public Dictionary<string, string> Details { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    public override string ToString()
    {
        string pStr = Parameters.Length > 0 ? $" (Params: {string.Join(", ", Parameters)})" : "";
        string txt = !string.IsNullOrEmpty(ExtractedText) ? $" [{ExtractedText}]" : "";
        return $"[MTP {TypeName}] {OperationName}{pStr}{txt}";
    }
}

/// <summary>
/// LAYER 7B — Media Transfer Protocol (MTP / PTP) Decoder
/// Decodes USB PTP/MTP container framing, operation codes, device properties,
/// and vendor-specific extension payloads (such as Samsung/Xiaomi browser launch triggers for FRP bypass).
/// </summary>
public static class MtpDecoder
{
    public const ushort TYPE_COMMAND  = 1;
    public const ushort TYPE_DATA     = 2;
    public const ushort TYPE_RESPONSE = 3;
    public const ushort TYPE_EVENT    = 4;

    private static readonly Dictionary<ushort, string> OperationCodes = new()
    {
        // Standard PTP / MTP Operations
        [0x1001] = "GET_DEVICE_INFO",
        [0x1002] = "OPEN_SESSION",
        [0x1003] = "CLOSE_SESSION",
        [0x1004] = "GET_STORAGE_IDS",
        [0x1005] = "GET_STORAGE_INFO",
        [0x1006] = "GET_NUM_OBJECTS",
        [0x1007] = "GET_OBJECT_HANDLES",
        [0x1008] = "GET_OBJECT_INFO",
        [0x1009] = "GET_OBJECT",
        [0x100A] = "GET_THUMB",
        [0x100B] = "DELETE_OBJECT",
        [0x100C] = "SEND_OBJECT_INFO",
        [0x100D] = "SEND_OBJECT",
        [0x100E] = "INITIATE_CAPTURE",
        [0x1014] = "GET_DEVICE_PROP_DESC",
        [0x1015] = "GET_DEVICE_PROP_VALUE",
        [0x1016] = "SET_DEVICE_PROP_VALUE",
        [0x1017] = "RESET_DEVICE_PROP_VALUE",
        [0x1018] = "TERMINATE_OPEN_CAPTURE",
        [0x1019] = "MOVE_OBJECT",
        [0x101A] = "COPY_OBJECT",
        [0x101B] = "GET_PARTIAL_OBJECT",
        [0x101C] = "INITIATE_OPEN_CAPTURE",

        // Android / Microsoft MTP Extensions
        [0x9801] = "GET_OBJECT_PROPS_SUPPORTED",
        [0x9802] = "GET_OBJECT_PROP_DESC",
        [0x9803] = "GET_OBJECT_PROP_VALUE",
        [0x9804] = "SET_OBJECT_PROP_VALUE",
        [0x9805] = "GET_OBJECT_PROP_LIST",
        [0x9806] = "SET_OBJECT_PROP_LIST",
        [0x9810] = "GET_OBJECT_REFERENCES",
        [0x9811] = "SET_OBJECT_REFERENCES",
        [0x9812] = "SKIP",

        // Vendor GSM Service Operations (e.g. Samsung/Motorola FRP browser push)
        [0x9999] = "VENDOR_FRP_BROWSER_TRIGGER",
        [0x999A] = "VENDOR_EXEC_POPUP",
        [0x9001] = "SAMSUNG_FACTORY_TEST",
        [0x9002] = "SAMSUNG_FRP_BYPASS_NOTIFY"
    };

    private static readonly Dictionary<ushort, string> ResponseCodes = new()
    {
        [0x2001] = "OK",
        [0x2002] = "GENERAL_ERROR",
        [0x2003] = "SESSION_NOT_OPEN",
        [0x2004] = "INVALID_TRANSACTION_ID",
        [0x2005] = "OPERATION_NOT_SUPPORTED",
        [0x2006] = "PARAMETER_NOT_SUPPORTED",
        [0x2007] = "INCOMPLETE_TRANSFER",
        [0x2008] = "INVALID_STORAGE_ID",
        [0x2009] = "INVALID_OBJECT_HANDLE",
        [0x200A] = "DEVICE_PROP_NOT_SUPPORTED",
        [0x200B] = "INVALID_OBJECT_FORMAT_CODE",
        [0x200C] = "STORE_FULL",
        [0x200D] = "OBJECT_WRITE_PROTECTED",
        [0x200E] = "STORE_READ_ONLY",
        [0x200F] = "ACCESS_DENIED",
        [0x2013] = "SPECIFICATION_BY_FORMAT_UNSUPPORTED",
        [0x2014] = "NO_VALID_OBJECT_INFO",
        [0x2015] = "INVALID_CODE_FORMAT",
        [0x2019] = "DEVICE_BUSY",
        [0x201A] = "INVALID_PARENT_OBJECT",
        [0x201B] = "INVALID_DEVICE_PROP_FORMAT",
        [0x201C] = "INVALID_DEVICE_PROP_VALUE",
        [0x201D] = "INVALID_PARAMETER",
        [0x201E] = "SESSION_ALREADY_OPEN",
        [0x201F] = "TRANSACTION_CANCELLED",
        [0x2020] = "SPECIFICATION_OF_DESTINATION_UNSUPPORTED"
    };

    /// <summary>
    /// Evaluates if buffer matches MTP/PTP container framing.
    /// </summary>
    public static double EvaluateMtp(ReadOnlySpan<byte> buf)
    {
        if (buf.Length < 12) return 0.0;

        uint len = BitConverter.ToUInt32(buf[..4]);
        ushort type = BitConverter.ToUInt16(buf[4..6]);
        ushort code = BitConverter.ToUInt16(buf[6..8]);

        // Validate Container Length and Type
        if (len < 12 || type < TYPE_COMMAND || type > TYPE_EVENT) return 0.0;

        // Command: length is header (12) + 0 to 5 uint32 params (max 32)
        if (type == TYPE_COMMAND)
        {
            if (len >= 12 && len <= 32 && (len - 12) % 4 == 0)
            {
                if (OperationCodes.ContainsKey(code)) return 0.98;
                if (code >= 0x9000 && code <= 0x9FFF) return 0.90; // Vendor extension opcode
            }
            return 0.0;
        }

        // Response: length is header (12) + 0 to 5 uint32 params (max 32)
        if (type == TYPE_RESPONSE)
        {
            if (len >= 12 && len <= 32 && (len - 12) % 4 == 0 && ResponseCodes.ContainsKey(code))
            {
                return 0.98;
            }
            return 0.0;
        }

        // Event: length is header (12) + params (max 24)
        if (type == TYPE_EVENT)
        {
            if (len >= 12 && len <= 24 && (len - 12) % 4 == 0)
            {
                return 0.90;
            }
            return 0.0;
        }

        // Data: variable payload length up to 64MB
        if (type == TYPE_DATA)
        {
            if (len >= 12 && len <= 64 * 1024 * 1024)
            {
                return 0.88;
            }
            return 0.0;
        }

        return 0.0;
    }

    /// <summary>
    /// Decodes an MTP packet from a byte buffer.
    /// </summary>
    public static MtpDecodedPacket? DecodePacket(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length < 12) return null;

        uint len = BitConverter.ToUInt32(buffer[..4]);
        ushort type = BitConverter.ToUInt16(buffer[4..6]);
        ushort code = BitConverter.ToUInt16(buffer[6..8]);
        uint txId = BitConverter.ToUInt32(buffer[8..12]);

        string typeName = type switch
        {
            TYPE_COMMAND => "COMMAND",
            TYPE_DATA => "DATA",
            TYPE_RESPONSE => "RESPONSE",
            TYPE_EVENT => "EVENT",
            _ => $"TYPE_0x{type:X4}"
        };

        string opName;
        if (type == TYPE_RESPONSE)
        {
            opName = ResponseCodes.TryGetValue(code, out var resp) ? resp : $"RESP_0x{code:X4}";
        }
        else
        {
            opName = OperationCodes.TryGetValue(code, out var op) ? op : $"OP_0x{code:X4}";
        }

        var packet = new MtpDecodedPacket
        {
            ContainerLength = len,
            ContainerType = type,
            Code = code,
            TransactionId = txId,
            TypeName = typeName,
            OperationName = opName
        };

        // Extract parameters (commands/responses)
        if (type == TYPE_COMMAND || type == TYPE_RESPONSE)
        {
            int paramBytes = Math.Min(buffer.Length - 12, (int)len - 12);
            int paramCount = Math.Max(0, paramBytes / 4);
            if (paramCount > 0)
            {
                var pList = new List<uint>();
                for (int i = 0; i < paramCount && i < 5; i++)
                {
                    pList.Add(BitConverter.ToUInt32(buffer.Slice(12 + i * 4, 4)));
                }
                packet.Parameters = [.. pList];
            }
        }
        // Extract data payload (data blocks)
        else if (type == TYPE_DATA)
        {
            int dataLen = Math.Min(buffer.Length - 12, (int)len - 12);
            if (dataLen > 0)
            {
                packet.DataPayload = buffer.Slice(12, dataLen).ToArray();
                packet.ExtractedText = ExtractMtpStrings(packet.DataPayload);
            }
        }

        packet.Details["ContainerLength"] = len.ToString();
        packet.Details["ContainerType"] = typeName;
        packet.Details["Code"] = $"0x{code:X4} ({opName})";
        packet.Details["TransactionId"] = txId.ToString();

        return packet;
    }

    /// <summary>
    /// Scans MTP data blocks for UTF-16LE / ASCII text strings (Device Info, URLs, FRP push data).
    /// </summary>
    private static string ExtractMtpStrings(byte[] data)
    {
        if (data.Length < 2) return string.Empty;

        var sb = new StringBuilder();

        // 1. Check for standard MTP Pascal-style UTF-16LE strings: [byte count] [UTF16 chars]
        int offset = 0;
        while (offset < data.Length)
        {
            byte strLen = data[offset];
            if (strLen is > 1 and < 128 && offset + 1 + strLen * 2 <= data.Length)
            {
                try
                {
                    string s = Encoding.Unicode.GetString(data, offset + 1, (strLen - 1) * 2).TrimEnd('\0').Trim();
                    if (s.Length >= 2 && IsPrintable(s))
                    {
                        if (sb.Length > 0) sb.Append(" | ");
                        sb.Append(s);
                        offset += 1 + strLen * 2;
                        continue;
                    }
                }
                catch { }
            }
            offset++;
        }

        if (sb.Length > 0) return sb.ToString();

        // 2. Fallback: check ASCII URLs or text
        string ascii = Encoding.ASCII.GetString(data);
        if (ascii.Contains("http://", StringComparison.OrdinalIgnoreCase) ||
            ascii.Contains("https://", StringComparison.OrdinalIgnoreCase))
        {
            int httpIdx = ascii.IndexOf("http", StringComparison.OrdinalIgnoreCase);
            int endIdx = ascii.IndexOfAny([' ', '\0', '\r', '\n', '"'], httpIdx);
            if (endIdx < 0) endIdx = Math.Min(ascii.Length, httpIdx + 128);
            return ascii[httpIdx..endIdx].Trim();
        }

        return string.Empty;
    }

    private static bool IsPrintable(string s)
    {
        foreach (char c in s)
        {
            if (c < 32 && c != '\t' && c != '\r' && c != '\n') return false;
        }
        return true;
    }
}
