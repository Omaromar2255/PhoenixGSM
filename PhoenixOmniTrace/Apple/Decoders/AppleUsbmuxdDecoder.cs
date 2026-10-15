using System;
using System.Collections.Generic;
using PhoenixGSM.OmniTrace.Apple.Models;

namespace PhoenixGSM.OmniTrace.Apple.Decoders;

/// <summary>
/// Decoder for Apple's usbmuxd protocol (TCP port 27015), used by all iOS servicing
/// and flashing tools to communicate with connected devices over USB.
/// </summary>
public static class AppleUsbmuxdDecoder
{
    public const uint USBMUXD_MSG_RESULT = 1;
    public const uint USBMUXD_MSG_CONNECT = 2;
    public const uint USBMUXD_MSG_LISTEN = 3;
    public const uint USBMUXD_MSG_DEVICE_ADD = 4;
    public const uint USBMUXD_MSG_DEVICE_REMOVE = 5;
    public const uint USBMUXD_MSG_PLIST = 8;

    public static double Evaluate(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length < 16) return 0.0;

        uint length = BitConverter.ToUInt32(buffer[..4]);
        uint version = BitConverter.ToUInt32(buffer[4..8]);
        uint message = BitConverter.ToUInt32(buffer[8..12]);

        // Validate length and versions
        if (length >= 16 && length <= 1048576 && (version == 0 || version == 1))
        {
            if (message == USBMUXD_MSG_PLIST || message == USBMUXD_MSG_CONNECT ||
                message == USBMUXD_MSG_LISTEN || message == USBMUXD_MSG_RESULT)
            {
                // If payload is a plist, 99% confidence
                if (buffer.Length > 16 && ApplePlistHelper.IsPlist(buffer[16..]))
                {
                    return 0.99;
                }
                return 0.90;
            }
        }

        // Check if raw payload itself is a plist with usbmuxd keys
        if (ApplePlistHelper.IsPlist(buffer))
        {
            var kv = ApplePlistHelper.ExtractKeyValues(buffer);
            if (kv.ContainsKey("MessageType") || kv.ContainsKey("ClientVersionString"))
            {
                return 0.95;
            }
        }

        return 0.0;
    }

    public static AppleDecodedCommand? DecodePacket(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length < 16) return null;

        uint length = BitConverter.ToUInt32(buffer[..4]);
        uint version = BitConverter.ToUInt32(buffer[4..8]);
        uint message = BitConverter.ToUInt32(buffer[8..12]);
        uint tag = BitConverter.ToUInt32(buffer[12..16]);

        var cmd = new AppleDecodedCommand
        {
            Mode = AppleDeviceMode.Normal,
            Category = "usbmuxd",
            Operation = GetMessageTypeName(message)
        };

        cmd.Details["HeaderLength"] = length.ToString();
        cmd.Details["Version"] = version.ToString();
        cmd.Details["Tag"] = tag.ToString();

        // Extract plist payload if present
        if (buffer.Length > 16)
        {
            var payloadSpan = buffer[16..];
            if (ApplePlistHelper.IsPlist(payloadSpan))
            {
                var kv = ApplePlistHelper.ExtractKeyValues(payloadSpan);
                foreach (var pair in kv) cmd.Details[pair.Key] = pair.Value;

                if (kv.TryGetValue("MessageType", out var msgType))
                {
                    cmd.Operation = $"usbmuxd:{msgType}";
                }
                if (kv.TryGetValue("ProgName", out var prog))
                {
                    cmd.Details["ClientProgram"] = prog;
                }
                if (kv.TryGetValue("PortNumber", out var port))
                {
                    cmd.Parameters = $"Port={port}";
                }
            }
        }

        cmd.Summary = $"usbmuxd [{cmd.Operation}] (tag={tag})";
        return cmd;
    }

    private static string GetMessageTypeName(uint msg) => msg switch
    {
        USBMUXD_MSG_RESULT => "Result",
        USBMUXD_MSG_CONNECT => "Connect",
        USBMUXD_MSG_LISTEN => "Listen",
        USBMUXD_MSG_DEVICE_ADD => "DeviceAdd",
        USBMUXD_MSG_DEVICE_REMOVE => "DeviceRemove",
        USBMUXD_MSG_PLIST => "Plist",
        _ => $"MsgType_{msg}"
    };
}
