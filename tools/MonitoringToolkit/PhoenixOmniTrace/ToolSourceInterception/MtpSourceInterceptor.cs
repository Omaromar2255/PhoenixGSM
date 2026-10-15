using System;
using System.Buffers.Binary;
using System.Text;

namespace PhoenixGSM.OmniTrace.ToolSourceInterception;

/// <summary>
/// Specialized interceptor for MTP (Media Transfer Protocol) and PTP commands
/// captured directly from the tool's process via DeviceIoControl or USB bulk pipes.
/// فاحص ومفكك أوامر MTP من المصدر مباشرة
/// </summary>
public static class MtpSourceInterceptor
{
    public static bool TryParseMtpCommand(
        byte[] payload,
        string toolName,
        int pid,
        int parentPid,
        string endpoint,
        string mechanism,
        out ToolSourceCommandRecord? record)
    {
        record = null;
        if (payload == null || payload.Length < 12) return false;

        // MTP/PTP Container Format:
        // [0..3]: uint32 Container Length
        // [4..5]: uint16 Container Type (1 = Command, 2 = Data, 3 = Response, 4 = Event)
        // [6..7]: uint16 Operation Code / Response Code
        // [8..11]: uint32 Transaction ID
        // [12..]: Parameters (up to 5 * 4 bytes)
        uint containerLen = BinaryPrimitives.ReadUInt32LittleEndian(payload.AsSpan(0, 4));
        ushort containerType = BinaryPrimitives.ReadUInt16LittleEndian(payload.AsSpan(4, 2));
        ushort opCode = BinaryPrimitives.ReadUInt16LittleEndian(payload.AsSpan(6, 2));
        uint transactionId = BinaryPrimitives.ReadUInt32LittleEndian(payload.AsSpan(8, 4));

        // Validate basic sanity for MTP container
        if (containerType < 1 || containerType > 4) return false;
        if (containerLen > 100 * 1024 * 1024) return false; // Sanity check 100MB

        string opName = ResolveMtpOpCode(opCode, containerType);
        string typeName = containerType switch
        {
            1 => "COMMAND",
            2 => "DATA",
            3 => "RESPONSE",
            4 => "EVENT",
            _ => "UNKNOWN"
        };

        // Extract parameters if present
        var paramsSb = new StringBuilder();
        int paramCount = (Math.Min(payload.Length, (int)containerLen) - 12) / 4;
        for (int i = 0; i < Math.Min(paramCount, 5); i++)
        {
            uint paramVal = BinaryPrimitives.ReadUInt32LittleEndian(payload.AsSpan(12 + i * 4, 4));
            paramsSb.Append($" [P{i + 1}=0x{paramVal:X8}]");
        }

        string pureCmd = $"MTP_{typeName}: {opName}{paramsSb}";
        string risk = EvaluateMtpRisk(opCode, containerType);

        var techDetails = new StringBuilder();
        techDetails.AppendLine("MTP / Media Transfer Protocol In-Process Interception");
        techDetails.AppendLine($"Tool: {toolName} (PID {pid}, Parent PID {parentPid})");
        techDetails.AppendLine($"Container Type: {typeName} (0x{containerType:X2})");
        techDetails.AppendLine($"Operation: {opName} (OpCode: 0x{opCode:X4})");
        techDetails.AppendLine($"Transaction ID: 0x{transactionId:X8}");
        techDetails.AppendLine($"Payload Size: {payload.Length} bytes (Declared Length: {containerLen})");
        if (paramsSb.Length > 0)
        {
            techDetails.AppendLine($"Parameters:{paramsSb}");
        }
        techDetails.AppendLine($"Capture Vector: {mechanism} (Target: {endpoint})");

        record = new ToolSourceCommandRecord
        {
            Timestamp = DateTime.UtcNow,
            Mode = ToolSourceMode.Mtp,
            ToolName = toolName,
            ProcessId = pid,
            ParentProcessId = parentPid,
            PureCommand = pureCmd,
            RawCommand = $"MTP 0x{opCode:X4} ({opName}) Type={typeName} Trans=0x{transactionId:X8}",
            InterceptMechanism = mechanism,
            TargetEndpoint = string.IsNullOrWhiteSpace(endpoint) ? "MTP USB Interface" : endpoint,
            RawPayload = payload,
            PayloadHex = ToolSourceCommandRecord.FormatHexDump(payload),
            PayloadAscii = Encoding.ASCII.GetString(payload.Length > 256 ? payload[..256] : payload),
            TechnicalDetails = techDetails.ToString(),
            RiskLevel = risk,
            Status = "CAPTURED_AT_SOURCE"
        };

        return true;
    }

    private static string ResolveMtpOpCode(ushort opCode, ushort containerType)
    {
        if (containerType == 3) // Response block
        {
            return opCode switch
            {
                0x2001 => "OK",
                0x2002 => "GENERAL_ERROR",
                0x2003 => "SESSION_NOT_OPEN",
                0x2006 => "INVALID_OBJECT_HANDLE",
                0x2009 => "STORE_FULL",
                0x2014 => "SPECIFICATION_BY_FORMAT_UNSUPPORTED",
                _ => $"RESPONSE_0x{opCode:X4}"
            };
        }

        return opCode switch
        {
            0x1001 => "GetDeviceInfo",
            0x1002 => "OpenSession",
            0x1003 => "CloseSession",
            0x1004 => "GetStorageIDs",
            0x1005 => "GetStorageInfo",
            0x1006 => "GetNumObjects",
            0x1007 => "GetObjectHandles",
            0x1008 => "GetObjectInfo",
            0x1009 => "GetObject (Download File)",
            0x100B => "DeleteObject (Wipe Data)",
            0x100C => "SendObjectInfo",
            0x100D => "SendObject (Push File/Payload)",
            0x1014 => "GetDevicePropDesc",
            0x1015 => "GetDevicePropValue",
            0x1016 => "SetDevicePropValue",
            0x101B => "GetPartialObject",
            0x9801 => "WPD_GetDeviceCapabilities",
            0x9802 => "WPD_GetObjectResources",
            0x9803 => "WPD_GetObjectProperties",
            _ => $"OpCode_0x{opCode:X4}"
        };
    }

    private static string EvaluateMtpRisk(ushort opCode, ushort containerType)
    {
        if (containerType == 1) // Command
        {
            return opCode switch
            {
                0x100B => "CRITICAL", // DeleteObject (Wiping partitions or user files)
                0x100D => "WARNING",  // SendObject (Staging payloads/exploits)
                0x1009 => "WARNING",  // GetObject (Reading private partitions)
                _ => "INFO"
            };
        }
        return "INFO";
    }
}
