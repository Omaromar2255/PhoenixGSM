using System;
using System.Text;
using System.Text.Json.Serialization;

namespace PhoenixGSM.UsbMonitor.Models;

public class AdbUsbFrame
{
    [JsonPropertyName("timestamp")]
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    [JsonPropertyName("direction")]
    public string Direction { get; set; } = "OUT"; // "OUT" (Host->Device) or "IN" (Device->Host)

    [JsonPropertyName("protocol")]
    public string Protocol { get; set; } = "ADB"; // ADB, FASTBOOT, QUALCOMM_SAHARA, QUALCOMM_FIREHOSE, SAMSUNG_ODIN, MTK, WINUSB_RAW

    [JsonPropertyName("adb_command")]
    public string Command { get; set; } = ""; // CNXN, AUTH, OPEN, OKAY, WRTE, CLSE or Non-ADB command

    [JsonPropertyName("command_hex")]
    public string CommandHex => $"0x{CommandRaw:X8}";

    [JsonIgnore]
    public uint CommandRaw { get; set; }

    [JsonPropertyName("arg0")]
    public uint Arg0 { get; set; }

    [JsonPropertyName("arg1")]
    public uint Arg1 { get; set; }

    [JsonPropertyName("data_length")]
    public uint DataLength { get; set; }

    [JsonPropertyName("data_check")]
    public uint DataCheck { get; set; }

    [JsonIgnore]
    public byte[]? Payload { get; set; }

    [JsonPropertyName("payload_preview")]
    public string? PayloadPreview { get; set; }

    [JsonPropertyName("hex_preview")]
    public string? HexPreview { get; set; }

    [JsonPropertyName("device")]
    public string Device { get; set; } = "USB Device";

    [JsonPropertyName("vid")]
    public string Vid { get; set; } = "";

    [JsonPropertyName("pid")]
    public string Pid { get; set; } = "";

    [JsonPropertyName("interface")]
    public int Interface { get; set; } = 1;

    [JsonPropertyName("endpoint")]
    public string Endpoint { get; set; } = "";

    [JsonPropertyName("transfer")]
    public string Transfer { get; set; } = "BULK";

    [JsonPropertyName("length")]
    public int Length => (Protocol == "ADB" ? 24 : 0) + (int)DataLength;

    public string GetDetailSummary()
    {
        if (Protocol != "ADB" && Protocol != "UNKNOWN")
        {
            return $"[{Protocol}] {Command} (Len={DataLength} B): {PayloadPreview ?? HexPreview}";
        }

        return Command switch
        {
            "CNXN" => $"CNXN: Version 0x{Arg0:X8}, MaxData={Arg1} | Payload: {PayloadPreview}",
            "AUTH" => $"AUTH: Type={GetAuthTypeName(Arg0)} | DataLen={DataLength}",
            "OPEN" => $"OPEN: LocalID={Arg0} | Destination: \"{PayloadPreview}\"",
            "OKAY" => $"OKAY: LocalID={Arg0}, RemoteID={Arg1}",
            "WRTE" => $"WRTE: LocalID={Arg0}, RemoteID={Arg1}, Len={DataLength} | Content: {PayloadPreview}",
            "CLSE" => $"CLSE: LocalID={Arg0}, RemoteID={Arg1}",
            "RAW" => $"[RAW] Len={DataLength} B | {HexPreview} | {PayloadPreview}",
            _ => $"{Command}: Arg0=0x{Arg0:X}, Arg1=0x{Arg1:X}, Len={DataLength} | {PayloadPreview ?? HexPreview}"
        };
    }

    private static string GetAuthTypeName(uint type) => type switch
    {
        1 => "TOKEN (1)",
        2 => "SIGNATURE (2)",
        3 => "RSAPUBLICKEY (3)",
        _ => $"UNKNOWN ({type})"
    };
}
