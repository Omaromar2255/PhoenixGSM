using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text.Json.Serialization;

namespace PhoenixGSM.OmniTrace.Models;

public enum SensorType
{
    USB,
    Network,
    Process,
    Serial,
    VirtualProxy,
    ETW,
    SyntheticTest,
    FileSystem
}

public enum TransportType
{
    BULK,
    CONTROL,
    INTERRUPT,
    TCP,
    SERIAL,
    ETW,
    FILE,
    UNKNOWN
}

public enum PacketDirection
{
    HOST_TO_DEVICE,
    DEVICE_TO_HOST,
    BIDIRECTIONAL,
    INTERNAL
}

/// <summary>
/// LAYER 0 — Unified Raw Event Model
/// Every sensor transmits this exact format to the Raw Event Bus.
/// RULE: Capture must NEVER depend on successful decoding. Raw data is always preserved.
/// </summary>
public sealed class RawCaptureEvent
{
    [JsonPropertyName("sequence")]
    public ulong SequenceNumber { get; set; }

    [JsonPropertyName("timestamp")]
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;

    [JsonPropertyName("timestampSource")]
    public string TimestampSource { get; set; } = "System";

    [JsonPropertyName("sensor")]
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public SensorType Sensor { get; set; } = SensorType.USB;

    [JsonPropertyName("transport")]
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public TransportType Transport { get; set; } = TransportType.BULK;

    [JsonPropertyName("direction")]
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public PacketDirection Direction { get; set; } = PacketDirection.HOST_TO_DEVICE;

    [JsonPropertyName("device")]
    public string DeviceIdentity { get; set; } = "DEFAULT_DEVICE";

    [JsonPropertyName("session")]
    public string SessionIdentity { get; set; } = string.Empty;

    [JsonPropertyName("interface")]
    public int InterfaceIdentity { get; set; } = 0;

    [JsonPropertyName("endpoint")]
    public string Endpoint { get; set; } = "0x00";

    [JsonPropertyName("length")]
    public int Length { get; set; }

    [JsonPropertyName("payloadSha256")]
    public string PayloadHash { get; set; } = string.Empty;

    [JsonPropertyName("raw")]
    public byte[] RawPayload { get; set; } = Array.Empty<byte>();

    [JsonIgnore]
    public byte[] CapturedPayload => RawPayload;

    [JsonIgnore]
    public string PayloadUtf8 => System.Text.Encoding.UTF8.GetString(RawPayload);

    [JsonPropertyName("metadata")]
    public Dictionary<string, string> Metadata { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    public static RawCaptureEvent Create(
        ulong sequence,
        SensorType sensor,
        TransportType transport,
        PacketDirection direction,
        string device,
        string session,
        int iface,
        string endpoint,
        byte[] payload,
        string timestampSource = "System",
        Dictionary<string, string>? metadata = null)
    {
        var evt = new RawCaptureEvent
        {
            SequenceNumber = sequence,
            Timestamp = DateTimeOffset.UtcNow,
            TimestampSource = timestampSource,
            Sensor = sensor,
            Transport = transport,
            Direction = direction,
            DeviceIdentity = device,
            SessionIdentity = session,
            InterfaceIdentity = iface,
            Endpoint = endpoint,
            Length = payload?.Length ?? 0,
            RawPayload = payload ?? Array.Empty<byte>(),
            Metadata = metadata ?? new(StringComparer.OrdinalIgnoreCase)
        };

        if (payload != null && payload.Length > 0)
        {
            using var sha = SHA256.Create();
            byte[] hash = sha.ComputeHash(payload);
            evt.PayloadHash = Convert.ToHexString(hash);
        }
        else
        {
            evt.PayloadHash = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"; // Empty hash
        }

        return evt;
    }

    public override string ToString()
    {
        return $"[Seq={SequenceNumber:D6} | {Sensor}/{Transport} | {Direction} | Dev={DeviceIdentity} | Ep={Endpoint} | Len={Length} | Hash={PayloadHash[..8]}...]";
    }
}
