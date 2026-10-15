using System;
using System.Text.Json.Serialization;

namespace PhoenixGSM.OmniTrace.Models;

public enum KnownProtocol
{
    ADB,
    Fastboot,
    QualcommSahara,
    QualcommFirehose,
    QualcommDiag,
    MtkBrom,
    MtkDa,
    SpreadtrumFdl,
    SamsungOdin,
    SerialAt,
    Mtp,
    Ptp,
    AppleUsbmuxd,
    AppleLockdown,
    AppleRecovery,
    AppleDfu,
    AppleRamdiskSsh,
    ApplePurpleDiag,
    VendorSpecific,
    HostCommand,
    InProcess,
    Unknown
}

public sealed class ProtocolCandidate
{
    [JsonPropertyName("protocol")]
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public KnownProtocol Protocol { get; set; } = KnownProtocol.Unknown;

    [JsonPropertyName("protocolName")]
    public string ProtocolName => Protocol.ToString();

    [JsonPropertyName("confidence")]
    public double Confidence { get; set; }

    [JsonPropertyName("reason")]
    public string Reason { get; set; } = string.Empty;

    public ProtocolCandidate() { }

    public ProtocolCandidate(KnownProtocol protocol, double confidence, string reason)
    {
        Protocol = protocol;
        Confidence = Math.Clamp(confidence, 0.0, 1.0);
        Reason = reason;
    }

    public override string ToString()
    {
        return $"{Protocol} ({Confidence:P1}) - {Reason}";
    }
}
