using System;

namespace PhoenixGSM.OmniTrace.Models;

/// <summary>
/// LAYER 6 — Session-Keyed Reassembly Identifier
/// Guarantees that streams from different devices, interfaces, endpoints,
/// or directions NEVER mix in global buffers.
/// </summary>
public readonly struct CaptureSessionKey : IEquatable<CaptureSessionKey>
{
    public string Device { get; }
    public int Interface { get; }
    public string Endpoint { get; }
    public PacketDirection Direction { get; }
    public string TransportSession { get; }

    public CaptureSessionKey(string device, int iface, string endpoint, PacketDirection direction, string transportSession)
    {
        Device = string.IsNullOrEmpty(device) ? "UNKNOWN_DEVICE" : device;
        Interface = iface;
        Endpoint = string.IsNullOrEmpty(endpoint) ? "0x00" : endpoint;
        Direction = direction;
        TransportSession = string.IsNullOrEmpty(transportSession) ? "DEFAULT_SESSION" : transportSession;
    }

    public bool Equals(CaptureSessionKey other)
    {
        return string.Equals(Device, other.Device, StringComparison.OrdinalIgnoreCase) &&
               Interface == other.Interface &&
               string.Equals(Endpoint, other.Endpoint, StringComparison.OrdinalIgnoreCase) &&
               Direction == other.Direction &&
               string.Equals(TransportSession, other.TransportSession, StringComparison.OrdinalIgnoreCase);
    }

    public override bool Equals(object? obj) => obj is CaptureSessionKey other && Equals(other);

    public override int GetHashCode()
    {
        return HashCode.Combine(
            StringComparer.OrdinalIgnoreCase.GetHashCode(Device),
            Interface,
            StringComparer.OrdinalIgnoreCase.GetHashCode(Endpoint),
            Direction,
            StringComparer.OrdinalIgnoreCase.GetHashCode(TransportSession));
    }

    public override string ToString()
    {
        return $"{Device}#IF{Interface}#EP{Endpoint}#{Direction}#{TransportSession}";
    }

    public static bool operator ==(CaptureSessionKey left, CaptureSessionKey right) => left.Equals(right);
    public static bool operator !=(CaptureSessionKey left, CaptureSessionKey right) => !left.Equals(right);
}
