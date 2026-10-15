using System;

namespace PhoenixGSM.OmniTrace.Sensors;

/// <summary>
/// Information model for an intercepted network URL, connection, or request.
/// </summary>
public sealed class CapturedUrlInfo
{
    public string Url { get; set; } = string.Empty;
    public string Host { get; set; } = string.Empty;
    public string PathAndQuery { get; set; } = string.Empty;
    public string Fragment { get; set; } = string.Empty;
    public string Scheme { get; set; } = "HTTPS";
    public string Method { get; set; } = "GET";
    public string ProcessName { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public string SourceTag { get; set; } = "NET-ETW";
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public bool WasDnsCorrelated { get; set; }
    public string? CorrelatedDnsHost { get; set; }
    public int RemotePort { get; set; }
    public string RemoteEndpoint { get; set; } = string.Empty;
}
