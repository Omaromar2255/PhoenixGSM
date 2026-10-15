using System;
using System.Collections.Concurrent;

namespace PhoenixGSM.OmniTrace.ThreatIntel;

public class IocEntry
{
    public string Type { get; set; } = string.Empty; // Hash, IP, Domain, Serial
    public string Value { get; set; } = string.Empty;
    public string ThreatName { get; set; } = string.Empty;
}

/// <summary>
/// Thread-safe repository of Indicators of Compromise (IOCs)
/// مستودع آمن للخيوط لمؤشرات الاختراق
/// </summary>
public class IocStore : IDisposable
{
    private readonly ConcurrentDictionary<string, string> _maliciousHashes = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, string> _maliciousHosts = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, string> _suspiciousSerials = new(StringComparer.OrdinalIgnoreCase);

    public void IngestIoc(IocEntry entry)
    {
        try
        {
            switch (entry.Type.ToUpperInvariant())
            {
                case "HASH":
                    _maliciousHashes[entry.Value] = entry.ThreatName;
                    break;
                case "IP":
                case "DOMAIN":
                    _maliciousHosts[entry.Value] = entry.ThreatName;
                    break;
                case "SERIAL":
                    _suspiciousSerials[entry.Value] = entry.ThreatName;
                    break;
            }
        }
        catch (Exception ex)
        {
            // فشل مفتوح
            Console.WriteLine($"[IocStore] Error ingesting IOC: {ex.Message}");
        }
    }

    public bool IsKnownMaliciousHash(string hash, out string threatName)
    {
        threatName = string.Empty;
        try
        {
            if (_maliciousHashes.TryGetValue(hash, out var val) && val != null)
            {
                threatName = val;
                return true;
            }
            return false;
        }
        catch
        {
            return false;
        }
    }

    public bool IsKnownMaliciousHost(string host, out string threatName)
    {
        threatName = string.Empty;
        try
        {
            if (_maliciousHosts.TryGetValue(host, out var val) && val != null)
            {
                threatName = val;
                return true;
            }
            return false;
        }
        catch
        {
            return false;
        }
    }

    public void Dispose()
    {
        _maliciousHashes.Clear();
        _maliciousHosts.Clear();
        _suspiciousSerials.Clear();
    }
}
