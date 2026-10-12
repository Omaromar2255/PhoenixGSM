using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Threading;
using PhoenixGSM.OmniTrace.Decoders;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.Sensors;

public sealed partial class NetworkUrlSensor
{
    #region Ingestion & Notification
    public void IngestCapturedUrl(
        string url,
        string procName,
        int pid,
        string sourceTag,
        bool isDns = false,
        string method = "GET",
        int remotePort = 0,
        string? endpoint = null)
    {
        if (string.IsNullOrWhiteSpace(url)) return;

        url = url.Trim(' ', '\t', '\r', '\n', '"', '\'', '<', '>');
        if (!url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
            !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase) &&
            !url.StartsWith("tcp://", StringComparison.OrdinalIgnoreCase))
        {
            url = "https://" + url;
        }

        // Deduplication: same PID + URL + Source within 2 seconds
        string dedupKey = $"{pid}:{url}:{sourceTag}";
        DateTime now = DateTime.UtcNow;
        if (_recentUrls.TryGetValue(dedupKey, out var expiry) && now < expiry)
        {
            return;
        }
        _recentUrls[dedupKey] = now.AddSeconds(2);

        if (_recentUrls.Count > 2000)
        {
            foreach (var kvp in _recentUrls)
            {
                if (now > kvp.Value) _recentUrls.TryRemove(kvp.Key, out _);
            }
        }

        Uri uri;
        try { uri = new Uri(url); } catch { return; }

        Interlocked.Increment(ref _urlsCaptured);

        if (string.IsNullOrWhiteSpace(procName) && pid > 0)
        {
            procName = ResolveProcessName(pid);
        }

        bool correlated = false;
        string? dnsHost = null;
        if (!isDns && _recentDnsHosts.TryGetValue(uri.Host, out var dnsRec))
        {
            correlated = true;
            dnsHost = uri.Host;
            if (pid <= 0 && dnsRec.pid > 0) pid = dnsRec.pid;
            if (string.IsNullOrEmpty(procName) && !string.IsNullOrEmpty(dnsRec.procName)) procName = dnsRec.procName;
        }

        if (remotePort == 0) remotePort = uri.Port;
        if (string.IsNullOrEmpty(endpoint)) endpoint = $"{uri.Host}:{remotePort}";

        var info = new CapturedUrlInfo
        {
            Url = url,
            Host = uri.Host,
            PathAndQuery = uri.PathAndQuery,
            Fragment = uri.Fragment,
            Scheme = uri.Scheme.ToUpperInvariant(),
            Method = method,
            ProcessName = string.IsNullOrWhiteSpace(procName) ? "NetworkTraffic" : procName,
            ProcessId = pid,
            SourceTag = sourceTag,
            Timestamp = now,
            WasDnsCorrelated = correlated,
            CorrelatedDnsHost = dnsHost,
            RemotePort = remotePort,
            RemoteEndpoint = endpoint
        };

        OnUrlCaptured?.Invoke(info);
        if (correlated && dnsHost != null)
        {
            OnDnsCorrelated?.Invoke(info, dnsHost);
        }

        ulong seq = Interlocked.Increment(ref _sequence);
        byte[] payloadBytes = Encoding.UTF8.GetBytes(url);

        var rawEvent = RawCaptureEvent.Create(
            sequence: seq,
            sensor: SensorType.Network,
            transport: TransportType.TCP,
            direction: PacketDirection.HOST_TO_DEVICE,
            device: uri.Host,
            session: $"{procName}_{pid}",
            iface: 0,
            endpoint: remotePort.ToString(),
            payload: payloadBytes
        );

        rawEvent.Metadata["Url"] = url;
        rawEvent.Metadata["Host"] = uri.Host;
        rawEvent.Metadata["Path"] = uri.PathAndQuery;
        rawEvent.Metadata["PathAndQuery"] = uri.PathAndQuery;
        rawEvent.Metadata["Fragment"] = uri.Fragment;
        rawEvent.Metadata["ProcessName"] = info.ProcessName;
        rawEvent.Metadata["ProcessId"] = pid.ToString();
        rawEvent.Metadata["SourceTag"] = sourceTag;
        rawEvent.Metadata["Method"] = method;
        rawEvent.Metadata["IsDns"] = isDns.ToString();
        if (correlated && dnsHost != null)
        {
            rawEvent.Metadata["CorrelatedFromDns"] = "True";
            rawEvent.Metadata["CorrelatedDnsHost"] = dnsHost;
        }

        _bus.Publish(rawEvent);
    }

    public static string ResolveProcessName(int pid)
    {
        if (pid <= 0) return "System";
        if (_procNameCache.TryGetValue(pid, out var cached)) return cached;
        try
        {
            using var proc = Process.GetProcessById(pid);
            string name = proc.ProcessName;
            _procNameCache[pid] = name;
            return name;
        }
        catch
        {
            return $"PID:{pid}";
        }
    }

    public static List<string> ExtractUrls(string text) => ShellCommandParser.ExtractUrls(text);

    public void RecordDnsResolution(string host, string procName = "", int pid = 0)
    {
        if (string.IsNullOrWhiteSpace(host)) return;
        host = host.TrimEnd('.');
        _recentDnsHosts[host] = (pid, procName, DateTime.UtcNow);
    }

    public bool IsHostCorrelatedFromDns(string host)
    {
        return !string.IsNullOrWhiteSpace(host) && _recentDnsHosts.ContainsKey(host.TrimEnd('.'));
    }

    public List<string> GetRecentDnsHosts() => new(_recentDnsHosts.Keys);

    public void SimulateUrlCapture(string url, string procName = "GSM_Tool.exe", int pid = 1234, string sourceTag = "SIM-NET")
    {
        IngestCapturedUrl(url, procName, pid, sourceTag);
    }
    #endregion
}
