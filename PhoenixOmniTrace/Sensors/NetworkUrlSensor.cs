using System;
using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing.Session;
using PhoenixGSM.OmniTrace.Bus;

namespace PhoenixGSM.OmniTrace.Sensors;

/// <summary>
/// LAYER 3D — Autonomous Multi-Vector Network Interceptor.
/// Combines 4 complementary monitoring layers to ensure 100% of network requests, links,
/// and connections across all GSM tools, browsers, curl, and background processes are captured:
/// 1. Windows Real-Time ETW (WinHTTP, WinINet, WebIO, DNS-Client, System.Net.Http, TCPIP).
/// 2. Active Kernel TCP Connection Watcher (GetExtendedTcpTable) attributing all sockets to PID & Process.
/// 3. Promiscuous Raw IP Packet Sniffer (SIO_RCVALL) extracting plain HTTP URLs (Host + Path).
/// 4. TLS ClientHello SNI Extractor revealing HTTPS domain targets before TLS encryption.
/// </summary>
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public sealed partial class NetworkUrlSensor : IDisposable
{
    public static readonly Guid WinHttpProviderGuid = new("7D44233D-3055-4B9C-BA64-0D47CA40A232");
    public static readonly Guid WinInetProviderGuid = new("43D1A55C-76D6-4F7E-995C-64C711E5CAFE");
    public static readonly Guid WebIoProviderGuid = new("50BCD9A3-8080-4BEF-A397-62F764B86A41");
    public static readonly Guid DnsClientProviderGuid = new("1C95126E-7EEA-49A9-A3FE-A378B03DDB4D");
    public static readonly Guid SystemNetHttpProviderGuid = new("4E7E8606-9602-5B49-B28A-F85C77DEB64C");
    public static readonly Guid SystemNetSocketsProviderGuid = new("0E4D5174-297C-56BE-05F2-243A70258160");
    public static readonly Guid TcpIpProviderGuid = new("2F07E2E4-90E3-496B-9CC8-876D344E0B49");

    public const string DefaultSessionName = "Microsoft-Windows-Net-Diagnostics-Session";

    private static readonly Regex UrlRegex = new(
        @"https?://[a-zA-Z0-9\-\._~:/\?#\[\]@!\$&'\(\)\*\+,;=%]+",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private readonly OmniTraceEventBus _bus;
    private TraceEventSession? _session;
    private Task? _processingTask;
    private Task? _tcpWatcherTask;
    private Task? _rawSnifferTask;
    private CancellationTokenSource? _cts;
    private bool _isRunning;
    private ulong _sequence;

    // Deduplication cache: key = $"{pid}:{url}:{sourceTag}", value = expiration time
    private readonly ConcurrentDictionary<string, DateTime> _recentUrls = new(StringComparer.OrdinalIgnoreCase);

    // Active TCP connection tracking: key = $"{pid}:{localPort}->{remoteIp}:{remotePort}"
    private readonly ConcurrentDictionary<string, DateTime> _activeTcpConnections = new(StringComparer.OrdinalIgnoreCase);

    // DNS host and IP bidirectional mapping
    private readonly ConcurrentDictionary<string, string> _ipToHostMap = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, (int pid, string procName, DateTime timestamp)> _recentDnsHosts = new(StringComparer.OrdinalIgnoreCase);

    // Stateful WinHTTP/WinINet session reassembly
    private readonly ConcurrentDictionary<int, string> _activeServersByPid = new();
    private readonly ConcurrentDictionary<ulong, string> _activeServersByHandle = new();

    // Process name lookup cache
    private static readonly ConcurrentDictionary<int, string> _procNameCache = new();

    // Observability metrics
    private long _urlsCaptured;
    private long _dnsQueriesCaptured;
    private long _tcpConnectionsCaptured;
    private long _eventsReceived;
    private long _errorsCount;
    private string? _lastError;

    public string SessionName { get; }
    public bool IsRunning => _isRunning;
    public long UrlsCaptured => Interlocked.Read(ref _urlsCaptured);
    public long DnsQueriesCaptured => Interlocked.Read(ref _dnsQueriesCaptured);
    public long TcpConnectionsCaptured => Interlocked.Read(ref _tcpConnectionsCaptured);
    public long EventsReceived => Interlocked.Read(ref _eventsReceived);
    public long ErrorsCount => Interlocked.Read(ref _errorsCount);
    public string? LastError => _lastError;

    public event Action<CapturedUrlInfo>? OnUrlCaptured;
    public event Action<CapturedUrlInfo, string>? OnDnsCorrelated;

    public NetworkUrlSensor(OmniTraceEventBus bus, string sessionName = DefaultSessionName)
    {
        _bus = bus ?? throw new ArgumentNullException(nameof(bus));
        SessionName = sessionName;
    }

    public void Start()
    {
        if (_isRunning) return;
        _cts = new CancellationTokenSource();
        var token = _cts.Token;

        // 1. Start Windows ETW Session (WinHTTP, WebIO, WinINet, DNS-Client, System.Net.Http)
        StartEtwSession();

        // 2. Start Active Kernel TCP Connection Watcher (GetExtendedTcpTable)
        _tcpWatcherTask = Task.Run(() => TcpConnectionWatcherLoop(token), token);

        // 3. Start Promiscuous Raw IP Packet Sniffer (SIO_RCVALL for HTTP & TLS SNI)
        _rawSnifferTask = Task.Run(() => RawPacketSnifferLoop(token), token);

        _isRunning = true;
    }

    public void Stop()
    {
        if (!_isRunning) return;
        _isRunning = false;

        try
        {
            _cts?.Cancel();
            _session?.Stop();
            _session?.Dispose();
            _session = null;
        }
        catch { }
    }

    public void Dispose()
    {
        Stop();
    }
}
