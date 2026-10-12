using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace PhoenixGSM.OmniTrace.Sensors;

public sealed partial class NetworkUrlSensor
{
    #region Active Kernel TCP Connection Watcher (GetExtendedTcpTable)
    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int pdwSize,
        bool bOrder,
        int ulAf,
        int tableClass,
        uint reserved);

    private const int AF_INET = 2;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;

    private async Task TcpConnectionWatcherLoop(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                PollActiveTcpConnections();
            }
            catch { }

            try
            {
                await Task.Delay(100, token).ConfigureAwait(false);
            }
            catch { break; }
        }
    }

    private void PollActiveTcpConnections()
    {
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (size <= 0) return;

        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buffer, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == 0)
            {
                int count = Marshal.ReadInt32(buffer);
                IntPtr rowPtr = IntPtr.Add(buffer, 4);

                for (int i = 0; i < count; i++)
                {
                    uint state = (uint)Marshal.ReadInt32(rowPtr, 0);
                    // state: 3 = SYN_SENT, 4 = SYN_RCVD, 5 = ESTABLISHED
                    if (state == 3 || state == 4 || state == 5)
                    {
                        byte p1 = Marshal.ReadByte(rowPtr, 8);
                        byte p2 = Marshal.ReadByte(rowPtr, 9);
                        int localPort = (p1 << 8) | p2;

                        uint remoteAddr = (uint)Marshal.ReadInt32(rowPtr, 12);
                        byte rp1 = Marshal.ReadByte(rowPtr, 16);
                        byte rp2 = Marshal.ReadByte(rowPtr, 17);
                        int remotePort = (rp1 << 8) | rp2;

                        int pid = Marshal.ReadInt32(rowPtr, 20);

                        // Exclude self and system idle
                        if (pid > 4 && pid != Environment.ProcessId && remotePort > 0)
                        {
                            var rIp = new IPAddress(remoteAddr);
                            string rIpStr = rIp.ToString();

                            // Filter out loopback / local subnet broadcast
                            if (!IPAddress.IsLoopback(rIp) && !rIpStr.StartsWith("0.") && !rIpStr.StartsWith("127."))
                            {
                                string connKey = $"{pid}:{localPort}->{rIpStr}:{remotePort}";
                                DateTime now = DateTime.UtcNow;

                                if (!_activeTcpConnections.TryGetValue(connKey, out var exp) || now > exp)
                                {
                                    _activeTcpConnections[connKey] = now.AddSeconds(15);
                                    Interlocked.Increment(ref _tcpConnectionsCaptured);

                                    // Resolve Host: prefer DNS mapping, fallback to IP
                                    string host = _ipToHostMap.TryGetValue(rIpStr, out var mappedHost) ? mappedHost : rIpStr;
                                    string scheme = remotePort == 443 ? "HTTPS" : (remotePort == 80 ? "HTTP" : "TCP");
                                    string method = remotePort == 443 ? "HTTPS" : (remotePort == 80 ? "HTTP" : "CONNECT");
                                    string url = remotePort == 443 ? $"https://{host}/" : (remotePort == 80 ? $"http://{host}/" : $"{scheme.ToLower()}://{host}:{remotePort}/");
                                    string procName = ResolveProcessName(pid);

                                    var info = new CapturedUrlInfo
                                    {
                                        Url = url,
                                        Host = host,
                                        PathAndQuery = "/",
                                        Scheme = scheme,
                                        Method = method,
                                        ProcessName = procName,
                                        ProcessId = pid,
                                        SourceTag = "NET-CONN",
                                        Timestamp = now,
                                        RemotePort = remotePort,
                                        RemoteEndpoint = $"{rIpStr}:{remotePort}"
                                    };

                                    IngestCapturedUrl(url, procName, pid, "NET-CONN", isDns: false, method: method, remotePort: remotePort, endpoint: $"{rIpStr}:{remotePort}");

                                    // Async reverse DNS resolution if IP is bare
                                    if (host == rIpStr)
                                    {
                                        _ = Task.Run(async () =>
                                        {
                                            try
                                            {
                                                var entry = await Dns.GetHostEntryAsync(rIp).ConfigureAwait(false);
                                                if (!string.IsNullOrWhiteSpace(entry.HostName))
                                                {
                                                    _ipToHostMap[rIpStr] = entry.HostName;
                                                }
                                            }
                                            catch { }
                                        });
                                    }
                                }
                            }
                        }
                    }

                    rowPtr = IntPtr.Add(rowPtr, 24);
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        // Prune old connections
        if (_activeTcpConnections.Count > 1000)
        {
            var now = DateTime.UtcNow;
            foreach (var kvp in _activeTcpConnections)
            {
                if (now > kvp.Value) _activeTcpConnections.TryRemove(kvp.Key, out _);
            }
        }
    }
    #endregion
}
