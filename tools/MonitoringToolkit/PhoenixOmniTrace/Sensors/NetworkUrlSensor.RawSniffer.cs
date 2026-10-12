using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace PhoenixGSM.OmniTrace.Sensors;

public sealed partial class NetworkUrlSensor
{
    #region Promiscuous Raw IP Packet Sniffer (SIO_RCVALL for HTTP & TLS SNI)
    private async Task RawPacketSnifferLoop(CancellationToken token)
    {
        var sockets = new List<Socket>();
        var tasks = new List<Task>();

        try
        {
            var hostEntry = await Dns.GetHostEntryAsync(Dns.GetHostName(), token).ConfigureAwait(false);
            
            foreach (var ip in hostEntry.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(ip))
                {
                    try
                    {
                        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
                        socket.Bind(new IPEndPoint(ip, 0));
                        byte[] inValue = [1, 0, 0, 0];
                        byte[] outValue = new byte[4];
                        socket.IOControl(IOControlCode.ReceiveAll, inValue, outValue);
                        
                        sockets.Add(socket);
                        tasks.Add(Task.Run(() => ReadFromRawSocket(socket, token), token));
                    }
                    catch
                    {
                        // Ignore bind failures (e.g. no admin rights for raw sockets on this interface)
                    }
                }
            }

            if (tasks.Count > 0)
            {
                await Task.WhenAll(tasks).ConfigureAwait(false);
            }
        }
        catch
        {
            // Fail-open: raw socket is optional supplemental vector
        }
        finally
        {
            foreach (var s in sockets)
            {
                try { s.Dispose(); } catch { }
            }
        }
    }

    private async Task ReadFromRawSocket(Socket socket, CancellationToken token)
    {
        byte[] buffer = new byte[65535];
        while (!token.IsCancellationRequested)
        {
            try
            {
                int received = await socket.ReceiveAsync(buffer, SocketFlags.None, token).ConfigureAwait(false);
                if (received > 20)
                {
                    ProcessRawIpPacket(buffer, received);
                }
            }
            catch
            {
                break; // Socket closed or error
            }
        }
    }

    private void ProcessRawIpPacket(byte[] packet, int length)
    {
        try
        {
            int ihl = (packet[0] & 0x0F) * 4;
            if (ihl < 20 || ihl >= length) return;

            byte protocol = packet[9];
            if (protocol != 6) return; // Only TCP

            var destIp = new IPAddress(new ReadOnlySpan<byte>(packet, 16, 4));
            string destIpStr = destIp.ToString();

            int tcpOffset = ihl;
            if (tcpOffset + 20 > length) return;

            int srcPort = (packet[tcpOffset] << 8) | packet[tcpOffset + 1];
            int dstPort = (packet[tcpOffset + 2] << 8) | packet[tcpOffset + 3];
            int dataOffset = ((packet[tcpOffset + 12] >> 4) & 0x0F) * 4;
            int payloadOffset = tcpOffset + dataOffset;
            int payloadLen = length - payloadOffset;

            if (payloadLen <= 0) return;

            // 1. Check for Plain HTTP Request (GET, POST, HEAD, PUT, DELETE, CONNECT)
            string verb = "GET";
            if (dstPort == 80 || dstPort == 8080 ||
                MatchesHttpVerb(packet, payloadOffset, payloadLen, out verb))
            {
                string payloadAscii = Encoding.ASCII.GetString(packet, payloadOffset, Math.Min(payloadLen, 2048));
                var match = Regex.Match(payloadAscii, @"^(GET|POST|HEAD|PUT|DELETE|CONNECT)\s+([^\s]+)\s+HTTP/[0-9\.]+", RegexOptions.IgnoreCase);
                if (match.Success)
                {
                    verb = match.Groups[1].Value.ToUpperInvariant();
                    string path = match.Groups[2].Value;
                    string host = "";
                    var hostMatch = Regex.Match(payloadAscii, @"\r\nHost:\s*([^\r\n:]+)(?::(\d+))?", RegexOptions.IgnoreCase);
                    if (hostMatch.Success)
                    {
                        host = hostMatch.Groups[1].Value.Trim();
                    }
                    if (string.IsNullOrWhiteSpace(host))
                    {
                        host = _ipToHostMap.TryGetValue(destIpStr, out var mh) ? mh : destIpStr;
                    }

                    string fullUrl = path.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                                     path.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
                        ? path
                        : $"http://{host}{path}";

                    IngestCapturedUrl(fullUrl, "NetworkTool", 0, "RAW-HTTP", method: verb, remotePort: dstPort, endpoint: $"{destIpStr}:{dstPort}");
                    return;
                }
            }

            // 2. Check for TLS ClientHello SNI Extractor (Port 443 / HTTPS)
            if ((dstPort == 443 || dstPort == 8443) && payloadLen > 44 && packet[payloadOffset] == 0x16)
            {
                string? sni = ExtractSni(packet, payloadOffset, payloadLen);
                if (!string.IsNullOrWhiteSpace(sni))
                {
                    _ipToHostMap[destIpStr] = sni;
                    string url = $"https://{sni}/";
                    IngestCapturedUrl(url, "NetworkTool", 0, "TLS-SNI", method: "HTTPS", remotePort: dstPort, endpoint: $"{destIpStr}:{dstPort}");
                }
            }
        }
        catch { }
    }

    private static bool MatchesHttpVerb(byte[] b, int offset, int len, out string verb)
    {
        verb = "GET";
        if (len < 4) return false;
        if (b[offset] == 'G' && b[offset + 1] == 'E' && b[offset + 2] == 'T' && b[offset + 3] == ' ') { verb = "GET"; return true; }
        if (len >= 5 && b[offset] == 'P' && b[offset + 1] == 'O' && b[offset + 2] == 'S' && b[offset + 3] == ' ') { verb = "POST"; return true; }
        if (len >= 5 && b[offset] == 'H' && b[offset + 1] == 'E' && b[offset + 2] == 'A' && b[offset + 3] == ' ') { verb = "HEAD"; return true; }
        if (len >= 4 && b[offset] == 'P' && b[offset + 1] == 'U' && b[offset + 2] == 'T' && b[offset + 3] == ' ') { verb = "PUT"; return true; }
        return false;
    }

    private static string? ExtractSni(byte[] payload, int offset, int length)
    {
        try
        {
            int end = offset + length;
            if (length < 44 || payload[offset] != 0x16) return null; // Not handshake
            int p = offset + 5; // Skip record header
            if (p >= end || payload[p] != 0x01) return null; // Not ClientHello
            p += 4; // Skip Handshake type and length
            p += 2; // Skip TLS version
            p += 32; // Skip Random
            if (p >= end) return null;
            int sessIdLen = payload[p++];
            p += sessIdLen;
            if (p + 2 > end) return null;
            int cipherLen = (payload[p] << 8) | payload[p + 1];
            p += 2 + cipherLen;
            if (p >= end) return null;
            int compLen = payload[p++];
            p += compLen;
            if (p + 2 > end) return null;
            int extTotalLen = (payload[p] << 8) | payload[p + 1];
            p += 2;
            int extEnd = Math.Min(p + extTotalLen, end);
            while (p + 4 <= extEnd)
            {
                int extType = (payload[p] << 8) | payload[p + 1];
                int extLen = (payload[p + 2] << 8) | payload[p + 3];
                p += 4;
                if (extType == 0) // server_name (SNI)
                {
                    if (p + 5 <= extEnd)
                    {
                        int nameType = payload[p + 2];
                        int nameLen = (payload[p + 3] << 8) | payload[p + 4];
                        if (nameType == 0 && p + 5 + nameLen <= extEnd)
                        {
                            return Encoding.ASCII.GetString(payload, p + 5, nameLen);
                        }
                    }
                }
                p += extLen;
            }
        }
        catch { }
        return null;
    }
    #endregion
}
