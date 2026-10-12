using System;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;

namespace PhoenixGSM.OmniTrace.Sensors;

public sealed partial class NetworkUrlSensor
{
    #region ETW Session
    private void StartEtwSession()
    {
        try
        {
            bool? isElevated = TraceEventSession.IsElevated();
            if (isElevated == false)
            {
                _lastError = "Administrator privileges required to start real-time Net ETW session.";
                return;
            }

            try
            {
                var existing = TraceEventSession.GetActiveSession(SessionName);
                if (existing != null)
                {
                    existing.Stop();
                    existing.Dispose();
                }
            }
            catch { }

            _session = new TraceEventSession(SessionName, TraceEventSessionOptions.Create)
            {
                BufferSizeMB = 32
            };

            // Enable WinHTTP, WinINet, WebIO without restrictive keyword filtering to get ALL URL requests
            _session.EnableProvider(WinHttpProviderGuid, TraceEventLevel.Verbose);
            _session.EnableProvider(WinInetProviderGuid, TraceEventLevel.Verbose);
            _session.EnableProvider(WebIoProviderGuid, TraceEventLevel.Verbose);
            _session.EnableProvider(DnsClientProviderGuid, TraceEventLevel.Verbose);

            // Enable .NET HttpClient and Sockets for modern Windows GSM tools
            try { _session.EnableProvider(SystemNetHttpProviderGuid, TraceEventLevel.Informational); } catch { }
            try { _session.EnableProvider(SystemNetSocketsProviderGuid, TraceEventLevel.Informational); } catch { }
            try { _session.EnableProvider(TcpIpProviderGuid, TraceEventLevel.Informational); } catch { }

            _session.Source.Dynamic.All += HandleTraceEvent;

            _processingTask = Task.Factory.StartNew(() =>
            {
                try
                {
                    _session.Source.Process();
                }
                catch (Exception ex)
                {
                    if (_isRunning)
                    {
                        Interlocked.Increment(ref _errorsCount);
                        _lastError = ex.Message;
                    }
                }
            }, TaskCreationOptions.LongRunning);
        }
        catch (Exception ex)
        {
            Interlocked.Increment(ref _errorsCount);
            _lastError = ex.Message;
        }
    }

    private void HandleTraceEvent(TraceEvent data)
    {
        Interlocked.Increment(ref _eventsReceived);

        try
        {
            int pid = data.ProcessID;
            if (pid <= 4 || pid == Environment.ProcessId) return;

            string procName = data.ProcessName ?? "";
            if (string.IsNullOrWhiteSpace(procName) && pid > 0)
            {
                procName = ResolveProcessName(pid);
            }

            if (data.ProviderGuid == WinHttpProviderGuid)
            {
                ExtractFromWinHttp(data, procName, pid);
                return;
            }

            if (data.ProviderGuid == WinInetProviderGuid)
            {
                ExtractFromWinInet(data, procName, pid);
                return;
            }

            if (data.ProviderGuid == WebIoProviderGuid)
            {
                ExtractFromWebIo(data, procName, pid);
                return;
            }

            if (data.ProviderGuid == DnsClientProviderGuid)
            {
                ExtractFromDnsClient(data, procName, pid);
                return;
            }

            if (data.ProviderGuid == SystemNetHttpProviderGuid)
            {
                ExtractFromDotNetHttp(data, procName, pid);
                return;
            }

            // General payload scan for any URL
            ScanPayloadForUrls(data, procName, pid, "ETW-NET");
        }
        catch { }
    }

    private void ExtractFromWinHttp(TraceEvent data, string procName, int pid)
    {
        string? url = null;
        string? server = null;
        string? path = null;
        ulong handle = 0;

        for (int i = 0; i < data.PayloadNames.Length; i++)
        {
            string name = data.PayloadNames[i];
            object val = data.PayloadValue(i);
            if (val == null) continue;
            string strVal = val.ToString() ?? "";

            if (name.Equals("Url", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("URI", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("pwszUrl", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("szUrl", StringComparison.OrdinalIgnoreCase))
            {
                url = strVal;
            }
            else if (name.Equals("ServerName", StringComparison.OrdinalIgnoreCase) ||
                     name.Equals("Server", StringComparison.OrdinalIgnoreCase) ||
                     name.Equals("Host", StringComparison.OrdinalIgnoreCase) ||
                     name.Equals("pwszServerName", StringComparison.OrdinalIgnoreCase) ||
                     name.Equals("szServerName", StringComparison.OrdinalIgnoreCase))
            {
                server = strVal;
            }
            else if (name.Equals("Path", StringComparison.OrdinalIgnoreCase) ||
                     name.Equals("Resource", StringComparison.OrdinalIgnoreCase) ||
                     name.Equals("ObjectName", StringComparison.OrdinalIgnoreCase) ||
                     name.Equals("pwszObjectName", StringComparison.OrdinalIgnoreCase) ||
                     name.Equals("szObjectName", StringComparison.OrdinalIgnoreCase) ||
                     name.Equals("pwszPath", StringComparison.OrdinalIgnoreCase))
            {
                path = strVal;
            }
            else if (name.Contains("Handle", StringComparison.OrdinalIgnoreCase))
            {
                if (ulong.TryParse(strVal, out var h)) handle = h;
            }
            else if (UrlRegex.IsMatch(strVal))
            {
                url = UrlRegex.Match(strVal).Value;
            }
        }

        if (!string.IsNullOrWhiteSpace(server))
        {
            _activeServersByPid[pid] = server;
            if (handle > 0) _activeServersByHandle[handle] = server;
        }
        else
        {
            if (handle > 0 && _activeServersByHandle.TryGetValue(handle, out var hServer))
            {
                server = hServer;
            }
            else if (_activeServersByPid.TryGetValue(pid, out var pServer))
            {
                server = pServer;
            }
        }

        if (string.IsNullOrWhiteSpace(url) && !string.IsNullOrWhiteSpace(server))
        {
            path = string.IsNullOrWhiteSpace(path) ? "/" : (path.StartsWith('/') ? path : "/" + path);
            url = server.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                  server.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
                ? $"{server.TrimEnd('/')}{path}"
                : $"https://{server.TrimEnd('/')}{path}";
        }

        if (!string.IsNullOrWhiteSpace(url))
        {
            IngestCapturedUrl(url, procName, pid, "WINHTTP");
        }
    }

    private void ExtractFromWinInet(TraceEvent data, string procName, int pid)
    {
        string? url = null;
        string? server = null;
        string? path = null;

        for (int i = 0; i < data.PayloadNames.Length; i++)
        {
            string name = data.PayloadNames[i];
            object val = data.PayloadValue(i);
            if (val == null) continue;
            string strVal = val.ToString() ?? "";

            if (name.Equals("URL", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("Url", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("pwszUrl", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("szUrl", StringComparison.OrdinalIgnoreCase))
            {
                url = strVal;
            }
            else if (name.Equals("ServerName", StringComparison.OrdinalIgnoreCase) ||
                     name.Equals("Server", StringComparison.OrdinalIgnoreCase) ||
                     name.Equals("Host", StringComparison.OrdinalIgnoreCase) ||
                     name.Equals("pwszServerName", StringComparison.OrdinalIgnoreCase) ||
                     name.Equals("szServerName", StringComparison.OrdinalIgnoreCase))
            {
                server = strVal;
            }
            else if (name.Equals("Path", StringComparison.OrdinalIgnoreCase) ||
                     name.Equals("Resource", StringComparison.OrdinalIgnoreCase) ||
                     name.Equals("ObjectName", StringComparison.OrdinalIgnoreCase) ||
                     name.Equals("pwszObjectName", StringComparison.OrdinalIgnoreCase) ||
                     name.Equals("szObjectName", StringComparison.OrdinalIgnoreCase) ||
                     name.Equals("pwszPath", StringComparison.OrdinalIgnoreCase))
            {
                path = strVal;
            }
            else if (UrlRegex.IsMatch(strVal))
            {
                url = UrlRegex.Match(strVal).Value;
            }
        }

        if (string.IsNullOrWhiteSpace(url) && !string.IsNullOrWhiteSpace(server))
        {
            path = string.IsNullOrWhiteSpace(path) ? "/" : (path.StartsWith('/') ? path : "/" + path);
            url = server.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                  server.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
                ? $"{server.TrimEnd('/')}{path}"
                : $"https://{server.TrimEnd('/')}{path}";
        }

        if (!string.IsNullOrWhiteSpace(url))
        {
            IngestCapturedUrl(url, procName, pid, "WININET");
        }
    }

    private void ExtractFromWebIo(TraceEvent data, string procName, int pid)
    {
        string? url = null;
        string? server = null;
        string? path = null;

        for (int i = 0; i < data.PayloadNames.Length; i++)
        {
            string name = data.PayloadNames[i];
            object val = data.PayloadValue(i);
            if (val == null) continue;
            string strVal = val.ToString() ?? "";

            if (name.Equals("URL", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("Url", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("URI", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("pwszUrl", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("szUrl", StringComparison.OrdinalIgnoreCase))
            {
                url = strVal;
            }
            else if (name.Equals("ServerName", StringComparison.OrdinalIgnoreCase) ||
                     name.Equals("Server", StringComparison.OrdinalIgnoreCase) ||
                     name.Equals("Host", StringComparison.OrdinalIgnoreCase) ||
                     name.Equals("pwszServerName", StringComparison.OrdinalIgnoreCase) ||
                     name.Equals("szServerName", StringComparison.OrdinalIgnoreCase))
            {
                server = strVal;
            }
            else if (name.Equals("Path", StringComparison.OrdinalIgnoreCase) ||
                     name.Equals("Resource", StringComparison.OrdinalIgnoreCase) ||
                     name.Equals("ObjectName", StringComparison.OrdinalIgnoreCase) ||
                     name.Equals("pwszObjectName", StringComparison.OrdinalIgnoreCase) ||
                     name.Equals("szObjectName", StringComparison.OrdinalIgnoreCase) ||
                     name.Equals("pwszPath", StringComparison.OrdinalIgnoreCase))
            {
                path = strVal;
            }
            else if (UrlRegex.IsMatch(strVal))
            {
                url = UrlRegex.Match(strVal).Value;
            }
        }

        if (string.IsNullOrWhiteSpace(url) && !string.IsNullOrWhiteSpace(server))
        {
            path = string.IsNullOrWhiteSpace(path) ? "/" : (path.StartsWith('/') ? path : "/" + path);
            url = server.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                  server.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
                ? $"{server.TrimEnd('/')}{path}"
                : $"https://{server.TrimEnd('/')}{path}";
        }

        if (!string.IsNullOrWhiteSpace(url))
        {
            IngestCapturedUrl(url, procName, pid, "WEBIO");
        }
    }

    private void ExtractFromDotNetHttp(TraceEvent data, string procName, int pid)
    {
        for (int i = 0; i < data.PayloadNames.Length; i++)
        {
            object val = data.PayloadValue(i);
            if (val == null) continue;
            string strVal = val.ToString() ?? "";
            if (UrlRegex.IsMatch(strVal))
            {
                string url = UrlRegex.Match(strVal).Value;
                IngestCapturedUrl(url, procName, pid, ".NET-HTTP");
            }
        }
    }

    private void ScanPayloadForUrls(TraceEvent data, string procName, int pid, string sourceTag)
    {
        for (int i = 0; i < data.PayloadNames.Length; i++)
        {
            object val = data.PayloadValue(i);
            if (val == null) continue;
            string strVal = val.ToString() ?? "";
            if (strVal.Length > 8 && UrlRegex.IsMatch(strVal))
            {
                string url = UrlRegex.Match(strVal).Value;
                IngestCapturedUrl(url, procName, pid, sourceTag);
            }
        }
    }

    private void ExtractFromDnsClient(TraceEvent data, string procName, int pid)
    {
        string? queryName = null;
        string? queryResults = null;

        for (int i = 0; i < data.PayloadNames.Length; i++)
        {
            string name = data.PayloadNames[i];
            object val = data.PayloadValue(i);
            if (val == null) continue;
            string strVal = val.ToString() ?? "";

            if (name.Equals("QueryName", StringComparison.OrdinalIgnoreCase))
            {
                queryName = strVal;
            }
            else if (name.Equals("QueryResults", StringComparison.OrdinalIgnoreCase) ||
                     name.Equals("Address", StringComparison.OrdinalIgnoreCase))
            {
                queryResults = strVal;
            }
            else if (name.Equals("ClientPID", StringComparison.OrdinalIgnoreCase) ||
                     name.Equals("ClientProcessId", StringComparison.OrdinalIgnoreCase))
            {
                if (int.TryParse(strVal, out var cPid) && cPid > 0)
                {
                    pid = cPid;
                    procName = ResolveProcessName(pid);
                }
            }
        }

        if (!string.IsNullOrWhiteSpace(queryName))
        {
            queryName = queryName.TrimEnd('.');
            if (queryName.EndsWith(".local", StringComparison.OrdinalIgnoreCase) ||
                queryName.EndsWith(".lan", StringComparison.OrdinalIgnoreCase) ||
                queryName.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
                queryName.Contains("wpad", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            if (string.IsNullOrWhiteSpace(procName) && pid > 0)
            {
                procName = ResolveProcessName(pid);
            }

            // Map IP addresses returned in queryResults to this domain name
            if (!string.IsNullOrWhiteSpace(queryResults))
            {
                var ipMatches = Regex.Matches(queryResults, @"\b(?:\d{1,3}\.){3}\d{1,3}\b");
                foreach (Match m in ipMatches)
                {
                    _ipToHostMap[m.Value] = queryName;
                }
            }

            _recentDnsHosts[queryName] = (pid, procName, DateTime.UtcNow);
            Interlocked.Increment(ref _dnsQueriesCaptured);
            string pseudoUrl = $"https://{queryName}/";
            IngestCapturedUrl(pseudoUrl, procName, pid, "DNS-QUERY", isDns: true, method: "DNS");
        }
    }
    #endregion
}
