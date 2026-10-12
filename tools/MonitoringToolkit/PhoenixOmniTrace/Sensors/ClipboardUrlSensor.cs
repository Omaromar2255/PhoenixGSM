using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using PhoenixGSM.OmniTrace.Bus;
using PhoenixGSM.OmniTrace.Decoders;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.Sensors;

/// <summary>
/// LAYER 3E — Windows Clipboard URL Sensor
/// Monitors Windows Clipboard in real-time. When GSM tools (e.g. Q-Unlocker, UnlockTool,
/// Chimera, SamFW) initiate downloads, updates, or file acquisitions, they frequently
/// copy complete download URLs (including private Mega.nz/MediaFire/Google Drive keys and #fragments)
/// to the clipboard.
/// Operates on a resilient, low-overhead background polling/listener loop with zero-crash fail-open architecture.
/// </summary>
public sealed class ClipboardUrlSensor : IDisposable
{
    private const uint CF_UNICODETEXT = 13;

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool OpenClipboard(IntPtr hWndNewOwner);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool CloseClipboard();

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr GetClipboardData(uint uFormat);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GlobalLock(IntPtr hMem);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GlobalUnlock(IntPtr hMem);

    private readonly OmniTraceEventBus _bus;
    private CancellationTokenSource? _cts;
    private Task? _monitorTask;
    private bool _isRunning;
    private string? _lastSeenHash;
    private ulong _sequence;

    // Deduplication cache to prevent re-emitting the same URL repeatedly
    private readonly ConcurrentDictionary<string, DateTime> _seenUrls = new(StringComparer.OrdinalIgnoreCase);

    public event Action<CapturedUrlInfo>? OnUrlCaptured;

    public bool IsRunning => _isRunning;

    public ClipboardUrlSensor(OmniTraceEventBus bus)
    {
        _bus = bus ?? throw new ArgumentNullException(nameof(bus));
    }

    public void Start()
    {
        if (_isRunning) return;
        _isRunning = true;
        _cts = new CancellationTokenSource();

        _monitorTask = Task.Factory.StartNew(
            () => MonitorClipboardLoop(_cts.Token),
            TaskCreationOptions.LongRunning);
    }

    public void Stop()
    {
        if (!_isRunning) return;
        _isRunning = false;
        try
        {
            _cts?.Cancel();
            _cts?.Dispose();
            _cts = null;
        }
        catch { }
    }

    private void MonitorClipboardLoop(CancellationToken token)
    {
        while (!token.IsCancellationRequested && _isRunning)
        {
            try
            {
                CheckClipboardForUrls();
            }
            catch
            {
                // Fail-open: prevent any exception from terminating clipboard monitoring loop
            }

            try
            {
                Thread.Sleep(250); // 4Hz low-overhead polling
            }
            catch (ThreadInterruptedException) { break; }
        }
    }

    public void CheckClipboardForUrls()
    {
        string? text = ReadClipboardTextSafe();
        if (string.IsNullOrWhiteSpace(text)) return;

        // Fast hash check to skip unmodified clipboard contents
        string textHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(text)));
        if (textHash == _lastSeenHash) return;
        _lastSeenHash = textHash;

        var urls = ShellCommandParser.ExtractUrls(text);
        if (urls.Count == 0) return;

        (string procName, int pid) = GetForegroundProcessInfo();

        DateTime now = DateTime.UtcNow;

        foreach (var url in urls)
        {
            if (string.IsNullOrWhiteSpace(url)) continue;

            string dedupKey = $"{pid}:{url}";
            if (_seenUrls.TryGetValue(dedupKey, out var expiry) && now < expiry)
            {
                continue;
            }
            _seenUrls[dedupKey] = now.AddSeconds(10);

            IngestClipboardUrl(url, procName, pid, "CLIPBOARD");
        }
    }

    public void IngestClipboardUrl(string url, string procName, int pid, string sourceTag)
    {
        if (string.IsNullOrWhiteSpace(url)) return;

        Uri uri;
        try { uri = new Uri(url); } catch { return; }

        DateTime now = DateTime.UtcNow;

        var info = new CapturedUrlInfo
        {
            Url = url,
            Host = uri.Host,
            PathAndQuery = uri.PathAndQuery,
            Scheme = uri.Scheme.ToUpperInvariant(),
            Method = "CLIPBOARD",
            ProcessName = procName,
            ProcessId = pid,
            SourceTag = sourceTag,
            Timestamp = now
        };

        OnUrlCaptured?.Invoke(info);

        ulong seq = Interlocked.Increment(ref _sequence);
        var rawEvent = RawCaptureEvent.Create(
            sequence: seq,
            sensor: SensorType.Network,
            transport: TransportType.TCP,
            direction: PacketDirection.HOST_TO_DEVICE,
            device: uri.Host,
            session: $"{procName}_{pid}",
            iface: 0,
            endpoint: uri.Port.ToString(),
            payload: Encoding.UTF8.GetBytes(url)
        );

        rawEvent.Metadata["Url"] = url;
        rawEvent.Metadata["Host"] = uri.Host;
        rawEvent.Metadata["Path"] = uri.PathAndQuery;
        rawEvent.Metadata["ProcessName"] = procName;
        rawEvent.Metadata["ProcessId"] = pid.ToString();
        rawEvent.Metadata["SourceTag"] = sourceTag;
        rawEvent.Metadata["IsClipboard"] = "True";

        _bus.Publish(rawEvent);
    }

    private static string? ReadClipboardTextSafe()
    {
        if (!OpenClipboard(IntPtr.Zero)) return null;

        try
        {
            IntPtr hData = GetClipboardData(CF_UNICODETEXT);
            if (hData == IntPtr.Zero) return null;

            IntPtr pText = GlobalLock(hData);
            if (pText == IntPtr.Zero) return null;

            try
            {
                return Marshal.PtrToStringUni(pText);
            }
            finally
            {
                GlobalUnlock(hData);
            }
        }
        finally
        {
            CloseClipboard();
        }
    }

    private static (string procName, int pid) GetForegroundProcessInfo()
    {
        try
        {
            IntPtr hwnd = GetForegroundWindow();
            if (hwnd == IntPtr.Zero) return ("System", 0);

            GetWindowThreadProcessId(hwnd, out uint pid);
            if (pid == 0) return ("System", 0);

            using var proc = Process.GetProcessById((int)pid);
            return (proc.ProcessName + ".exe", (int)pid);
        }
        catch
        {
            return ("Unknown.exe", 0);
        }
    }

    public void Dispose()
    {
        Stop();
    }
}
