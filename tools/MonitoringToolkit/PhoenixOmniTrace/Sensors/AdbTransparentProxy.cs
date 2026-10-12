using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using PhoenixGSM.OmniTrace.Bus;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.Sensors;

/// <summary>
/// LAYER 2A — Byte-Transparent ADB Proxy
/// Intercepts ADB host-side communication without modifying data, timing, or half-close semantics.
/// Every chunk is published as RawCaptureEvent to the Event Bus.
/// Enforces true TCP half-close: shutting down send-side upon EOF.
/// </summary>
public sealed class AdbTransparentProxy : IDisposable
{
    private readonly OmniTraceEventBus _bus;
    private readonly int _listenPort;
    private readonly int _targetPort;
    private TcpListener? _listener;
    private CancellationTokenSource? _cts;
    private ulong _sequenceCounter = 100000;

    public bool IsRunning { get; private set; }
    public bool IsPortBoundByAnotherProcess { get; private set; }
    public string StatusMessage { get; private set; } = "Not Started";

    public AdbTransparentProxy(OmniTraceEventBus bus, int listenPort = 5038, int targetPort = 5037)
    {
        _bus = bus;
        _listenPort = listenPort;
        _targetPort = targetPort;
    }

    public static int DiscoverAdbServerPort()
    {
        string? envPort = Environment.GetEnvironmentVariable("ANDROID_ADB_SERVER_PORT");
        if (!string.IsNullOrEmpty(envPort) && int.TryParse(envPort, out int p))
        {
            return p;
        }

        string? socketEnv = Environment.GetEnvironmentVariable("ADB_SERVER_SOCKET");
        if (!string.IsNullOrEmpty(socketEnv) && socketEnv.StartsWith("tcp:", StringComparison.OrdinalIgnoreCase))
        {
            var parts = socketEnv.Split(':');
            if (parts.Length >= 3 && int.TryParse(parts[2], out int sp))
            {
                return sp;
            }
        }

        return 5037;
    }

    public void Start()
    {
        if (IsRunning) return;

        _cts = new CancellationTokenSource();
        try
        {
            _listener = new TcpListener(IPAddress.Loopback, _listenPort);
            _listener.Start();
            IsRunning = true;
            IsPortBoundByAnotherProcess = false;
            StatusMessage = $"Listening on 127.0.0.1:{_listenPort}, proxying to {_targetPort}";
            _ = Task.Run(() => AcceptClientsAsync(_cts.Token), _cts.Token);
        }
        catch (SocketException sex) when (sex.SocketErrorCode == SocketError.AddressAlreadyInUse || 
                                          sex.NativeErrorCode == 10048 || 
                                          sex.SocketErrorCode == SocketError.AccessDenied)
        {
            // Fail-open: Port 5037 is already held by an active tool (e.g., Global Unlocker or adb server).
            // Do NOT kill foreign processes and do NOT crash.
            // Mark state, report anomaly, and let other sensors (ETW, Process, USB) capture without interference.
            IsPortBoundByAnotherProcess = true;
            IsRunning = false;
            _listener = null;
            StatusMessage = $"Fail-Open: Port {_listenPort} is already bound by another process (SocketError={sex.SocketErrorCode}). Bypassing TCP proxy to preserve workflow.";
            _bus.ReportAnomaly("ADB_PROXY_PORT_BOUND", StatusMessage);
        }
        catch (Exception ex)
        {
            IsRunning = false;
            _listener = null;
            StatusMessage = $"Fail-Open: Failed to bind ADB proxy on port {_listenPort}: {ex.Message}";
            _bus.ReportAnomaly("ADB_PROXY_START_ERROR", StatusMessage);
        }
    }

    private async Task AcceptClientsAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested && _listener != null)
        {
            try
            {
                var client = await _listener.AcceptTcpClientAsync(token).ConfigureAwait(false);
                _ = Task.Run(() => HandleClientSessionAsync(client, token), token);
            }
            catch (OperationCanceledException) { break; }
            catch { }
        }
    }

    private async Task HandleClientSessionAsync(TcpClient client, CancellationToken token)
    {
        string session = Guid.NewGuid().ToString("N");
        using var target = new TcpClient();

        try
        {
            await target.ConnectAsync(IPAddress.Loopback, _targetPort, token).ConfigureAwait(false);
            using var clientStream = client.GetStream();
            using var targetStream = target.GetStream();

            var c2t = ForwardStreamAsync(client, target, clientStream, targetStream, PacketDirection.HOST_TO_DEVICE, session, token);
            var t2c = ForwardStreamAsync(target, client, targetStream, clientStream, PacketDirection.DEVICE_TO_HOST, session, token);

            await Task.WhenAll(c2t, t2c).ConfigureAwait(false);
        }
        catch { }
        finally
        {
            client.Dispose();
        }
    }

    private async Task ForwardStreamAsync(
        TcpClient sourceClient,
        TcpClient destClient,
        NetworkStream source,
        NetworkStream destination,
        PacketDirection direction,
        string session,
        CancellationToken token)
    {
        byte[] buffer = new byte[8192];
        try
        {
            while (!token.IsCancellationRequested)
            {
                int read = await source.ReadAsync(buffer.AsMemory(0, buffer.Length), token).ConfigureAwait(false);
                if (read <= 0)
                {
                    // Half-close semantics: notify target that source has finished transmitting
                    try
                    {
                        destClient.Client.Shutdown(SocketShutdown.Send);
                    }
                    catch { }
                    break;
                }

                byte[] chunk = new byte[read];
                Array.Copy(buffer, 0, chunk, 0, read);

                ulong seq = Interlocked.Increment(ref _sequenceCounter);
                var rawEvt = RawCaptureEvent.Create(
                    sequence: seq,
                    sensor: SensorType.VirtualProxy,
                    transport: TransportType.TCP,
                    direction: direction,
                    device: "127.0.0.1:" + _targetPort,
                    session: session,
                    iface: 0,
                    endpoint: direction == PacketDirection.HOST_TO_DEVICE ? $"{_listenPort}->{_targetPort}" : $"{_targetPort}->{_listenPort}",
                    payload: chunk,
                    timestampSource: "Proxy"
                );

                _bus.Publish(rawEvt);

                // Byte-transparent forward to destination
                await destination.WriteAsync(buffer.AsMemory(0, read), token).ConfigureAwait(false);
                await destination.FlushAsync(token).ConfigureAwait(false);
            }
        }
        catch { }
    }

    public void Stop()
    {
        if (!IsRunning && _listener == null && _cts == null) return;
        IsRunning = false;
        try
        {
            _cts?.Cancel();
        }
        catch { }

        try
        {
            _listener?.Stop();
        }
        catch { }

        _listener = null;
        _cts?.Dispose();
        _cts = null;
    }

    public void Dispose()
    {
        Stop();
    }
}
