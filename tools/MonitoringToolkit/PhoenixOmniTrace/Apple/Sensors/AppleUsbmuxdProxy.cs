using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using PhoenixGSM.OmniTrace.Bus;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.Apple.Sensors;

/// <summary>
/// Transparent Proxy and Socket Observer for Apple's usbmuxd service (TCP 27015).
/// Operates with strict fail-open semantics: if port 27015 is held by AppleMobileDeviceService,
/// it safely records the status and avoids workflow disruption.
/// </summary>
public sealed class AppleUsbmuxdProxy : IDisposable
{
    private readonly OmniTraceEventBus _bus;
    private readonly int _listenPort;
    private readonly int _targetPort;
    private TcpListener? _listener;
    private CancellationTokenSource? _cts;
    private ulong _sequenceCounter = 500000;

    public bool IsRunning { get; private set; }
    public bool IsPortBoundByAnotherProcess { get; private set; }
    public string StatusMessage { get; private set; } = "Not Started";

    public AppleUsbmuxdProxy(OmniTraceEventBus bus, int listenPort = 27016, int targetPort = 27015)
    {
        _bus = bus;
        _listenPort = listenPort;
        _targetPort = targetPort;
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
            StatusMessage = $"Listening on 127.0.0.1:{_listenPort}, target 27015";
            _ = Task.Run(() => AcceptClientsAsync(_cts.Token), _cts.Token);
        }
        catch (SocketException sex) when (sex.SocketErrorCode == SocketError.AddressAlreadyInUse ||
                                          sex.NativeErrorCode == 10048 ||
                                          sex.SocketErrorCode == SocketError.AccessDenied)
        {
            IsPortBoundByAnotherProcess = true;
            IsRunning = false;
            _listener = null;
            StatusMessage = $"Fail-Open: Port {_listenPort} bound by AppleMobileDeviceService. Bypassing socket proxy to preserve tool operation.";
            _bus.ReportAnomaly("USBMUXD_PROXY_PORT_BOUND", StatusMessage);
        }
        catch (Exception ex)
        {
            IsRunning = false;
            _listener = null;
            StatusMessage = $"Fail-Open: usbmuxd proxy error on port {_listenPort}: {ex.Message}";
            _bus.ReportAnomaly("USBMUXD_PROXY_START_ERROR", StatusMessage);
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

            await Task.WhenAny(c2t, t2c).ConfigureAwait(false);
        }
        catch { }
        finally
        {
            try { client.Close(); } catch { }
            try { target.Close(); } catch { }
        }
    }

    private async Task ForwardStreamAsync(
        TcpClient srcClient,
        TcpClient dstClient,
        NetworkStream src,
        NetworkStream dst,
        PacketDirection direction,
        string session,
        CancellationToken token)
    {
        byte[] buffer = new byte[16384];
        try
        {
            while (!token.IsCancellationRequested)
            {
                int read = await src.ReadAsync(buffer.AsMemory(0, buffer.Length), token).ConfigureAwait(false);
                if (read <= 0)
                {
                    try { dstClient.Client.Shutdown(SocketShutdown.Send); } catch { }
                    break;
                }

                byte[] payload = new byte[read];
                Buffer.BlockCopy(buffer, 0, payload, 0, read);

                ulong seq = Interlocked.Increment(ref _sequenceCounter);
                var rawEvt = RawCaptureEvent.Create(
                    sequence: seq,
                    sensor: SensorType.VirtualProxy,
                    transport: TransportType.TCP,
                    direction: direction,
                    device: "USBMUXD_LOOPBACK",
                    session: session,
                    iface: 0,
                    endpoint: direction == PacketDirection.HOST_TO_DEVICE ? "TCP_27015_IN" : "TCP_27015_OUT",
                    payload: payload,
                    timestampSource: "UsbmuxdProxy"
                );

                _bus.Publish(rawEvt);
                await dst.WriteAsync(buffer.AsMemory(0, read), token).ConfigureAwait(false);
                await dst.FlushAsync(token).ConfigureAwait(false);
            }
        }
        catch { }
    }

    public void Stop()
    {
        if (!IsRunning) return;
        IsRunning = false;
        try { _cts?.Cancel(); } catch { }
        try { _listener?.Stop(); } catch { }
        _listener = null;
    }

    public void Dispose()
    {
        Stop();
        _cts?.Dispose();
    }
}
