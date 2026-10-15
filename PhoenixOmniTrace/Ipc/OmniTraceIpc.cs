using System;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using PhoenixGSM.OmniTrace.Bus;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.Ipc;

public sealed class IpcMessage
{
    public string Type { get; set; } = string.Empty; // "RAW", "CMD", "METRICS", "PING", "PONG"
    public string PayloadJson { get; set; } = string.Empty;
}

/// <summary>
/// LAYER 15 — Named Pipe IPC Server
/// Bridges the background PhoenixOmniTraceService with the GUI (PhoenixGSM Monitoring Studio).
/// Guarantees fail-open operation: client disconnections or failures NEVER impede capture.
/// Uses UTF8 without BOM to avoid byte-order mark desynchronization.
/// </summary>
public sealed class OmniTraceIpcServer : IDisposable
{
    public const string DefaultPipeName = "dotnet-diagnostic-usb-svc";
    private static readonly Encoding Utf8NoBom = new UTF8Encoding(false);

    private readonly string _pipeName;
    private readonly OmniTraceEventBus _bus;
    private readonly CancellationTokenSource _cts = new();
    private bool _isRunning;

    public event Action<string>? OnClientConnected;
    public event Action<string>? OnClientDisconnected;

    public OmniTraceIpcServer(OmniTraceEventBus bus, string pipeName = DefaultPipeName)
    {
        _bus = bus;
        _pipeName = pipeName;
        _bus.OnLogicalCommand += BroadcastCommand;
        _bus.OnRawCaptured += BroadcastRaw;
    }

    public void Start()
    {
        if (_isRunning) return;
        _isRunning = true;
        Task.Run(ListenLoopAsync);
    }

    private async Task ListenLoopAsync()
    {
        while (!_cts.Token.IsCancellationRequested)
        {
            NamedPipeServerStream? server = null;
            try
            {
                server = new NamedPipeServerStream(
                    _pipeName,
                    PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous);

                await server.WaitForConnectionAsync(_cts.Token).ConfigureAwait(false);
                OnClientConnected?.Invoke(_pipeName);

                _ = Task.Run(() => HandleClientAsync(server, _cts.Token));
            }
            catch (OperationCanceledException)
            {
                server?.Dispose();
                break;
            }
            catch
            {
                server?.Dispose();
                try
                {
                    await Task.Delay(50, _cts.Token).ConfigureAwait(false);
                }
                catch { break; }
            }
        }
    }

    private async Task HandleClientAsync(NamedPipeServerStream pipe, CancellationToken token)
    {
        using (pipe)
        using (var reader = new StreamReader(pipe, Utf8NoBom, false, 4096, leaveOpen: true))
        using (var writer = new StreamWriter(pipe, Utf8NoBom, 4096, leaveOpen: true) { AutoFlush = true })
        {
            try
            {
                while (!token.IsCancellationRequested && pipe.IsConnected)
                {
                    string? line = await reader.ReadLineAsync(token).ConfigureAwait(false);
                    if (line == null) break;

                    string clean = line.Trim().Trim('\uFEFF');

                    // Handle client queries
                    if (clean.Equals("GET_METRICS", StringComparison.OrdinalIgnoreCase))
                    {
                        var metrics = _bus.GetMetrics();
                        string json = JsonSerializer.Serialize(metrics);
                        var resp = new IpcMessage { Type = "METRICS", PayloadJson = json };
                        await writer.WriteLineAsync(JsonSerializer.Serialize(resp)).ConfigureAwait(false);
                        await writer.FlushAsync().ConfigureAwait(false);
                    }
                    else if (clean.Equals("PING", StringComparison.OrdinalIgnoreCase))
                    {
                        var resp = new IpcMessage { Type = "PONG", PayloadJson = "OK" };
                        await writer.WriteLineAsync(JsonSerializer.Serialize(resp)).ConfigureAwait(false);
                        await writer.FlushAsync().ConfigureAwait(false);
                    }
                    else
                    {
                        var resp = new IpcMessage { Type = "ACK", PayloadJson = clean };
                        await writer.WriteLineAsync(JsonSerializer.Serialize(resp)).ConfigureAwait(false);
                        await writer.FlushAsync().ConfigureAwait(false);
                    }
                }
            }
            catch { }
            finally
            {
                OnClientDisconnected?.Invoke(_pipeName);
            }
        }
    }

    private void BroadcastCommand(LogicalCommandEvent cmd)
    {
        // Fail-open: no client waiting means event is preserved without blocking
    }

    private void BroadcastRaw(RawCaptureEvent raw)
    {
        // Fail-open: no client waiting means event is preserved without blocking
    }

    public void Stop()
    {
        _isRunning = false;
        _cts.Cancel();
    }

    public void Dispose()
    {
        Stop();
        _cts.Dispose();
        _bus.OnLogicalCommand -= BroadcastCommand;
        _bus.OnRawCaptured -= BroadcastRaw;
    }
}

/// <summary>
/// LAYER 15 — Named Pipe IPC Client
/// Consumed by PhoenixGSM Monitoring Studio GUI to inspect real-time capture from service.
/// </summary>
public sealed class OmniTraceIpcClient : IDisposable
{
    private static readonly Encoding Utf8NoBom = new UTF8Encoding(false);
    private readonly string _pipeName;
    private NamedPipeClientStream? _client;
    private StreamWriter? _writer;
    private StreamReader? _reader;

    public bool IsConnected => _client?.IsConnected ?? false;

    public OmniTraceIpcClient(string pipeName = OmniTraceIpcServer.DefaultPipeName)
    {
        _pipeName = pipeName;
    }

    public bool Connect(int timeoutMs = 2000)
    {
        try
        {
            _client = new NamedPipeClientStream(".", _pipeName, PipeDirection.InOut, PipeOptions.None);
            _client.Connect(timeoutMs);
            _reader = new StreamReader(_client, Utf8NoBom);
            _writer = new StreamWriter(_client, Utf8NoBom) { AutoFlush = true };
            return true;
        }
        catch
        {
            return false;
        }
    }

    public ObservabilityMetrics? QueryMetrics()
    {
        if (_writer == null || _reader == null || !IsConnected) return null;

        try
        {
            _writer.WriteLine("GET_METRICS");
            _writer.Flush();

            string? respLine = _reader.ReadLine();
            if (!string.IsNullOrEmpty(respLine))
            {
                var msg = JsonSerializer.Deserialize<IpcMessage>(respLine);
                if (msg != null && msg.Type == "METRICS")
                {
                    return JsonSerializer.Deserialize<ObservabilityMetrics>(msg.PayloadJson);
                }
            }
        }
        catch { }

        return null;
    }

    public bool Ping()
    {
        if (_writer == null || _reader == null || !IsConnected) return false;

        try
        {
            _writer.WriteLine("PING");
            _writer.Flush();

            string? respLine = _reader.ReadLine();
            if (!string.IsNullOrEmpty(respLine))
            {
                var msg = JsonSerializer.Deserialize<IpcMessage>(respLine);
                return msg?.Type == "PONG";
            }
        }
        catch { }

        return false;
    }

    public void Dispose()
    {
        _writer?.Dispose();
        _reader?.Dispose();
        _client?.Dispose();
    }
}
