using System;
using System.Buffers.Binary;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using PhoenixOmniTrace.L24_SourceSentinel.Decoders;
using PhoenixOmniTrace.L24_SourceSentinel.Models;

namespace PhoenixOmniTrace.L24_SourceSentinel.Core;

public sealed class SourceIpcServer : IDisposable
{
    public const string PipeName = "PhoenixL24SentinelPipe";
    private CancellationTokenSource? _cts;
    private bool _isDisposed;

    public event Action<SourceTelemetryEvent>? OnEventCaptured;

    public bool IsRunning { get; private set; }

    public void Start()
    {
        if (IsRunning || _isDisposed) return;
        try { _cts?.Cancel(); _cts?.Dispose(); } catch { }
        _cts = new CancellationTokenSource();
        IsRunning = true;

        // Launch 6 concurrent pipe listener tasks to prevent any packet loss under heavy I/O
        for (int i = 0; i < 6; i++)
        {
            Task.Run(() => ListenLoopAsync(_cts.Token));
        }
    }

    public void Stop()
    {
        if (!IsRunning) return;
        IsRunning = false;
        try
        {
            _cts?.Cancel();
            _cts?.Dispose();
        }
        catch { }
        _cts = null;
    }

    private async Task ListenLoopAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested && !_isDisposed && IsRunning)
        {
            try
            {
                await using var server = new NamedPipeServerStream(
                    PipeName,
                    PipeDirection.In,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous);

                await server.WaitForConnectionAsync(token);
                await ProcessClientStreamAsync(server, token);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception)
            {
                if (token.IsCancellationRequested || !IsRunning) break;
                await Task.Delay(50, token).ConfigureAwait(false);
            }
        }
    }

    private async Task ProcessClientStreamAsync(Stream stream, CancellationToken token)
    {
        using var reader = new BinaryReader(stream, Encoding.Unicode, leaveOpen: true);
        try
        {
            while (stream.CanRead && !token.IsCancellationRequested && !_isDisposed && IsRunning)
            {
                int pid = reader.ReadInt32();
                int tid = reader.ReadInt32();
                int stageId = reader.ReadInt32();
                uint ioctlCode = reader.ReadUInt32();
                string apiName = reader.ReadString();
                string callerOrigin = reader.ReadString();
                string targetResource = reader.ReadString();
                int payloadLen = reader.ReadInt32();
                byte[] payload = payloadLen > 0 ? reader.ReadBytes(payloadLen) : Array.Empty<byte>();

                var (category, decodedText) = RawPayloadClassifier.Classify(apiName, targetResource, ioctlCode, payload);

                var evt = new SourceTelemetryEvent
                {
                    ProcessId = pid,
                    ThreadId = tid,
                    Stage = Enum.IsDefined(typeof(SentinelStage), stageId) ? (SentinelStage)stageId : SentinelStage.RawCommandExecution,
                    HookedApiName = apiName,
                    CallerModuleOrigin = string.IsNullOrWhiteSpace(callerOrigin) ? "UnknownOrigin" : callerOrigin,
                    TargetResource = string.IsNullOrWhiteSpace(targetResource) ? "N/A" : targetResource,
                    CommandCategory = category,
                    DecodedCommandText = decodedText,
                    RawPayloadHex = payload.Length > 0 ? Convert.ToHexString(payload.AsSpan(0, Math.Min(payload.Length, 256))) : string.Empty,
                    PayloadSize = payload.Length
                };

                OnEventCaptured?.Invoke(evt);
            }
        }
        catch (EndOfStreamException) { /* انتهاء اتصال العملية المراقبة */ }
        catch (IOException) { /* إغلاق الأنبوب */ }
        catch (Exception) { /* حماية تامة ضد انهيار الخادم */ }
    }

    public void Dispose()
    {
        if (_isDisposed) return;
        _isDisposed = true;
        Stop();
    }
}
