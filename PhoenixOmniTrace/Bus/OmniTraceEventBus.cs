using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using PhoenixGSM.OmniTrace.Correlation;
using PhoenixGSM.OmniTrace.Detection;
using PhoenixGSM.OmniTrace.Decoders;
using PhoenixGSM.OmniTrace.Models;
using PhoenixGSM.OmniTrace.Reassembly;
using PhoenixGSM.OmniTrace.Sensors;

namespace PhoenixGSM.OmniTrace.Bus;

public sealed class ObservabilityMetrics
{
    public long RawEventsCaptured { get; set; }
    public long DecodedEvents { get; set; }
    public long UnknownEvents { get; set; }
    public long DroppedEvents { get; set; }
    public long MalformedFrames { get; set; }
    public int ActiveSessions { get; set; }
    public int ActiveDevices { get; set; }
    public int ActiveEndpoints { get; set; }
    public long ParserErrors { get; set; }
    public int QueueDepth { get; set; }

    public override string ToString()
    {
        return $"[Metrics] Raw={RawEventsCaptured:N0} | Decoded={DecodedEvents:N0} | Unknown={UnknownEvents:N0} | Dropped={DroppedEvents:N0} | Malformed={MalformedFrames:N0} | Sessions={ActiveSessions} | Queue={QueueDepth}";
    }
}

/// <summary>
/// LAYER 14 — Raw Event Bus & Observability Backbone
/// Decouples capture ingestion from decoding pipeline.
/// Guarantees fail-open behavior: unknown data and parser anomalies are safely handled and retained.
/// Links complete multi-packet raw evidence to logical commands.
/// </summary>
public sealed partial class OmniTraceEventBus : IDisposable
{
    private readonly Channel<RawCaptureEvent> _channel;
    private readonly CancellationTokenSource _cts = new();
    private Task? _processingTask;

    public TransportReassembler Reassembler { get; } = new();
    public ProtocolDetector Detector { get; } = new();
    public AdbWireDecoder AdbDecoder { get; } = new();
    public AdbSmartSocketDecoder SmartSocketDecoder { get; } = new();
    public AdbChannelStateMachine ChannelStateMachine { get; } = new();
    public ShellStreamReconstructor ShellReconstructor { get; } = new();
    public CommandCorrelationEngine Correlation { get; } = new();
    public UsbDeviceSensor UsbSensor { get; }
    public AdbPushArtifactSensor? ArtifactSensor { get; set; }

    private readonly ConcurrentDictionary<string, byte> _activeDevices = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, byte> _activeEndpoints = new(StringComparer.OrdinalIgnoreCase);

    // Observability Counters
    private long _rawEventsCaptured;
    private long _decodedEvents;
    private long _unknownEvents;
    private long _droppedEvents;
    private long _malformedFrames;
    private long _parserErrors;
    private long _inFlight;

    public event Action<RawCaptureEvent>? OnRawCaptured;
    public event Action<LogicalCommandEvent>? OnLogicalCommand;
    public event Action<RawCaptureEvent, ProtocolCandidate>? OnProtocolDetected;
    public event Action<string, string>? OnAnomalyDetected;

    public void ReportAnomaly(string code, string message)
    {
        OnAnomalyDetected?.Invoke(code, message);
    }

    public void ReportLogicalCommand(LogicalCommandEvent cmd)
    {
        Interlocked.Increment(ref _decodedEvents);
        OnLogicalCommand?.Invoke(cmd);
    }

    public OmniTraceEventBus(int capacity = 65536)
    {
        UsbSensor = new UsbDeviceSensor(this);
        var options = new BoundedChannelOptions(capacity)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleWriter = false,
            SingleReader = true
        };
        _channel = Channel.CreateBounded<RawCaptureEvent>(options);
        _processingTask = Task.Run(ProcessEventsAsync);
    }

    public bool Publish(RawCaptureEvent evt)
    {
        Interlocked.Increment(ref _rawEventsCaptured);
        _activeDevices[evt.DeviceIdentity] = 1;
        _activeEndpoints[$"{evt.DeviceIdentity}:{evt.Endpoint}"] = 1;

        OnRawCaptured?.Invoke(evt);

        if (!_channel.Writer.TryWrite(evt))
        {
            Interlocked.Increment(ref _droppedEvents);
            return false;
        }

        return true;
    }

    private async Task ProcessEventsAsync()
    {
        var reader = _channel.Reader;
        var token = _cts.Token;

        try
        {
            while (await reader.WaitToReadAsync(token).ConfigureAwait(false))
            {
                while (reader.TryRead(out var evt))
                {
                    Interlocked.Increment(ref _inFlight);
                    try
                    {
                        ProcessSingleEvent(evt, isDirectSync: false);
                    }
                    finally
                    {
                        Interlocked.Decrement(ref _inFlight);
                    }
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            Interlocked.Increment(ref _parserErrors);
            OnAnomalyDetected?.Invoke("EVENT_BUS_FATAL_ERROR", ex.Message);
        }
    }

    public void ProcessSingleEvent(RawCaptureEvent evt, bool isDirectSync = true)
    {
        try
        {
            if (isDirectSync)
            {
                Interlocked.Increment(ref _rawEventsCaptured);
                _activeDevices[evt.DeviceIdentity] = 1;
                _activeEndpoints[$"{evt.DeviceIdentity}:{evt.Endpoint}"] = 1;
                OnRawCaptured?.Invoke(evt);
            }

            // 1. Reassembly queueing
            Reassembler.PushRawEvent(evt);

            var key = new CaptureSessionKey(
                evt.DeviceIdentity,
                evt.InterfaceIdentity,
                evt.Endpoint,
                evt.Direction,
                evt.SessionIdentity);

            byte[] currentStream = Reassembler.PeekStream(key);
            if (currentStream.Length == 0) return;

            // One-shot filesystem staged files are parsed and correlated directly by TempFileAtSensor
            if (evt.Sensor == SensorType.FileSystem || evt.Transport == TransportType.FILE)
            {
                Reassembler.ConsumeStream(key, currentStream.Length);
                return;
            }

            // In-process direct operations are correlated directly by InProcessExecutionSensor
            if (evt.Direction == PacketDirection.INTERNAL ||
                (evt.Metadata != null && evt.Metadata.TryGetValue("ExecutionType", out var exec) && exec == "InProcessDirect"))
            {
                Reassembler.ConsumeStream(key, currentStream.Length);
                return;
            }

            // 2. Protocol candidate detection
            var candidate = Detector.GetBestCandidate(currentStream, evt.Sensor, evt.Transport, evt.Direction);
            OnProtocolDetected?.Invoke(evt, candidate);

            if (candidate.Protocol == KnownProtocol.Unknown)
            {
                Interlocked.Increment(ref _unknownEvents);
                // Preserve raw bytes in reassembly buffer without dropping or discarding
                return;
            }

            // 3. Decoding based on detected protocol
            switch (candidate.Protocol)
            {
                case KnownProtocol.ADB:
                    DecodeAdbStream(key, currentStream, evt);
                    break;

                case KnownProtocol.Fastboot:
                    DecodeFastbootStream(key, currentStream, evt);
                    break;

                case KnownProtocol.SerialAt:
                    if (currentStream.Contains((byte)'\r') || currentStream.Contains((byte)'\n') || currentStream.Length >= 512 || (currentStream.Length > 0 && currentStream[0] == '>'))
                    {
                        DecodeSerialAtStream(key, currentStream, evt);
                    }
                    break;

                case KnownProtocol.Mtp:
                case KnownProtocol.Ptp:
                    DecodeMtpStream(key, currentStream, evt);
                    break;

                case KnownProtocol.MtkBrom:
                case KnownProtocol.MtkDa:
                    DecodeMtkStream(key, currentStream, evt);
                    break;

                case KnownProtocol.SpreadtrumFdl:
                    DecodeSpdFdlStream(key, currentStream, evt);
                    break;

                case KnownProtocol.QualcommSahara:
                case KnownProtocol.QualcommFirehose:
                    DecodeQualcommEdlStream(candidate.Protocol, key, currentStream, evt);
                    break;

                case KnownProtocol.QualcommDiag:
                case KnownProtocol.SamsungOdin:
                    DecodeGenericKnownProtocol(candidate.Protocol, key, currentStream, evt);
                    break;

                case KnownProtocol.HostCommand:
                    DecodeHostCommandStream(key, currentStream, evt);
                    break;

                case KnownProtocol.InProcess:
                    DecodeInProcessStream(key, currentStream, evt);
                    break;

                case KnownProtocol.AppleUsbmuxd:
                case KnownProtocol.AppleLockdown:
                case KnownProtocol.AppleRecovery:
                case KnownProtocol.AppleDfu:
                case KnownProtocol.AppleRamdiskSsh:
                case KnownProtocol.ApplePurpleDiag:
                    DecodeAppleStream(candidate.Protocol, key, currentStream, evt);
                    break;

                default:
                    Interlocked.Increment(ref _unknownEvents);
                    break;
            }
        }
        catch (Exception ex)
        {
            Interlocked.Increment(ref _parserErrors);
            OnAnomalyDetected?.Invoke("PIPELINE_PARSE_EXCEPTION", ex.Message);
        }
    }

    public ObservabilityMetrics GetMetrics()
    {
        return new ObservabilityMetrics
        {
            RawEventsCaptured = Volatile.Read(ref _rawEventsCaptured),
            DecodedEvents = Volatile.Read(ref _decodedEvents),
            UnknownEvents = Volatile.Read(ref _unknownEvents),
            DroppedEvents = Volatile.Read(ref _droppedEvents),
            MalformedFrames = Volatile.Read(ref _malformedFrames),
            ParserErrors = Volatile.Read(ref _parserErrors),
            ActiveSessions = Reassembler.GetActiveSessionCount(),
            ActiveDevices = _activeDevices.Count,
            ActiveEndpoints = _activeEndpoints.Count,
            QueueDepth = _channel.Reader.Count
        };
    }

    /// <summary>
    /// Flushes all pending queued events in the channel and waits for in-flight event processing to complete.
    /// </summary>
    public void Flush(int timeoutMs = 2000)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while ((_channel.Reader.Count > 0 || Interlocked.Read(ref _inFlight) > 0) && sw.ElapsedMilliseconds < timeoutMs)
        {
            Thread.Sleep(5);
        }
        Thread.Sleep(15);
    }

    public void Dispose()
    {
        Flush(1000);
        _channel.Writer.TryComplete();
        _cts.Cancel();
        try
        {
            _processingTask?.Wait(500);
        }
        catch { }
        _cts.Dispose();
    }
}
