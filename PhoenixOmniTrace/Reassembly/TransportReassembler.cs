using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.Reassembly;

/// <summary>
/// LAYER 6 — Transport Reassembler
/// Manages per-session byte streams. Handles fragmentation, coalescing,
/// and guarantees that multiple devices/endpoints never corrupt each other's stream.
/// Thread-safe lock consistency across stream storage and evidence metadata.
/// </summary>
public sealed class TransportReassembler
{
    private sealed class SessionStreamBuffer
    {
        private readonly MemoryStream _stream = new();
        private readonly object _lock = new();
        private readonly List<ulong> _rawSequences = [];
        private readonly List<string> _evidenceHashes = [];

        public void Append(RawCaptureEvent evt)
        {
            lock (_lock)
            {
                if (evt.RawPayload.Length > 0)
                {
                    _stream.Write(evt.RawPayload, 0, evt.RawPayload.Length);
                }
                _rawSequences.Add(evt.SequenceNumber);
                if (!string.IsNullOrEmpty(evt.PayloadHash))
                {
                    _evidenceHashes.Add(evt.PayloadHash);
                }

                // Safety bound: prevent unbounded growth if a stream is never consumed
                if (_stream.Length > 16 * 1024 * 1024)
                {
                    // Truncate oldest 8MB to protect memory
                    byte[] current = _stream.ToArray();
                    _stream.SetLength(0);
                    _stream.Write(current, 8 * 1024 * 1024, current.Length - 8 * 1024 * 1024);
                }
            }
        }

        public byte[] PeekBytes()
        {
            lock (_lock)
            {
                return _stream.ToArray();
            }
        }

        public void Consume(int byteCount)
        {
            lock (_lock)
            {
                if (byteCount <= 0) return;
                byte[] current = _stream.ToArray();
                _stream.SetLength(0);
                if (byteCount < current.Length)
                {
                    _stream.Write(current, byteCount, current.Length - byteCount);
                }
            }
        }

        public void Clear()
        {
            lock (_lock)
            {
                _stream.SetLength(0);
                _rawSequences.Clear();
                _evidenceHashes.Clear();
            }
        }

        public List<ulong> CopySequences()
        {
            lock (_lock)
            {
                return new List<ulong>(_rawSequences);
            }
        }

        public List<string> CopyHashes()
        {
            lock (_lock)
            {
                return new List<string>(_evidenceHashes);
            }
        }

        public (List<ulong> sequences, List<string> hashes) SnapshotEvidence()
        {
            lock (_lock)
            {
                return (new List<ulong>(_rawSequences), new List<string>(_evidenceHashes));
            }
        }

        public int AvailableBytes
        {
            get
            {
                lock (_lock)
                {
                    return (int)_stream.Length;
                }
            }
        }
    }

    private readonly ConcurrentDictionary<CaptureSessionKey, SessionStreamBuffer> _buffers = new();

    public void PushRawEvent(RawCaptureEvent evt)
    {
        var key = new CaptureSessionKey(
            evt.DeviceIdentity,
            evt.InterfaceIdentity,
            evt.Endpoint,
            evt.Direction,
            evt.SessionIdentity
        );

        var buf = _buffers.GetOrAdd(key, _ => new SessionStreamBuffer());
        buf.Append(evt);
    }

    public byte[] PeekStream(CaptureSessionKey key)
    {
        if (_buffers.TryGetValue(key, out var buf))
        {
            return buf.PeekBytes();
        }
        return Array.Empty<byte>();
    }

    public void ConsumeStream(CaptureSessionKey key, int count)
    {
        if (_buffers.TryGetValue(key, out var buf))
        {
            buf.Consume(count);
        }
    }

    public List<ulong> GetSequencesForSession(CaptureSessionKey key)
    {
        if (_buffers.TryGetValue(key, out var buf))
        {
            return buf.CopySequences();
        }
        return [];
    }

    public List<string> GetHashesForSession(CaptureSessionKey key)
    {
        if (_buffers.TryGetValue(key, out var buf))
        {
            return buf.CopyHashes();
        }
        return [];
    }

    public (List<ulong> sequences, List<string> hashes) GetEvidenceSnapshot(CaptureSessionKey key)
    {
        if (_buffers.TryGetValue(key, out var buf))
        {
            return buf.SnapshotEvidence();
        }
        return ([], []);
    }

    public void ResetSession(CaptureSessionKey key)
    {
        if (_buffers.TryGetValue(key, out var buf))
        {
            buf.Clear();
        }
    }

    public void RemoveSession(CaptureSessionKey key)
    {
        _buffers.TryRemove(key, out _);
    }

    public int GetActiveSessionCount() => _buffers.Count;

    public void ClearAll() => _buffers.Clear();
}
