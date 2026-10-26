using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using PhoenixOmniTrace.L24_SourceSentinel.Models;

namespace PhoenixOmniTrace.L24_SourceSentinel.Core;

/// <summary>
/// محرك منع التكرار الدقيق ودمج التجزئة التدريجية في نفس البافر بالذاكرة دون التهام الروابط أو الأوامر المستقلة
/// </summary>
public static class RamCommandConsolidator
{
    private static readonly object SyncLock = new();
    private static long _outboundExecutedSequence = 1;

    private static readonly List<TrackedRamCommandEntry> _discoveredRamEntries = new();
    private static readonly ConcurrentDictionary<string, long> _phoneResponseLastExecSeq = new(StringComparer.OrdinalIgnoreCase);
    private static readonly ConcurrentDictionary<string, DateTime> _phoneResponseLastTime = new(StringComparer.OrdinalIgnoreCase);

    private sealed class TrackedRamCommandEntry
    {
        public required Guid EventId { get; init; }
        public required L24CommandGroup Group { get; init; }
        public required bool IsPhoneResponse { get; init; }
        public required long MemoryAddress { get; set; }
        public required string NormalizedCommand { get; set; }
        public required SourceTelemetryEvent EventRef { get; init; }
        public DateTime LastUpdatedUtc { get; set; }
    }

    public static void ResetSession()
    {
        lock (SyncLock)
        {
            _discoveredRamEntries.Clear();
            _phoneResponseLastExecSeq.Clear();
            _phoneResponseLastTime.Clear();
            Interlocked.Exchange(ref _outboundExecutedSequence, 1);
        }
    }

    public static void NotifyActualOutboundCommandExecuted()
    {
        Interlocked.Increment(ref _outboundExecutedSequence);
    }

    public static bool TryConsolidateOrDeduplicate(SourceTelemetryEvent evt)
    {
        if (evt == null) return false;

        string pure = NormalizeCommandKey(evt.PureCommandText);
        if (string.IsNullOrWhiteSpace(pure)) return false;

        long currentExecSeq = Interlocked.Read(ref _outboundExecutedSequence);
        DateTime now = DateTime.UtcNow;

        if (evt.Scope == L24CommandScope.ExecutedOnDevice)
        {
            if (!evt.IsPhoneResponse)
            {
                NotifyActualOutboundCommandExecuted();
                return true;
            }
            else
            {
                if (_phoneResponseLastExecSeq.TryGetValue(pure, out long lastSeq) && lastSeq == currentExecSeq)
                {
                    if (_phoneResponseLastTime.TryGetValue(pure, out var lastTime) && (now - lastTime).TotalSeconds < 2.0)
                        return false;
                }

                _phoneResponseLastExecSeq[pure] = currentExecSeq;
                _phoneResponseLastTime[pure] = now;
                return true;
            }
        }

        if (evt.Scope == L24CommandScope.DiscoveredInRam)
        {
            lock (SyncLock)
            {
                if (evt.IsPhoneResponse)
                {
                    if (TryMergeSameBufferFragmentLocked(evt, pure, isResponse: true, now, out bool dropFragment))
                    {
                        if (dropFragment) return false;
                        _phoneResponseLastExecSeq[pure] = currentExecSeq;
                        _phoneResponseLastTime[pure] = now;
                        return true;
                    }

                    if (_phoneResponseLastExecSeq.TryGetValue(pure, out long recordedSeq) && recordedSeq == currentExecSeq)
                    {
                        return false;
                    }

                    _phoneResponseLastExecSeq[pure] = currentExecSeq;
                    _phoneResponseLastTime[pure] = now;
                }

                if (TryMergeSameBufferFragmentLocked(evt, pure, evt.IsPhoneResponse, now, out bool dropDuplicateOrFragment))
                {
                    return !dropDuplicateOrFragment;
                }

                _discoveredRamEntries.Add(new TrackedRamCommandEntry
                {
                    EventId = evt.EventId,
                    Group = evt.CommandGroup,
                    IsPhoneResponse = evt.IsPhoneResponse,
                    MemoryAddress = evt.MemoryAddress,
                    NormalizedCommand = pure,
                    EventRef = evt,
                    LastUpdatedUtc = now
                });

                return true;
            }
        }

        return true;
    }

    private static bool TryMergeSameBufferFragmentLocked(
        SourceTelemetryEvent incoming,
        string incomingPure,
        bool isResponse,
        DateTime now,
        out bool shouldDrop)
    {
        shouldDrop = false;

        for (int i = _discoveredRamEntries.Count - 1; i >= 0; i--)
        {
            var existing = _discoveredRamEntries[i];
            if (existing.IsPhoneResponse != isResponse) continue;

            string existingPure = existing.NormalizedCommand;

            if (string.Equals(existingPure, incomingPure, StringComparison.OrdinalIgnoreCase))
            {
                shouldDrop = true;
                return true;
            }

            bool isSameMemoryNeighborhood = incoming.MemoryAddress > 0 && existing.MemoryAddress > 0 &&
                                            Math.Abs(incoming.MemoryAddress - existing.MemoryAddress) <= 256;
            bool isRecentBufferUpdate = (now - existing.LastUpdatedUtc).TotalSeconds <= 15.0;

            if (isSameMemoryNeighborhood && isRecentBufferUpdate)
            {
                if (incomingPure.Length < existingPure.Length && incomingPure.Length >= 4 &&
                    existingPure.StartsWith(incomingPure, StringComparison.OrdinalIgnoreCase))
                {
                    shouldDrop = true;
                    return true;
                }

                if (incomingPure.Length > existingPure.Length && existingPure.Length >= 4 &&
                    incomingPure.StartsWith(existingPure, StringComparison.OrdinalIgnoreCase))
                {
                    existing.NormalizedCommand = incomingPure;
                    existing.MemoryAddress = incoming.MemoryAddress;
                    existing.LastUpdatedUtc = now;

                    existing.EventRef.DecodedCommandText = incoming.DecodedCommandText;
                    existing.EventRef.RawPayloadHex = incoming.RawPayloadHex;
                    existing.EventRef.PayloadSize = incoming.PayloadSize;
                    existing.EventRef.PureCommandText = incoming.PureCommandText;
                    if (!string.IsNullOrWhiteSpace(incoming.TargetResource))
                        existing.EventRef.TargetResource = incoming.TargetResource;

                    shouldDrop = true;
                    return true;
                }
            }
        }

        return false;
    }

    public static string NormalizeCommandKey(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return string.Empty;
        string s = raw.Trim();
        var sb = new StringBuilder(s.Length);
        bool prevSpace = false;
        foreach (char c in s)
        {
            if (c is ' ' or '\t' or '\r' or '\n')
            {
                if (!prevSpace)
                {
                    sb.Append(' ');
                    prevSpace = true;
                }
            }
            else
            {
                sb.Append(c);
                prevSpace = false;
            }
        }
        return sb.ToString().Trim();
    }
}
