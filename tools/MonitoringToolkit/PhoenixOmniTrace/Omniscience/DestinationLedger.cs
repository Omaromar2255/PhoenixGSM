using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace PhoenixGSM.OmniTrace.Omniscience
{
    public enum TargetDestination
    {
        PhoneDevice,
        LocalComputer,
        ExternalRemote
    }

    public enum EventDirection
    {
        Inbound,
        Outbound,
        Internal
    }

    public record DestinationEvent(
        string EventId,
        TargetDestination Destination,
        EventDirection Direction,
        int SourceProcessId,
        string SourceProcessName,
        string Description,
        string PayloadHash,
        long PayloadSize,
        double Entropy,
        DateTime Timestamp
    );

    /// <summary>
    /// Thread-safe ledger tracking every tool action by destination.
    /// دفتر الأستاذ لتتبع الوجهات - Thread-safe
    /// </summary>
    public class DestinationLedger : IDisposable
    {
        private readonly ConcurrentBag<DestinationEvent> _ledger = new();
        private bool _disposed = false;

        public void AddEvent(DestinationEvent destEvent)
        {
            try
            {
                if (_disposed) return;
                _ledger.Add(destEvent);
                // إضافة الحدث إلى السجل
            }
            catch (Exception ex)
            {
                // Fail-open: don't crash
                Console.WriteLine($"[DestinationLedger] Error adding event: {ex.Message}");
            }
        }

        public IEnumerable<DestinationEvent> GetExfiltrationEvents()
        {
            try
            {
                return _ledger.Where(e => e.Destination == TargetDestination.ExternalRemote && e.Direction == EventDirection.Outbound).ToList();
            }
            catch
            {
                return Array.Empty<DestinationEvent>();
            }
        }

        public IEnumerable<DestinationEvent> GetPhonePayloadEvents()
        {
            try
            {
                return _ledger.Where(e => e.Destination == TargetDestination.PhoneDevice).ToList();
            }
            catch
            {
                return Array.Empty<DestinationEvent>();
            }
        }

        public IEnumerable<DestinationEvent> GetLocalTamperEvents()
        {
            try
            {
                return _ledger.Where(e => e.Destination == TargetDestination.LocalComputer && e.Direction == EventDirection.Internal).ToList();
            }
            catch
            {
                return Array.Empty<DestinationEvent>();
            }
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _ledger.Clear();
                _disposed = true;
            }
            GC.SuppressFinalize(this);
        }
    }
}
