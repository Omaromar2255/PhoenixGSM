using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace PhoenixGSM.OmniTrace.ForensicTimeline;

/// <summary>
/// Unified forensic timeline aggregator
/// مجمع الجدول الزمني الجنائي الموحد
/// </summary>
public class TimelineEntry
{
    public DateTime Timestamp { get; set; }
    public string SensorSource { get; set; } = string.Empty;
    public string EventType { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public string ThreatLevel { get; set; } = "Low";
    public string Description { get; set; } = string.Empty;
}

public class EventTimeline : IDisposable
{
    private readonly ConcurrentBag<TimelineEntry> _timeline = new();
    
    public EventTimeline()
    {
        // تهيئة الجدول الزمني
        // Initialize timeline
    }

    /// <summary>
    /// Add an event to the timeline.
    /// إضافة حدث إلى الجدول الزمني.
    /// </summary>
    public void AddTimelineEvent(TimelineEntry entry)
    {
        try
        {
            _timeline.Add(entry);
        }
        catch (Exception ex)
        {
            // Fail-open: log error but do not crash
            // فشل مفتوح: سجل الخطأ ولكن لا تعطل النظام
            Console.WriteLine($"[Timeline] Error adding event: {ex.Message}");
        }
    }

    public IEnumerable<TimelineEntry> GetChronologicalEvents()
    {
        return _timeline.OrderBy(e => e.Timestamp);
    }

    public IEnumerable<TimelineEntry> GetEventsByProcess(int pid)
    {
        return _timeline.Where(e => e.ProcessId == pid).OrderBy(e => e.Timestamp);
    }

    public IEnumerable<TimelineEntry> GetEventsByThreatLevel(string severity)
    {
        return _timeline.Where(e => e.ThreatLevel.Equals(severity, StringComparison.OrdinalIgnoreCase)).OrderBy(e => e.Timestamp);
    }

    public void Dispose()
    {
        _timeline.Clear();
    }
}
