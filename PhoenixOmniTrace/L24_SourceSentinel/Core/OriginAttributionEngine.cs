using System;
using System.Collections.Concurrent;
using System.IO;
using PhoenixOmniTrace.L24_SourceSentinel.Models;

namespace PhoenixOmniTrace.L24_SourceSentinel.Core;

public sealed class OriginAttributionEngine
{
    private readonly ConcurrentDictionary<string, TrackedHandleInfo> _handles = new();
    private readonly ConcurrentDictionary<string, int> _originCounter = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, int> _categoryCounter = new(StringComparer.OrdinalIgnoreCase);

    public void RegisterHandle(int pid, IntPtr handle, string resourcePath, string callerOrigin)
    {
        string key = $"{pid}:{handle.ToInt64()}";
        var info = new TrackedHandleInfo
        {
            HandleValue = handle,
            ProcessId = pid,
            TargetPath = resourcePath,
            ResourceType = TrackedHandleInfo.DetectResourceType(resourcePath),
            OpeningCallerOrigin = callerOrigin,
            OpenedTimestamp = DateTime.UtcNow
        };
        _handles[key] = info;
    }

    public string LookupResourceByHandle(int pid, IntPtr handle, string fallbackName)
    {
        string key = $"{pid}:{handle.ToInt64()}";
        if (_handles.TryGetValue(key, out var info) && !string.IsNullOrWhiteSpace(info.TargetPath))
        {
            return info.TargetPath;
        }
        return fallbackName;
    }

    public void TrackEvent(SourceTelemetryEvent evt)
    {
        string originKey = string.IsNullOrWhiteSpace(evt.CallerModuleOrigin) ? "Unknown" : evt.CallerModuleOrigin;
        // تقصير اسم الأصل إذا كان مساراً كاملاً للعرض الإحصائي الأنيق
        if (originKey.Contains('\\'))
        {
            originKey = Path.GetFileName(originKey);
        }
        _originCounter.AddOrUpdate(originKey, 1, (_, count) => count + 1);

        string catKey = string.IsNullOrWhiteSpace(evt.CommandCategory) ? "Unclassified" : evt.CommandCategory;
        _categoryCounter.AddOrUpdate(catKey, 1, (_, count) => count + 1);
    }

    public IReadOnlyDictionary<string, int> GetOriginDistribution() => _originCounter;
    public IReadOnlyDictionary<string, int> GetCategoryDistribution() => _categoryCounter;

    public void Clear()
    {
        _handles.Clear();
        _originCounter.Clear();
        _categoryCounter.Clear();
    }
}
