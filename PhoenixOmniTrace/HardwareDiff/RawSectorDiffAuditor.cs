using System;
using System.Collections.Generic;

namespace PhoenixGSM.OmniTrace.HardwareDiff;

/// <summary>
/// نتيجة فحص وتدقيق الفروقات في أقسام وذاكرة الهاتف الفيزيائية
/// Result of raw partition hash differential inspection
/// </summary>
public record RawPartitionAuditResult(
    bool HasModifications,
    List<string> ModifiedPartitions,
    List<string> AddedPartitions,
    List<string> RemovedPartitions,
    string Summary);

/// <summary>
/// مدقق ومطابق قطاعات وأقسام التخزين الفيزيائية للهاتف (eMMC / UFS Raw Partitions)
/// Audits raw storage partition hashes before and after vetting to catch low-level flash writes
/// </summary>
public class RawSectorDiffAuditor : IDisposable
{
    public event Action<RawPartitionAuditResult>? OnRawSectorModificationDetected;

    /// <summary>
    /// مقارنة جداول التجزئة للأقسام الخام قبل وبعد جلسة الفحص
    /// Compares partition hash manifests before and after vetting
    /// </summary>
    public RawPartitionAuditResult ComparePartitionHashes(
        IDictionary<string, string> beforeHashes,
        IDictionary<string, string> afterHashes)
    {
        var modified = new List<string>();
        var added = new List<string>();
        var removed = new List<string>();

        try
        {
            foreach (var (part, beforeHash) in beforeHashes)
            {
                if (afterHashes.TryGetValue(part, out var afterHash))
                {
                    if (!string.Equals(beforeHash, afterHash, StringComparison.OrdinalIgnoreCase))
                    {
                        modified.Add(part);
                    }
                }
                else
                {
                    removed.Add(part);
                }
            }

            foreach (var part in afterHashes.Keys)
            {
                if (!beforeHashes.ContainsKey(part))
                {
                    added.Add(part);
                }
            }

            bool hasChanges = modified.Count > 0 || added.Count > 0 || removed.Count > 0;
            string summary = hasChanges
                ? $"تعديلات مكتشفة في أقسام الفلاش الخام: {modified.Count} معدل، {added.Count} مضاف، {removed.Count} محذوف"
                : "جميع أقسام التخزين الفيزيائية متطابقة 100% دون أي تعديل خفي.";

            var result = new RawPartitionAuditResult(hasChanges, modified, added, removed, summary);

            if (hasChanges)
            {
                OnRawSectorModificationDetected?.Invoke(result);
            }

            return result;
        }
        catch (Exception ex)
        {
            return new RawPartitionAuditResult(false, [], [], [], $"خطأ في المقارنة: {ex.Message}");
        }
    }

    public void Dispose()
    {
        GC.SuppressFinalize(this);
    }
}
