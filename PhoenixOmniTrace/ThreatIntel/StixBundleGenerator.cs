using System;
using System.Collections.Generic;
using System.Text.Json;
using PhoenixGSM.OmniTrace.ForensicTimeline;

namespace PhoenixGSM.OmniTrace.ThreatIntel;

/// <summary>
/// Serializes forensic findings and detected IOCs into standard STIX 2.1 JSON format
/// تسلسل النتائج الجنائية والمؤشرات المكتشفة إلى تنسيق STIX 2.1 القياسي
/// </summary>
public class StixBundleGenerator : IDisposable
{
    public string GenerateStix21Bundle(string reportName, IEnumerable<IocEntry> iocs, IEnumerable<TimelineEntry> observations)
    {
        try
        {
            var bundleId = $"bundle--{Guid.NewGuid()}";
            var stixObjects = new List<object>();

            // إضافة تقرير
            // Add Report
            var reportId = $"report--{Guid.NewGuid()}";
            stixObjects.Add(new
            {
                type = "report",
                id = reportId,
                name = reportName,
                published = DateTime.UtcNow.ToString("o"),
                object_refs = new List<string>()
            });

            // إضافة المؤشرات
            // Add Indicators
            foreach (var ioc in iocs)
            {
                stixObjects.Add(new
                {
                    type = "indicator",
                    id = $"indicator--{Guid.NewGuid()}",
                    name = ioc.ThreatName,
                    pattern = $"[{ioc.Type} = '{ioc.Value}']",
                    valid_from = DateTime.UtcNow.ToString("o")
                });
            }

            var bundle = new
            {
                type = "bundle",
                id = bundleId,
                objects = stixObjects
            };

            return JsonSerializer.Serialize(bundle, new JsonSerializerOptions { WriteIndented = true });
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[STIX] Error generating bundle: {ex.Message}");
            return "{}";
        }
    }

    public void Dispose()
    {
        // لا يوجد موارد للتنظيف
        // No resources to clean
    }
}
