using System;
using System.Text;
using System.Collections.Generic;

namespace PhoenixGSM.OmniTrace.IndirectChannels;

public class OdinInspectionResult
{
    public bool IsSensitivePartitionWrite { get; set; }
    public string PartitionName { get; set; } = string.Empty;
    public string Summary { get; set; } = string.Empty;
    public bool IsLokeHandshake { get; set; }
}

public class SamsungOdinDecoder : IDisposable
{
    private readonly HashSet<string> _sensitivePartitions = new(StringComparer.OrdinalIgnoreCase)
    {
        "efs", "boot", "recovery", "param", "persistent", "sec_efs", "cp_debug"
    };

    // تحليل حزم بروتوكول Odin وتحديد الأقسام الحساسة
    public OdinInspectionResult? InspectOdinFrame(ReadOnlySpan<byte> frame)
    {
        try
        {
            if (frame.Length < 4) return null;

            var result = new OdinInspectionResult();

            // Check for LOKE handshake: ODIN (4F 44 49 4E) or LOKE
            string header = Encoding.ASCII.GetString(frame.Slice(0, 4));
            if (header == "ODIN" || header == "LOKE")
            {
                result.IsLokeHandshake = true;
                result.Summary = "LOKE Handshake detected";
                return result;
            }

            // Simple heuristic to find partition names in typical Odin chunks
            // البحث عن أسماء الأقسام الحساسة في الحزمة
            string asciiContent = Encoding.ASCII.GetString(frame);
            
            foreach (var partition in _sensitivePartitions)
            {
                if (asciiContent.Contains(partition, StringComparison.OrdinalIgnoreCase))
                {
                    result.IsSensitivePartitionWrite = true;
                    result.PartitionName = partition;
                    result.Summary = $"Sensitive partition write detected: {partition}";
                    return result;
                }
            }

            return null; // Not sensitive
        }
        catch (Exception ex)
        {
            // Fail-open: لا توقف النظام
            Console.WriteLine($"[Error] InspectOdinFrame failed: {ex.Message}");
            return null;
        }
    }

    public void Dispose()
    {
        _sensitivePartitions.Clear();
    }
}
