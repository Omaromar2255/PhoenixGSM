using System;
using System.Linq;
using System.Text;
using System.Xml.Linq;

namespace PhoenixGSM.OmniTrace.ProtocolInspectors;

/// <summary>
/// محلل أوامر كوالكوم فايرهوز (Qualcomm Firehose XML Parser)
/// </summary>
public class QualcommFirehoseParser
{
    private const string ProtocolName = "Qualcomm_Firehose";

    /// <summary>
    /// فحص حمولة XML لبروتوكول الفايرهوز (Inspect Firehose XML payload)
    /// </summary>
    public FlashingInspectionResult? InspectFirehoseXml(byte[] payload)
    {
        try
        {
            string xmlText = Encoding.UTF8.GetString(payload);
            return InspectFirehoseXml(xmlText);
        }
        catch (Exception ex)
        {
            // Fail-open: لا توقف النظام في حال خطأ التحليل
            // Do not crash the system on parsing error
            Console.WriteLine($"[FirehoseParser] Byte decoding error: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// فحص النص (Inspect text XML)
    /// </summary>
    public FlashingInspectionResult? InspectFirehoseXml(string xmlText)
    {
        if (string.IsNullOrWhiteSpace(xmlText) || !xmlText.Contains("<"))
            return null;

        try
        {
            // محاولة تنظيف النص إذا لزم الأمر
            int startIdx = xmlText.IndexOf('<');
            int endIdx = xmlText.LastIndexOf('>');
            if (startIdx >= 0 && endIdx > startIdx)
            {
                string cleanXml = xmlText.Substring(startIdx, endIdx - startIdx + 1);
                XElement root;
                try
                {
                    root = XElement.Parse(cleanXml);
                }
                catch
                {
                    // Fallback for fragments
                    root = XElement.Parse($"<root>{cleanXml}</root>").Elements().First();
                }

                return ParseCommand(root, cleanXml);
            }
        }
        catch (Exception ex)
        {
            // Fail-open try/catch pattern
            Console.WriteLine($"[FirehoseParser] XML parsing exception: {ex.Message}");
        }

        return null;
    }

    private FlashingInspectionResult? ParseCommand(XElement cmd, string rawXml)
    {
        string tagName = cmd.Name.LocalName.ToLowerInvariant();
        FlashingOperationType opType = FlashingOperationType.Unknown;
        string? partition = null;
        long? address = null;
        long? length = null;

        switch (tagName)
        {
            case "program":
                opType = FlashingOperationType.WritePartition;
                partition = cmd.Attribute("filename")?.Value ?? "unknown";
                break;
            case "erase":
                opType = FlashingOperationType.ErasePartition;
                partition = cmd.Attribute("filename")?.Value;
                break;
            case "read":
                opType = FlashingOperationType.Read;
                partition = cmd.Attribute("filename")?.Value;
                break;
            case "patch":
                opType = FlashingOperationType.PatchMemory;
                partition = cmd.Attribute("filename")?.Value;
                break;
            case "peek":
            case "poke":
                opType = FlashingOperationType.PeekPoke;
                address = ParseHexOrLong(cmd.Attribute("address64")?.Value);
                length = ParseHexOrLong(cmd.Attribute("size_in_bytes")?.Value);
                break;
            case "configure":
                opType = FlashingOperationType.QueryChipInfo;
                break;
            default:
                return null; // Not a recognized command
        }

        // استخراج المعلومات الأساسية وتصنيف الخطورة
        // Extract basic info and classify risk
        FlashingRiskLevel risk = FlashingRiskClassifier.ClassifyOperationRisk(opType);
        
        if (!string.IsNullOrEmpty(partition))
        {
            var partitionRisk = FlashingRiskClassifier.ClassifyPartitionRisk(partition, opType);
            if (partitionRisk > risk)
                risk = partitionRisk;
        }

        string desc = $"Firehose {opType} command detected.";
        if (partition != null) desc += $" Target: {partition}.";
        if (address != null) desc += $" Address: 0x{address:X}.";

        return new FlashingInspectionResult(
            Protocol: ProtocolName,
            Operation: opType,
            TargetPartition: partition,
            MemoryAddress: address,
            Length: length,
            RiskLevel: risk,
            Description: desc,
            RawXmlOrCommand: rawXml
        );
    }

    private long? ParseHexOrLong(string? val)
    {
        if (string.IsNullOrWhiteSpace(val)) return null;
        if (val.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            if (long.TryParse(val.Substring(2), System.Globalization.NumberStyles.HexNumber, null, out long res))
                return res;
        }
        else
        {
            if (long.TryParse(val, out long res))
                return res;
        }
        return null;
    }
}
