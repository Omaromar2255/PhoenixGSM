using System;
using System.Collections.Generic;

namespace PhoenixGSM.OmniTrace.ProtocolInspectors;

/// <summary>
/// تصنيف الخطورة لعمليات التفليش (Risk Classifier for Flashing Operations)
/// </summary>
public static class FlashingRiskClassifier
{
    // الأقسام الحرجة التي لا يجب مسحها أو العبث بها
    private static readonly HashSet<string> CriticalPartitions = new(StringComparer.OrdinalIgnoreCase)
    {
        "boot", "recovery", "aboot", "sbl", "sbl1", "tz", "rpm", "modem", 
        "fsg", "sec", "devinfo", "nvram", "nvdata", "efs", "persist", "mdm", 
        "lk", "tee1", "tee2", "scp1", "scp2", "spmfw", "sspm", "pi_img"
    };

    private static readonly HashSet<string> HighRiskPartitions = new(StringComparer.OrdinalIgnoreCase)
    {
        "system", "vendor", "product", "odm", "oem", "userdata"
    };

    /// <summary>
    /// تقييم خطورة القسم (Evaluate partition risk)
    /// </summary>
    public static FlashingRiskLevel ClassifyPartitionRisk(string? partitionName, FlashingOperationType operation)
    {
        if (string.IsNullOrWhiteSpace(partitionName))
            return FlashingRiskLevel.Low;

        var partition = partitionName.Trim();

        // Read operations are generally low risk
        // عمليات القراءة تعتبر آمنة نسبياً
        if (operation == FlashingOperationType.Read)
            return FlashingRiskLevel.Low;

        if (CriticalPartitions.Contains(partition))
            return FlashingRiskLevel.Critical;

        if (HighRiskPartitions.Contains(partition))
            return FlashingRiskLevel.High;

        return FlashingRiskLevel.Medium;
    }

    /// <summary>
    /// تقييم خطورة العملية بشكل عام (Classify overall operation risk)
    /// </summary>
    public static FlashingRiskLevel ClassifyOperationRisk(FlashingOperationType operation)
    {
        return operation switch
        {
            FlashingOperationType.DisableAuth => FlashingRiskLevel.Critical, // تعطيل الحماية خطير جداً
            FlashingOperationType.PeekPoke => FlashingRiskLevel.Critical,    // تعديل الذاكرة الحية (ثغرات)
            FlashingOperationType.BootloaderUnlock => FlashingRiskLevel.High,
            FlashingOperationType.FormatStorage => FlashingRiskLevel.High,
            FlashingOperationType.ErasePartition => FlashingRiskLevel.Medium,
            FlashingOperationType.WritePartition => FlashingRiskLevel.Medium,
            FlashingOperationType.PatchMemory => FlashingRiskLevel.High,
            FlashingOperationType.Read => FlashingRiskLevel.Low,
            FlashingOperationType.QueryChipInfo => FlashingRiskLevel.Safe,
            _ => FlashingRiskLevel.Low
        };
    }
}
