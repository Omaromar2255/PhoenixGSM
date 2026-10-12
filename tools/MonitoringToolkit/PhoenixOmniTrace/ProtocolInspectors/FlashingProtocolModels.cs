using System;

namespace PhoenixGSM.OmniTrace.ProtocolInspectors;

/// <summary>
/// مستوى الخطورة لعملية التفليش (Risk level for flashing operation)
/// </summary>
public enum FlashingRiskLevel
{
    Safe = 0,       // آمن
    Low = 1,        // منخفض
    Medium = 2,     // متوسط
    High = 3,       // عالي
    Critical = 4    // حرج جداً
}

/// <summary>
/// نوع العملية (Operation type)
/// </summary>
public enum FlashingOperationType
{
    Unknown = 0,
    Read = 1,               // قراءة
    WritePartition = 2,     // كتابة قسم
    ErasePartition = 3,     // مسح قسم
    PatchMemory = 4,        // تعديل الذاكرة
    PeekPoke = 5,           // فحص وتعديل الذاكرة الحية
    BootloaderUnlock = 6,   // فتح البوت لودر
    DisableAuth = 7,        // تعطيل الحماية
    FormatStorage = 8,      // تهيئة التخزين
    QueryChipInfo = 9       // استعلام عن معلومات الشريحة
}

/// <summary>
/// نتيجة فحص التفليش (Flashing inspection result)
/// </summary>
public record FlashingInspectionResult(
    string Protocol,
    FlashingOperationType Operation,
    string? TargetPartition,
    long? MemoryAddress,
    long? Length,
    FlashingRiskLevel RiskLevel,
    string Description,
    string? RawXmlOrCommand
);
