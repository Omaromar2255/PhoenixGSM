using System;

namespace PhoenixGSM.OmniTrace.ModemMonitoring
{
    // مسارات المودم - Modem Routes
    public enum ModemRoute
    {
        UsbCdcAcm,        // مسار الاتصال التسلسلي (AT Commands)
        VendorDiagBinary, // مسار تشخيص الشركة المصنعة (Qualcomm DIAG)
        AdbRilInternal    // مسار طبقة واجهة الراديو عبر ADB
    }

    // فئات المخاطر - Risk Categories
    public enum ModemRiskCategory
    {
        InfoQuery,             // استعلام عن معلومات - Info Query
        SimLockTampering,      // تلاعب بقفل الشبكة - Sim/Network Lock Tampering
        RadioControl,          // تحكم في الراديو - Radio Control
        SmsCallOperations,     // عمليات الرسائل والمكالمات - SMS/Call Operations
        VendorSpecificHighRisk,// أوامر خطيرة خاصة بالشركة المصنعة - Vendor Specific High Risk
        BasebandMemoryNvWrite  // كتابة في ذاكرة النطاق الأساسي - Baseband Memory / NV Write
    }

    // نموذج حدث أمر المودم - Modem Command Event Model
    public record ModemCommandEvent(
        ModemRoute Route,
        string CommandText,
        ModemRiskCategory RiskCategory,
        int RiskLevel,
        string Description,
        string TargetNodeOrPort,
        DateTime Timestamp,
        byte[]? RawBytes
    );
}
