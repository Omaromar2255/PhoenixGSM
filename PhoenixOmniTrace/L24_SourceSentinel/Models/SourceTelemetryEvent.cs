using System;

namespace PhoenixOmniTrace.L24_SourceSentinel.Models;

public enum SentinelStage
{
    RamUnpackOrModuleLoad = 0, // فك كود في الرام أو استدعاء ملف خارجي (DLL/EXE)
    PortAndDeviceRadar = 1,    // البحث عن منفذ COM أو جهاز USB عبر Registry/SetupAPI/WMI
    LocalFilePreparation = 2,  // قراءة/كتابة ملفات محلية على الكمبيوتر قبل إرسال الأمر
    PortConfiguration = 3,     // فتح المنفذ أو ضبط السرعة (BaudRate / WinUSB Init)
    RawCommandExecution = 4,   // إرسال الأمر الفعلي (AT, MTK, EDL, ADB, Pipe, Process)
    NetworkPreEncryption = 5   // بيانات شبكة صادرة من الأداة قبل التشفير
}

public sealed class SourceTelemetryEvent
{
    public Guid EventId { get; init; } = Guid.NewGuid();
    public DateTime Timestamp { get; init; } = DateTime.UtcNow;
    public int ProcessId { get; init; }
    public int ThreadId { get; init; }
    public SentinelStage Stage { get; init; }
    
    // اسم الدالة الأصلية التي تم التقاط الحدث منها (مثل NtWriteFile, SetupDiGetClassDevsW, LdrLoadDll)
    public string HookedApiName { get; init; } = string.Empty;
    
    // الملف أو منطقة الرام التي أصدرت هذا الأمر (مثال: ext_helper.dll + 0x2410 أو [RAM_Unpacked_0x180000])
    public string CallerModuleOrigin { get; init; } = string.Empty;
    
    // الهدف الذي تتعامل معه الأداة (مثال: \\.\COM5 أو HKLM\HARDWARE\DEVICEMAP\SERIALCOMM أو C:\temp\da.bin)
    public string TargetResource { get; set; } = string.Empty;
    
    // التصنيف التلقائي للأمر (AT Command, MTK BROM Handshake, Port Scan, Shell Pipe, File Read)
    public string CommandCategory { get; set; } = string.Empty;
    
    // النص الصريح للأمر أو الاستعلام
    public string DecodedCommandText { get; set; } = string.Empty;
    
    // البايتات الخام بصيغة Hex للمراجعة الجنائية الدقيقة
    public string RawPayloadHex { get; init; } = string.Empty;
    
    public int PayloadSize { get; init; }

    // Helper formatting properties for UI DataGrid binding
    public string StageBadge => Stage switch
    {
        SentinelStage.RamUnpackOrModuleLoad => "🧠 RAM / Module",
        SentinelStage.PortAndDeviceRadar => "📡 Radar / Scan",
        SentinelStage.LocalFilePreparation => "📁 Local File Prep",
        SentinelStage.PortConfiguration => "⚙️ Port Config",
        SentinelStage.RawCommandExecution => "⚡ Raw Command",
        SentinelStage.NetworkPreEncryption => "🌐 Network Out",
        _ => Stage.ToString()
    };

    public string FormattedTimestamp => Timestamp.ToLocalTime().ToString("HH:mm:ss.fff");
    public string TimeFormatted => FormattedTimestamp;
    public string ProcessThreadInfo => $"{ProcessId}:{ThreadId}";
}
