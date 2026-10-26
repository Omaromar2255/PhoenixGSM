namespace PhoenixOmniTrace.L24_SourceSentinel.Models;

/// <summary>
/// مراحل المراقبة الجنائية لاصطياد الأوامر والملفات
/// </summary>
public enum SentinelStage
{
    RamUnpackOrModuleLoad = 0,
    PortAndDeviceRadar = 1,
    LocalFilePreparation = 2,
    PortConfiguration = 3,
    RawCommandExecution = 4,
    NetworkPreEncryption = 5
}

/// <summary>
/// النطاق التشغيلي للحدث (منفذ فعلياً للجهاز، مكتشف بالذاكرة، أو رادار وملفات)
/// </summary>
public enum L24CommandScope
{
    ExecutedOnDevice = 0,
    DiscoveredInRam = 1,
    RadarAndFiles = 2
}

/// <summary>
/// وضع اكتشاف الأوامر من الذاكرة الرام
/// </summary>
public enum L24DiscoveryMode
{
    ExecutedOnly = 0,
    PhoneCommandsInRam = 1,
    FullRamDiscovery = 2
}

/// <summary>
/// الفئات التصنيفية الـ 10 للأوامر في الطبقة 24
/// </summary>
public enum L24CommandGroup
{
    ModemAt = 0,
    MediaTek = 1,
    Qualcomm = 2,
    AppleIos = 3,
    AdbFastboot = 4,
    ServerCloudLogin = 5,
    FileTransfer = 6,
    ArchiveUnpack = 7,
    CryptoAuth = 8,
    OtherCommands = 9
}
