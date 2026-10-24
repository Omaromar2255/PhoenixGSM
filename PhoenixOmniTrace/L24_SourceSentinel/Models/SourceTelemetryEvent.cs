using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text;

namespace PhoenixOmniTrace.L24_SourceSentinel.Models;

public enum SentinelStage
{
    RamUnpackOrModuleLoad = 0,
    PortAndDeviceRadar = 1,
    LocalFilePreparation = 2,
    PortConfiguration = 3,
    RawCommandExecution = 4,
    NetworkPreEncryption = 5
}

public enum L24CommandScope
{
    ExecutedOnDevice = 0,
    DiscoveredInRam = 1,
    RadarAndFiles = 2
}

public enum L24DiscoveryMode
{
    ExecutedOnly = 0,
    PhoneCommandsInRam = 1,
    FullRamDiscovery = 2
}

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

public static class L24CommandClassifier
{
    public static bool IsUrlOrNetworkOrAuth(SourceTelemetryEvent? evt)
    {
        if (evt == null) return false;
        if (evt.Stage == SentinelStage.NetworkPreEncryption) return true;
        if (evt.CommandGroup == L24CommandGroup.ServerCloudLogin) return true;

        string cat = (evt.CommandCategory ?? string.Empty).ToLowerInvariant();
        string api = (evt.HookedApiName ?? string.Empty).ToLowerInvariant();
        string txt = $"{evt.DecodedCommandText} {evt.PureCommandText} {evt.TargetResource}".ToLowerInvariant();

        if (cat.Contains("url") || cat.Contains("http") || cat.Contains("network") ||
            cat.Contains("cloud") || cat.Contains("server") || cat.Contains("login") ||
            cat.Contains("auth") || cat.Contains("session") || cat.Contains("token") ||
            cat.Contains("outbound") || cat.Contains("inbound"))
            return true;

        if (api.Contains("url") || api.Contains("network") || api.Contains("clipboard") || api.Contains("http"))
            return true;

        if (txt.Contains("http://") || txt.Contains("https://") || txt.Contains("wss://") || txt.Contains("ws://"))
            return true;

        return false;
    }

    public static L24CommandScope DetermineScope(string hookedApiName, SentinelStage stage, string commandCategory, string decodedText = "", string rawCommand = "")
    {
        string api = hookedApiName ?? string.Empty;
        string cat = commandCategory ?? string.Empty;
        string txt = $"{decodedText} {rawCommand}".ToLowerInvariant();

        // 1. استبعاد تام للروابط وطلبات الشبكة والسيرفر والمصادقة من نطاق الأوامر الفعلية للجهاز وتوجيهها للذاكرة/الشبكة
        if (stage == SentinelStage.NetworkPreEncryption ||
            api.Contains("Network", StringComparison.OrdinalIgnoreCase) ||
            api.Contains("Url", StringComparison.OrdinalIgnoreCase) ||
            api.Contains("Clipboard", StringComparison.OrdinalIgnoreCase) ||
            cat.Contains("Server", StringComparison.OrdinalIgnoreCase) ||
            cat.Contains("Cloud", StringComparison.OrdinalIgnoreCase) ||
            cat.Contains("Network", StringComparison.OrdinalIgnoreCase) ||
            cat.Contains("URL", StringComparison.OrdinalIgnoreCase) ||
            cat.Contains("Login", StringComparison.OrdinalIgnoreCase) ||
            cat.Contains("Account", StringComparison.OrdinalIgnoreCase) ||
            cat.Contains("Outbound", StringComparison.OrdinalIgnoreCase) ||
            cat.Contains("Inbound", StringComparison.OrdinalIgnoreCase) ||
            txt.Contains("http://") || txt.Contains("https://") || txt.Contains("wss://") || txt.Contains("ws://") ||
            txt.Contains("host:") || txt.Contains("authorization:") || txt.Contains("bearer "))
        {
            return L24CommandScope.DiscoveredInRam;
        }

        if (api.Equals("LiveRAM_UniversalInterceptor", StringComparison.OrdinalIgnoreCase) ||
            api.Equals("PE_ExportTableAuditor", StringComparison.OrdinalIgnoreCase))
        {
            if (stage == SentinelStage.RamUnpackOrModuleLoad)
                return L24CommandScope.RadarAndFiles;

            return L24CommandScope.DiscoveredInRam;
        }

        if (stage is SentinelStage.RamUnpackOrModuleLoad or SentinelStage.PortAndDeviceRadar or SentinelStage.LocalFilePreparation ||
            api.Equals("ModuleLoaderSnap", StringComparison.OrdinalIgnoreCase) ||
            api.Equals("SERIALCOMM_SmartClassifier", StringComparison.OrdinalIgnoreCase) ||
            api.Contains("FileSystemWatcher", StringComparison.OrdinalIgnoreCase) ||
            cat.Contains("Helper File", StringComparison.OrdinalIgnoreCase) ||
            cat.Contains("Firmware / Archive Extraction", StringComparison.OrdinalIgnoreCase) ||
            cat.Contains("Boot Loader / Firmware File Access", StringComparison.OrdinalIgnoreCase) ||
            cat.Contains("Archived File", StringComparison.OrdinalIgnoreCase))
        {
            return L24CommandScope.RadarAndFiles;
        }

        return L24CommandScope.ExecutedOnDevice;
    }

    public static L24CommandGroup DetermineGroup(string commandCategory, string decodedText, string rawCommand)
    {
        string cat = (commandCategory ?? string.Empty).ToLowerInvariant();
        string txt = $"{decodedText} {rawCommand}".ToLowerInvariant();

        if (cat.Contains("server") || cat.Contains("cloud") || cat.Contains("network") || cat.Contains("http") ||
            cat.Contains("url") || cat.Contains("login") || cat.Contains("account") || cat.Contains("session") ||
            cat.Contains("outbound") || cat.Contains("inbound") || cat.Contains("c2") || cat.Contains("dns") ||
            txt.Contains("http://") || txt.Contains("https://") || txt.Contains("wss://") || txt.Contains("ws://") ||
            txt.Contains("host:") || txt.Contains("authorization:") || txt.Contains("bearer ") ||
            txt.Contains("user-agent:") || txt.Contains("content-type:") || txt.Contains("http/1.") ||
            txt.Contains("\"username\"") || txt.Contains("\"password\"") || txt.Contains("\"access_token\"") ||
            txt.Contains("\"login\"") || txt.Contains("\"license"))
        {
            return L24CommandGroup.ServerCloudLogin;
        }

        if (cat.Contains("apple") || cat.Contains("ios") || cat.Contains("lockdown") || cat.Contains("usbmux") ||
            cat.Contains("iboot") || cat.Contains("dfu") || cat.Contains("pongo") || cat.Contains("purple") ||
            cat.Contains("syscfg") || cat.Contains("ramdisk") || cat.Contains("afc") || cat.Contains("mobilegestalt") ||
            txt.Contains("lockdownd") || txt.Contains("mobilegestalt") || txt.Contains("activation_record") ||
            txt.Contains("ic-info.sisv") || txt.Contains("cfa6lpaa") || txt.Contains("pwnd:[") ||
            txt.Contains("cpid:") || txt.Contains("ecid:") || txt.Contains("syscfg ") || txt.Contains("irecovery") ||
            txt.Contains("idevice") || txt.Contains("mount_apfs") || txt.Contains("mount_hfs") ||
            txt.Contains("pongo") || txt.Contains("checkm8") || txt.Contains("gaster") ||
            txt.Contains(".shsh2") || txt.Contains(".im4p") || txt.Contains(".img4"))
        {
            return L24CommandGroup.AppleIos;
        }

        if (cat.Contains("mtk") || cat.Contains("mediatek") || cat.Contains("brom") || cat.Contains("xflash") ||
            cat.Contains("da command") || cat.Contains("preloader") || txt.Contains("mtk_") ||
            txt.Contains("brom_") || txt.Contains("preloader") || txt.Contains("0e8d") ||
            txt.Contains("download-agent") || txt.Contains("sla_challenge") || txt.Contains("daa_challenge"))
        {
            return L24CommandGroup.MediaTek;
        }

        if (cat.Contains("qualcomm") || cat.Contains("firehose") || cat.Contains("sahara") || cat.Contains("edl") ||
            cat.Contains("diag") || cat.Contains("qmsl") || txt.Contains("qlib_") || txt.Contains("qphonems_") ||
            txt.Contains("fh_loader") || txt.Contains("qsahara") || txt.Contains("rawprogram") ||
            txt.Contains("prog_emmc") || txt.Contains("prog_ufs") || txt.Contains("<program") ||
            txt.Contains("<erase") || txt.Contains("<patch") || txt.Contains("<configure") ||
            txt.Contains("<peek") || txt.Contains("<poke") || txt.Contains("05c6") || txt.Contains("9008"))
        {
            return L24CommandGroup.Qualcomm;
        }

        if (cat.Contains("crypto") || cat.Contains("decrypt") || cat.Contains("encrypt") || cat.Contains("seed") ||
            cat.Contains("security key") || txt.Contains("openssl ") || txt.Contains("aes-") ||
            txt.Contains("cryptdecrypt") || txt.Contains("cryptencrypt") || txt.Contains("bcrypt") ||
            txt.Contains("ofp_decrypt") || txt.Contains("ops_decrypt") || txt.Contains("ozipdecrypt") ||
            txt.Contains("da_pl_crypto") || txt.Contains("pbkdf2") || txt.Contains("hmac_sha") ||
            txt.Contains("akseedno") || txt.Contains("mslsecur") || txt.Contains("oem_pk_hash"))
        {
            return L24CommandGroup.CryptoAuth;
        }

        if (cat.Contains("archive") || cat.Contains("unpack") || cat.Contains("compression") ||
            txt.Contains("7z ") || txt.Contains("7za ") || txt.Contains("unzip ") || txt.Contains("tar -") ||
            txt.Contains("lz4 ") || txt.Contains("simg2img") || txt.Contains("img2simg") || txt.Contains("lpunpack") ||
            txt.Contains("payload-dumper") || txt.Contains("zstd ") || txt.Contains("brotli ") || txt.Contains("gunzip") ||
            txt.Contains("unrar ") || txt.Contains("extracttodirectory") || txt.Contains("cabextract"))
        {
            return L24CommandGroup.ArchiveUnpack;
        }

        if (cat.Contains("transfer") || cat.Contains("upload") || cat.Contains("download") || cat.Contains("push") ||
            cat.Contains("pull") || cat.Contains("boot loader") || cat.Contains("firmware file") ||
            cat.Contains("helper file") || cat.Contains("archived") ||
            txt.Contains("adb push") || txt.Contains("adb pull") || txt.Contains("sync:send") || txt.Contains("sync:recv") ||
            txt.Contains("sync:data") || txt.Contains("scp ") || txt.Contains("sftp ") || txt.Contains("curl ") ||
            txt.Contains("wget ") || txt.Contains("invoke-webrequest") || txt.Contains("downloadfile") ||
            txt.Contains("uploadfile") || txt.Contains("ideviceinstaller") || txt.Contains("install-write"))
        {
            return L24CommandGroup.FileTransfer;
        }

        if (cat.Contains("modem") || cat.Contains("at command") || cat.Contains("ril") || cat.Contains("baudrate") ||
            rawCommand.StartsWith("AT", StringComparison.OrdinalIgnoreCase) || rawCommand.StartsWith("+"))
        {
            return L24CommandGroup.ModemAt;
        }

        if (cat.Contains("adb") || cat.Contains("fastboot") || cat.Contains("shell") || cat.Contains("heredoc") ||
            txt.Contains("adb ") || txt.Contains("fastboot ") || txt.Contains("shell:") || txt.Contains("host:") ||
            txt.Contains("getprop") || txt.Contains("setprop") || txt.Contains("service call") || txt.Contains("pm ") ||
            txt.Contains("am ") || txt.Contains("/data/local/tmp"))
        {
            return L24CommandGroup.AdbFastboot;
        }

        return L24CommandGroup.OtherCommands;
    }

    public static string GetGroupArabicTitle(L24CommandGroup group) => group switch
    {
        L24CommandGroup.ModemAt => "📻 أوامر المودم (Modem / AT)",
        L24CommandGroup.MediaTek => "🔶 ميدياتك (MTK / BROM / DA)",
        L24CommandGroup.Qualcomm => "🔷 كوالكوم و EDL (Sahara / Firehose / DIAG)",
        L24CommandGroup.AppleIos => "🍎 أبل (Apple iOS / DFU / Lockdown / Pongo)",
        L24CommandGroup.AdbFastboot => "🤖 أندرويد (ADB / Fastboot / Shell)",
        L24CommandGroup.ServerCloudLogin => "🌐 الروابط والخوادم وتسجيل الدخول (URLs / Login / Cloud)",
        L24CommandGroup.FileTransfer => "📤 نقل وملفات محفوظة (Transfer / Saved Files)",
        L24CommandGroup.ArchiveUnpack => "📦 فك الضغط والصور (Unpack / LZ4 / Sparse)",
        L24CommandGroup.CryptoAuth => "🔐 التشفير والمفاتيح والبذور (Crypto / Keys / Seeds)",
        _ => "🧩 أوامر وعمليات أخرى (Odin / SPD / Logs / Other)"
    };

    public static string GetGroupShortSlug(L24CommandGroup group) => group switch
    {
        L24CommandGroup.ModemAt => "Modem_AT",
        L24CommandGroup.MediaTek => "MediaTek",
        L24CommandGroup.Qualcomm => "Qualcomm_EDL",
        L24CommandGroup.AppleIos => "Apple_iOS",
        L24CommandGroup.AdbFastboot => "ADB_Fastboot",
        L24CommandGroup.ServerCloudLogin => "Server_URLs_Login",
        L24CommandGroup.FileTransfer => "File_Transfer_Saved",
        L24CommandGroup.ArchiveUnpack => "Archive_Unpack",
        L24CommandGroup.CryptoAuth => "Crypto_Keys_Seeds",
        _ => "Other_Commands"
    };

    public static bool IsPurePhoneTestable(SourceTelemetryEvent evt, out string cleanTestableCommand)
    {
        cleanTestableCommand = string.Empty;
        if (evt == null) return false;

        string cat = evt.CommandCategory ?? string.Empty;
        if (cat.Contains("Response", StringComparison.OrdinalIgnoreCase) ||
            cat.Contains("Helper File", StringComparison.OrdinalIgnoreCase) ||
            cat.Contains("Module", StringComparison.OrdinalIgnoreCase) ||
            cat.Contains("Server", StringComparison.OrdinalIgnoreCase) ||
            cat.Contains("Login", StringComparison.OrdinalIgnoreCase) ||
            cat.Contains("Inbound", StringComparison.OrdinalIgnoreCase) ||
            cat.Contains("URL", StringComparison.OrdinalIgnoreCase) ||
            cat.Contains("Network", StringComparison.OrdinalIgnoreCase) ||
            cat.Contains("Cloud", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (IsUrlOrNetworkOrAuth(evt)) return false;

        string raw = evt.PureCommandText;
        if (string.IsNullOrWhiteSpace(raw) || raw.Length < 2) return false;
        if (raw.Contains("\",\"", StringComparison.Ordinal) || raw.Contains("\", \"", StringComparison.Ordinal))
            return false;

        string trimmed = raw.Trim();

        if (trimmed.StartsWith("AT+", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("AT*", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("AT^", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("AT%", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("AT$", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("AT#", StringComparison.OrdinalIgnoreCase) ||
            trimmed.Equals("ATE0", StringComparison.OrdinalIgnoreCase) ||
            trimmed.Equals("ATE1", StringComparison.OrdinalIgnoreCase) ||
            trimmed.Equals("ATI", StringComparison.OrdinalIgnoreCase) ||
            trimmed.Equals("ATZ", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("060100", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("120D00", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("514200", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("516400", StringComparison.OrdinalIgnoreCase))
        {
            cleanTestableCommand = trimmed;
            return true;
        }

        if (trimmed.StartsWith("adb ", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("fastboot ", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("shell:", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("reboot:", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("su -c", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("getprop", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("setprop", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("service call", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("pm ", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("am ", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("dd if=", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("chmod ", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("/data/local/tmp/", StringComparison.OrdinalIgnoreCase))
        {
            cleanTestableCommand = trimmed.StartsWith("shell:", StringComparison.OrdinalIgnoreCase)
                ? $"adb shell \"{trimmed[6..].Trim()}\""
                : trimmed;
            return true;
        }

        if ((trimmed.StartsWith("<?xml", StringComparison.OrdinalIgnoreCase) && trimmed.Contains("<data>", StringComparison.OrdinalIgnoreCase)) ||
            trimmed.StartsWith("<program ", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("<erase ", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("<patch ", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("<read ", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("<configure ", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("<peek ", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("<poke ", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("CMD_", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("Brom_", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("DA_", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("XFLASH_", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("MTK_", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("[BROM]", StringComparison.OrdinalIgnoreCase))
        {
            cleanTestableCommand = trimmed;
            return true;
        }

        if (trimmed.StartsWith("irecovery", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("idevice", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("syscfg ", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("setenv ", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("getenv ", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("sep auto", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("fuse lock", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("mount_apfs", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("mount_hfs", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("nvram ", StringComparison.OrdinalIgnoreCase))
        {
            cleanTestableCommand = trimmed;
            return true;
        }

        return false;
    }
}

public sealed class SourceTelemetryEvent : INotifyPropertyChanged
{
    private string _targetResource = string.Empty;
    private string _commandCategory = string.Empty;
    private string _decodedCommandText = string.Empty;
    private string _rawPayloadHex = string.Empty;
    private int _payloadSize;
    private string _pureCommandText = string.Empty;
    private string _savedFilePath = string.Empty;

    public Guid EventId { get; init; } = Guid.NewGuid();
    public DateTime Timestamp { get; init; } = DateTime.UtcNow;
    public int ProcessId { get; init; }
    public int ThreadId { get; init; }
    public SentinelStage Stage { get; init; }
    public long MemoryAddress { get; init; }

    public string HookedApiName { get; init; } = string.Empty;
    public string CallerModuleOrigin { get; init; } = string.Empty;

    public string TargetResource
    {
        get => _targetResource;
        set { if (_targetResource != value) { _targetResource = value; OnPropertyChanged(); } }
    }

    public string CommandCategory
    {
        get => _commandCategory;
        set
        {
            if (_commandCategory != value)
            {
                _commandCategory = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(CommandGroup));
                OnPropertyChanged(nameof(CommandGroupBadge));
            }
        }
    }

    public string DecodedCommandText
    {
        get => _decodedCommandText;
        set
        {
            if (_decodedCommandText != value)
            {
                _decodedCommandText = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(PureCommandText));
                OnPropertyChanged(nameof(CommandGroup));
                OnPropertyChanged(nameof(CommandGroupBadge));
            }
        }
    }

    public string RawPayloadHex
    {
        get => _rawPayloadHex;
        set
        {
            if (_rawPayloadHex != value)
            {
                _rawPayloadHex = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(PureCommandText));
            }
        }
    }

    public int PayloadSize
    {
        get => _payloadSize;
        set { if (_payloadSize != value) { _payloadSize = value; OnPropertyChanged(); } }
    }

    public string SavedFilePath
    {
        get => _savedFilePath;
        set { if (_savedFilePath != value) { _savedFilePath = value; OnPropertyChanged(); } }
    }

    public string PureCommandText
    {
        get
        {
            if (!string.IsNullOrWhiteSpace(_pureCommandText))
                return _pureCommandText;

            if (!string.IsNullOrWhiteSpace(_rawPayloadHex) && _rawPayloadHex.Length % 2 == 0)
            {
                try
                {
                    string utf8 = Encoding.UTF8.GetString(Convert.FromHexString(_rawPayloadHex)).Trim();
                    if (!string.IsNullOrWhiteSpace(utf8) && IsMostlyPrintable(utf8))
                        return utf8;
                }
                catch { }
            }

            int colonIdx = _decodedCommandText.IndexOf(':');
            if (colonIdx >= 0 && colonIdx + 1 < _decodedCommandText.Length &&
                !_decodedCommandText.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
                !_decodedCommandText.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                return _decodedCommandText[(colonIdx + 1)..].Trim();
            }

            return _decodedCommandText.Trim();
        }
        set
        {
            if (_pureCommandText != value)
            {
                _pureCommandText = value;
                OnPropertyChanged();
            }
        }
    }

    public L24CommandScope Scope => L24CommandClassifier.DetermineScope(HookedApiName, Stage, CommandCategory, DecodedCommandText, PureCommandText);
    public L24CommandGroup CommandGroup => L24CommandClassifier.DetermineGroup(CommandCategory, DecodedCommandText, PureCommandText);
    public string CommandGroupBadge => L24CommandClassifier.GetGroupArabicTitle(CommandGroup);

    public bool IsPhoneResponse =>
        CommandCategory.Contains("Response", StringComparison.OrdinalIgnoreCase) ||
        DecodedCommandText.Contains("رد الهاتف", StringComparison.OrdinalIgnoreCase) ||
        DecodedCommandText.Contains("رد المودم", StringComparison.OrdinalIgnoreCase);

    public string ScopeBadge => Scope switch
    {
        L24CommandScope.ExecutedOnDevice => "⚡ منفذ فعلياً للجهاز",
        L24CommandScope.DiscoveredInRam => "🧠 مكتشف في الذاكرة",
        _ => "📡 رادار / ملفات محفوظة"
    };

    public string StageBadge => Stage switch
    {
        SentinelStage.RamUnpackOrModuleLoad => "🧠 RAM / Module",
        SentinelStage.PortAndDeviceRadar => "📡 Radar / Scan",
        SentinelStage.LocalFilePreparation => "💾 Saved File / Prep",
        SentinelStage.PortConfiguration => "⚙️ Port Config",
        SentinelStage.RawCommandExecution => Scope == L24CommandScope.DiscoveredInRam ? "🧠 RAM Discovered" : "⚡ Executed Command",
        SentinelStage.NetworkPreEncryption => "🌐 Network / Login / URL",
        _ => Stage.ToString()
    };

    public string FormattedTimestamp => Timestamp.ToLocalTime().ToString("HH:mm:ss.fff");
    public string TimeFormatted => FormattedTimestamp;
    public string ProcessThreadInfo => $"{ProcessId}:{ThreadId}";

    private static bool IsMostlyPrintable(string s)
    {
        int printable = 0;
        foreach (char c in s)
        {
            if ((c >= 32 && c <= 126) || c == '\r' || c == '\n' || c == '\t')
                printable++;
        }
        return s.Length > 0 && (double)printable / s.Length >= 0.85;
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? propName = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propName));
}
