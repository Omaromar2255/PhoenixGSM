using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using PhoenixOmniTrace.L24_SourceSentinel.Models;

namespace PhoenixOmniTrace.L24_SourceSentinel.Core;

public sealed class LiveHeapCommandHunter : IDisposable
{
    private CancellationTokenSource? _cts;
    private readonly ConcurrentDictionary<int, string> _monitoredPids = new();
    private readonly ConcurrentDictionary<int, string> _childAdbPids = new();
    private readonly ConcurrentDictionary<string, DateTime> _localCooldown = new(StringComparer.OrdinalIgnoreCase);

    // 1. ذاكرة البصمة للقطع (Dirty-Chunk Hash Cache) لمنع إعادة فحص نفس الشريحة غير المتغيرة كل دورة (تسريع 30x وإلغاء تأخير الـ 7 دقائق!)
    private readonly ConcurrentDictionary<long, ulong> _chunkHashCache = new();

    // 2. قائمة النصوص الثابتة الأولية (Baseline Snapshot) لعزل أوامر وضع الخمول (Idle) عند تفعيل الخيار دون حذف أي ميزة
    private readonly ConcurrentDictionary<string, byte> _idleBaselineStrings = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<int, bool> _pidBaselineCompleted = new();
    private readonly ConcurrentDictionary<long, byte> _carvedLoaderAddresses = new();

    private volatile bool _isWinUsbOrChildAdbActive;
    private volatile bool _isRamHunterEnabled = true;
    private volatile bool _suppressIdleStaticBaseline = true;
    private volatile bool _scanDynamicHeapOnly = false;
    private volatile bool _enableInMemoryLoaderCarving = true;
    private volatile bool _isCapturingBaselineNow;
    private int _parentScanCycleCounter;

    public event Action<SourceTelemetryEvent>? OnCommandCaptured;

    public L24DiscoveryMode DiscoveryMode { get; set; } = L24DiscoveryMode.FullRamDiscovery;
    public Func<L24CommandGroup, bool>? IsCategoryEnabled { get; set; }
    public bool ExcludeUrls { get; set; } = false;

    /// <summary>
    /// خيار تشغيل أو إيقاف فاحص الرام اللحظي عند الحاجة لتوفير الأداء 100% دون المساس بالأوامر المنفذة
    /// </summary>
    public bool IsRamHunterEnabled
    {
        get => _isRamHunterEnabled;
        set => _isRamHunterEnabled = value;
    }

    /// <summary>
    /// خيار عزل وإخفاء النصوص الثابتة التي تظهر في وضع الخمول (Idle Baseline Filter) مع إمكانية إيقافه لرؤية كل نصوص البرنامج الثابتة
    /// </summary>
    public bool SuppressIdleStaticBaseline
    {
        get => _suppressIdleStaticBaseline;
        set
        {
            if (_suppressIdleStaticBaseline != value)
            {
                _suppressIdleStaticBaseline = value;
                _chunkHashCache.Clear();
            }
        }
    }

    /// <summary>
    /// خيار حصر الفحص في الـ Heap الديناميكي القابل للكتابة فقط (MEM_PRIVATE + RW) لأقصى سرعة ودقة
    /// </summary>
    public bool ScanDynamicHeapOnly
    {
        get => _scanDynamicHeapOnly;
        set
        {
            if (_scanDynamicHeapOnly != value)
            {
                _scanDynamicHeapOnly = value;
                _chunkHashCache.Clear();
            }
        }
    }

    /// <summary>
    /// خيار استخراج وحفظ ملفات البوت واللودر والـ DA والـ Firehose والـ IMG4 مباشرة من الرام حتى لو لم تحفظها الأداة على القرص
    /// </summary>
    public bool EnableInMemoryLoaderCarving
    {
        get => _enableInMemoryLoaderCarving;
        set => _enableInMemoryLoaderCarving = value;
    }

    public int BaselineStringsCount => _idleBaselineStrings.Count;

    /// <summary>
    /// التقاط بصمة الوضع الحالي (Idle Snapshot) يدوياً أو تلقائياً لاعتبار كل ما هو موجود الآن في الرام خلفية ثابتة
    /// </summary>
    public void CaptureCurrentRamAsIdleBaseline()
    {
        _isCapturingBaselineNow = true;
        _chunkHashCache.Clear();
        Task.Run(() =>
        {
            try
            {
                foreach (var target in _monitoredPids)
                {
                    ScanProcessHeapAndBuffers(target.Key, target.Value, CancellationToken.None, recordAsBaselineOnly: true);
                    _pidBaselineCompleted[target.Key] = true;
                }
            }
            catch { }
            finally
            {
                _isCapturingBaselineNow = false;
            }
        });
    }

    public void ClearIdleBaseline()
    {
        _idleBaselineStrings.Clear();
        _pidBaselineCompleted.Clear();
        _chunkHashCache.Clear();
    }

    public bool IsGroupEnabled(L24CommandGroup group)
    {
        return IsCategoryEnabled == null || IsCategoryEnabled(group);
    }

    public bool IsWinUsbOrChildAdbActive
    {
        get => _isWinUsbOrChildAdbActive;
        set => _isWinUsbOrChildAdbActive = value;
    }

    public void RegisterChildAdbProcess(int childPid, string processName)
    {
        _childAdbPids[childPid] = processName;
        _isWinUsbOrChildAdbActive = true;
    }

    private static readonly string[] AllowedShellVerbs =
    {
        "cat ", "sh ", "su ", "echo ", "dd ", "chmod ", "mount ", "rm ", "cp ", "mv ", "pm ", "am ", "setprop ", "getprop "
    };

    private static readonly HashSet<string> TruncatedAtPrefixes = new(StringComparer.OrdinalIgnoreCase)
    {
        "AT+CGM", "AT+CIM", "AT+CNM", "AT+CFU", "AT+CSC",
        "AT+CIMP", "AT+CHU", "AT+CMG", "AT+CPB", "AT+DEVCO",
        "AT+CP", "AT+CH", "AT+CU", "AT+CLI", "AT+CPM", "AT^CU",
        "AT%IA", "AT%LA", "+CPIN:", "+CPIN: SI", "+CPIN: SIM PIN<"
    };

    // 1. أوامر المودم الصريحة (محسنة لمنع الأوامر المقطوعة على حواف البافر مثل AT+CP و +CPIN: SI)
    private static readonly Regex StrictAtCommandRegex = new(
        @"(?:\bAT[\+\*\^\%\$\#][A-Z0-9_]{3,28}(?:=[0-9A-Za-z,""\-\.\?\/\:]{1,140}|\?)?(?=[\r\n\x00""\s]|$)|" +
        @"\b(?:ATE0|ATE1|ATI|ATZ|AT&F|AT&W)\b|" +
        @"\+DEVCONINFO:\s*[^\r\n\x00""]{6,240}|" +
        @"\+(?:CGMI|CGMM|CGMR|CGSN|CIMI|CPIN|CNUM|CLCK|IMEITEST|IMEISIGN|MSLSECUR|AKSEEDNO|VERSNAME|RFBYCODE|LOCKSTATUS|SPD|HWVER):\s*[A-Za-z0-9\-\._\s,]{3,160}(?=[\r\n\x00""]|$)|" +
        @"\b(?:060100[0-9A-Fa-f]{6,64}|120[dD]00[0-9A-Fa-f]{10,128}|514200[0-9A-Fa-f]{4,64}|516400[0-9A-Fa-f]{6,64})\b)",
        RegexOptions.Compiled);

    // 2. أوامر وبروتوكولات وسجلات تنفيذ MediaTek الحية
    private static readonly Regex MtkProtocolRegex = new(
        @"(\b(?:MTK_DOWNLOAD_AGENT|MTK_BLOADER_INFO|MTK_AllInOne_DA|DA_PL_CRYPTO|Brom_[A-Za-z0-9_]{3,45}|DA_[A-Za-z0-9_]{3,45}|SLA_Challenge|DAA_Challenge|Send_DA|Jump_DA|CMD_Download_DA|CMD_Read16|CMD_Write16|CMD_Read32|CMD_Write32|CMD_GetHwCode|CMD_GetTargetConfig|CMD_GetMeId|CMD_GetSocId|XFLASH_[A-Za-z0-9_]{3,45}|EMMC_BOOT|UFS_BOOT|BROM_REGISTER_ACCESS)\b|" +
        @"\b(?:preloader_[a-zA-Z0-9_]{2,50}\.bin|MT[0-9]{4}_Android_scatter\.txt|auth_sv5\.auth|DA_SWSEC[A-Za-z0-9_\.]*\.bin|DA_BR[A-Za-z0-9_\.]*\.bin|da_mt[0-9]{4}[A-Za-z0-9_\.]*\.bin)\b|" +
        @"\b(?:Waiting for device|Bypassing authentication|Handshaking|Sending Download-Agent|Booting device|Reading partition info|Erasing FRP|Formatting userdata|Unlocking bootloader|Relocking bootloader|BOOTROM:0E8D:0003|PRELOADER:0E8D:2000|Hardware\s*:\s*MT[0-9]{4}[A-Za-z0-9\s\(\)\/]*|Security Config\s*:\s*[^\r\n\x00""\<]{2,80}|MEID\s*:\s*[0-9A-Fa-f]{8,32}|SOC ID\s*:\s*[0-9A-Fa-f]{16,64})\b|" +
        @"\b(?:erase|read|write|format|dump|flash|wipe|unlock|relock)\s+(?:nvram|nvdata|proinfo|protect1|protect2|seccfg|lk|lk2|boot|para|misc|recovery|userdata|frp|persistent|md1img|super|vbmeta|rpmb|preloader|pgpt)\b(?![""\,])[A-Za-z0-9_\-\s\.\/]{0,45})",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // 3. جميع أطوار ADB و Fastboot و Shell
    private static readonly Regex DeepAdbAndShellRegex = new(
        @"((?:shell|host|sync|usb|reboot|remount|reverse|tcp|localabstract|abb|abb_exec|framebuffer|jdwp):[A-Za-z0-9_\-\s\.\/,\=\$\#\|\<\>\&\;'\+]{2,220}|" +
        @"\b(?:adb|fastboot)\s+(?:shell|push|pull|install|install-multiple|uninstall|sideload|backup|restore|reboot|flash|flashing|oem|getvar|erase|boot|devices|forward|reverse|wait-for-device)\b[^\r\n\x00""]{0,150}|" +
        @"(?:^|[\r\n])\s*(?:[\$\#]\s*)?(?:su\s+-c|getprop|setprop|service\s+call|logcat\s+|dumpsys\s+|pm\s+(?:uninstall|install|install-create|install-write|install-commit|clear|grant|revoke|disable|disable-user|enable|list|path)|am\s+(?:start|broadcast|force-stop|startservice)|dd\s+if=|mount\s+-o|chmod\s+[0-7]{3,4}|chown\s+|rm\s+-rf|busybox\s+|toybox\s+|/data/local/tmp/AT)[^\r\n\x00""]{0,180}|" +
        @"(?:echo|cat)\s+[^\r\n\x00""]{1,100}\s*>>?\s*\/(?:dev|data|sdcard|system|efs|vendor)\/[A-Za-z0-9_\-\.\/]+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // 4. أوامر كوالكوم و EDL الموسعة (Firehose XML / Sahara / VIP / QMSL / DIAG)
    private static readonly Regex QualcommCommandRegex = new(
        @"(\b(?:QLIB_[A-Za-z0-9_]{4,65}|QPHONEMS_[A-Za-z0-9_]{4,65}|fh_loader(?:\.exe)?\s+[^\r\n\x00""]{3,160}|qsahara_server(?:\.exe)?\s+[^\r\n\x00""]{3,160}|edl(?:\.py|\.exe)?\s+[^\r\n\x00""]{3,140})\b|" +
        @"<\?xml[\s\S]{10,450}?(?:</data>|</FUSMsg>|</patches>)|" +
        @"<(?:program|erase|patch|read|ufs|emmc|configure|power|getstorageinfo|setbootablestoragedrive|firmwarewrite|getsha256digest|peek|poke|nop|sig|vip)\b[^>]{2,260}/?>|" +
        @"<response\s+value=""(?:ACK|NAK)""[^>]{0,180}/>|" +
        @"\b(?:Calling handler for|Chip serial num|MSM_HW_ID|OEM_PK_HASH|Sahara protocol|Firehose|prog_emmc_firehose|prog_ufs_firehose|rawprogram[0-9]|patch[0-9])[A-Za-z0-9_\-\.\s\:\=0x\/]{2,120})",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // 5. أنماط أجهزة Apple iOS / iPadOS الشاملة (الأطوار الـ 7)
    private static readonly Regex AppleIosRamRegex = new(
        @"(\b(?:irecovery|ideviceinfo|ideviceactivation|idevice_id|idevicepair|idevicerestore|idevicebackup2|ideviceinstaller|iproxy|gaster|checkm8|pongo|syscfg)(?:\.exe)?\s+[^\r\n\x00""\<]{2,140}|" +
        @"\b(?:CPID:[0-9A-Fa-f]{4}|ECID:[0-9A-Fa-f]{8,20}|PWND:\[[A-Za-z0-9_\-\.]+\]|SRTG:\[iBoot-[0-9\.]+\]|MODE:(?:DFU|Recovery))[^\r\n\x00""]{0,100}|" +
        @"\b(?:setenv|getenv|saveenv|fsboot|bgcolor|sep\s+auto|fuse\s+lock|modload|ramdisk|bootx|xargs|syscfg\s+(?:print|add|get|delete))\b[^\r\n\x00""\<]{0,100}|" +
        @"\b(?:mount_apfs|mount_hfs|mount_filesystems|fsck_apfs|plutil\s+-|launchctl\s+|nvram\s+|chflags\s+)[^\r\n\x00""\<]{0,120}|" +
        @"\b(?:com\.apple\.(?:mobile\.lockdown|mobile\.installation_proxy|afc|mobilebackup2|mobile\.diagnostics_relay|mobileactivationd|commcenter)|MobileGestalt|ActivationRecord|activation_record\.plist|IC-Info\.sisv|data_ark\.plist|CFA6LPAA)\b[^\r\n\x00""\<]{0,100}|" +
        @"<key>(?:Request|QueryType|UniqueDeviceID|ActivationState|ProductType|SerialNumber|InternationalMobileEquipmentIdentity|DieID|MLB#|SrNm|WmMC|BTMAC)</key>\s*<string>[^<]{1,120}</string>)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // 6. الروابط واستدعاءات الملفات الخارجية من الخوادم
    private static readonly Regex CloudAndServerUrlRegex = new(
        @"((?:https?|wss?|ftp|tcp)://[a-zA-Z0-9\-\._~:/\?#\[\]@!\$&'\(\)\*\+,;=%]{8,280}|" +
        @"(?:^|[\r\n])\s*Host:\s*[a-zA-Z0-9\-\.]{4,120}(?::\d{2,5})?)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // 7. عمليات تسجيل الدخول والمصادقة والحسابات والتراخيص والبيانات المرسلة/المستلمة للخوادم
    private static readonly Regex LoginAndServerAuthRegex = new(
        @"((?:^|[\r\n])(?:POST|GET|PUT|DELETE|PATCH)\s+\/[a-zA-Z0-9_\-\.\/\?\&\=\%]{1,220}\s+HTTP\/[12]\.[01]|" +
        @"(?:^|[\r\n])HTTP\/[12]\.[01]\s+[2345]\d\d\s+[A-Za-z0-9\s]{2,40}|" +
        @"(?:^|[\r\n])(?:Authorization:\s*(?:Bearer|Basic)\s+[A-Za-z0-9\-\._~\+\/]+=*|X-API-Key:\s*[A-Za-z0-9\-\._]{6,140}|Set-Cookie:\s*[^\r\n\x00]{6,160}|Cookie:\s*[^\r\n\x00]{6,160})|" +
        @"\{[^{}\r\n]{0,60}""(?:username|user|email|login|password|passwd|pwd|token|access_token|refresh_token|jwt|session|session_id|hwid|pc_id|license|license_key|credit|balance|expire|expire_date|imei|serial|sn|ecid|udid|device_id|challenge|sla_challenge|daa_challenge|auth_req|signature|auth_data|signed_da|sla_sig|daa_sig|download_url|file_url|ticket|status|result|server_msg)""\s*:\s*[^}\r\n]{2,240}\}|" +
        @"\b(?:username|user|email|login|password|passwd|token|access_token|session_id|hwid|license_key)\s*[=:]\s*[A-Za-z0-9_\-\.\@\$\%\+\/]{3,120})",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // 8. أوامر رفع وتحميل ونقل الملفات وتجهيز ملفات البوت واللودر والفلاش (مع حفظ تلقائي للملف!)
    private static readonly Regex FileTransferAndLoaderRegex = new(
        @"(\b(?:adb\s+(?:push|pull|sync)|sync:(?:SEND|RECV|STAT|DATA|DONE)|scp\s+-[a-zA-Z0-9]+\s+[^\r\n\x00""]{3,140}|sftp\s+[^\r\n\x00""]{4,140}|curl\s+[^\r\n\x00""]{5,160}|wget\s+[^\r\n\x00""]{5,160}|Invoke-WebRequest\s+[^\r\n\x00""]{5,160}|Start-BitsTransfer\s+[^\r\n\x00""]{5,160}|ideviceinstaller(?:\.exe)?\s+-[iIuU]\s+[^\r\n\x00""]{3,140})\b|" +
        @"\b(?:WriteFileToDevice|ReadFileFromDevice|DownloadFileAsync|UploadFileAsync|SendFileToPhone|PullFileFromPhone|ReadPartitionData|WritePartitionData|Send_DA|Download_DA|EmmcRead|EmmcWrite|UfsRead|UfsWrite)\b[^\r\n\x00""]{0,90}|" +
        @"(?<![a-zA-Z0-9_])([a-zA-Z]:\\[a-zA-Z0-9_\-\.\/\\ ]{3,160}\.(?:tar|tar\.md5|7z|zip|bin|da|auth|mbn|elf|img|pit|ops|ofp|pac|qcn|xqcn|shsh2|im4p|img4|xml|json|txt))(?![a-zA-Z0-9_])|" +
        @"(?<![a-zA-Z0-9_])([a-zA-Z0-9_\-\.]{3,90}\.(?:mbn|elf|pit|ops|ofp|pac|qcn|xqcn|shsh2|im4p|img4|da|auth|scatter\.txt))(?![a-zA-Z0-9_]))",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // 9. أوامر فتح الضغط والضغط وتفكيك الصور
    private static readonly Regex ArchiveAndUnpackCommandRegex = new(
        @"(\b(?:7z|7za|unzip|unrar|tar|gzip|gunzip|bzip2|xz|lz4|zstd|brotli|simg2img|img2simg|lpunpack|payload-dumper|cabextract|expand)(?:\.exe)?\s+(?:-[a-zA-Z0-9]+\s+|x\s+|e\s+|-xf\s+|-xzf\s+|d\s+)[^\r\n\x00""]{3,150}|" +
        @"\b(?:ZipFile\.ExtractToDirectory|ArchiveExtractor\.[A-Za-z0-9_]+|SevenZipExtractor|Lz4Decompress|SparseImageConverter)\b[^\r\n\x00""]{0,90})",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // 10. أوامر التشفير وفك التشفير + صائد المفاتيح والبذور الأمنية
    private static readonly Regex CryptoAndDecryptionCommandRegex = new(
        @"(\b(?:openssl\s+(?:enc|aes-[0-9]{3}-[a-z]+|dgst|rsautl|pkeyutl)\s+[^\r\n\x00""]{4,150}|ofp_decrypt[^\r\n\x00""]{0,110}|ops_decrypt[^\r\n\x00""]{0,110}|ozipdecrypt[^\r\n\x00""]{0,110})\b|" +
        @"\b(?:AES_decrypt|AES_encrypt|AES_cbc_encrypt|RSA_private_decrypt|RSA_public_encrypt|EVP_DecryptInit|EVP_EncryptInit|CryptDecrypt|CryptEncrypt|BCryptDecrypt|BCryptEncrypt|RijndaelManaged|AesGcm|PBKDF2|HMACSHA256|DecryptFirmware|DecryptPayload|EncryptPayload|VerifyAuthSignature)\b[^\r\n\x00""]{0,70}|" +
        @"\b(?:AKSEEDNO|MSLSECUR|SimLock|NCK_CODE|MCK_CODE|SPC_CODE|AES_KEY|RSA_MODULUS|SLA_RESPONSE|DAA_RESPONSE|AUTH_SIGNATURE)\s*[:=]\s*[^\r\n\x00""]{4,140})",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // 11. بروتوكولات Odin و Unisoc SPD والمسارات الحساسة وأوامر الأدوات الأخرى
    private static readonly Regex OdinSpdAndOtherRegex = new(
        @"(\b(?:BSL_CMD_[A-Za-z0-9_]{3,40}|spd_dump(?:\.exe)?\s+[^\r\n\x00""]{3,140}|FDL1|FDL2|LOKE_[A-Za-z0-9_]{2,30}|ODIN_[A-Za-z0-9_]{2,50})\b|" +
        @"\b(?:cmd(?:\.exe)?\s+\/[cCkK]\s+[^\r\n\x00""]{4,140}|powershell(?:\.exe)?\s+-(?:Command|EncodedCommand|File|NoProfile|ExecutionPolicy)\s+[^\r\n\x00""]{4,140}|pnputil(?:\.exe)?\s+\/[a-zA-Z\-]+\s+[^\r\n\x00""]{2,100}|devcon(?:\.exe)?\s+[a-zA-Z]+\s+[^\r\n\x00""]{2,100}|filter-x(?:64|86)(?:\.exe)?\s+[^\r\n\x00""]{3,120})\b|" +
        @"(\/(?:data\/local\/tmp|dev\/block\/bootdevice\/by-name|dev\/block\/platform|dev\/block\/mapper|dev\/smd|dev\/ttyUSB|dev\/ttyACM|dev\/at_mdm|dev\/umts_ipc|efs|nvdata|nvram|persist|mnt\/vendor\/persist)\/[A-Za-z0-9_\-\.\/]{1,90})|" +
        @"(\\\\\?\\(?:usb|USB)#VID_[0-9A-Fa-f]{4}&PID_[0-9A-Fa-f]{4}#[^\s""\x00-\x1F\<\>]{4,110}))",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint PROCESS_VM_READ = 0x0010;
    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_PRIVATE = 0x20000;
    private const uint MEM_IMAGE = 0x1000000;
    private const uint PAGE_READONLY = 0x02;
    private const uint PAGE_READWRITE = 0x04;
    private const uint PAGE_WRITECOPY = 0x08;
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_GUARD = 0x100;
    private const uint PAGE_NOACCESS = 0x01;

    public void StartHunting(int targetPid, string processName)
    {
        if (targetPid > 0)
        {
            _monitoredPids[targetPid] = processName;
        }

        if (_cts != null) return;
        _cts = new CancellationTokenSource();
        var token = _cts.Token;

        Task.Run(async () =>
        {
            while (!token.IsCancellationRequested)
            {
                if (!_isRamHunterEnabled || DiscoveryMode == L24DiscoveryMode.ExecutedOnly || _isCapturingBaselineNow)
                {
                    await Task.Delay(400, token).ConfigureAwait(false);
                    continue;
                }

                // 1. فحص العمليات الفرعية السريعة (adb.exe, fastboot.exe, cmd.exe, إلخ) فوراً بدون تأخير
                foreach (var kvp in _childAdbPids)
                {
                    if (token.IsCancellationRequested) break;
                    try
                    {
                        using var proc = Process.GetProcessById(kvp.Key);
                        if (!proc.HasExited)
                            ScanProcessHeapAndBuffers(kvp.Key, kvp.Value, token, recordAsBaselineOnly: false);
                    }
                    catch
                    {
                        _childAdbPids.TryRemove(kvp.Key, out _);
                    }
                }

                // 2. فحص العملية الأم (مع أخذ بصمة الـ Idle Baseline تلقائياً في الدورة الأولى عند تفعيل SuppressIdleStaticBaseline)
                _parentScanCycleCounter++;
                foreach (var target in _monitoredPids)
                {
                    if (token.IsCancellationRequested) break;
                    try
                    {
                        using var proc = Process.GetProcessById(target.Key);
                        if (!proc.HasExited)
                        {
                            bool isFirstBaselinePass = _suppressIdleStaticBaseline && !_pidBaselineCompleted.ContainsKey(target.Key);
                            ScanProcessHeapAndBuffers(target.Key, target.Value, token, recordAsBaselineOnly: isFirstBaselinePass);
                            if (isFirstBaselinePass)
                            {
                                _pidBaselineCompleted[target.Key] = true;
                            }
                        }
                    }
                    catch
                    {
                        _monitoredPids.TryRemove(target.Key, out _);
                    }
                }

                await Task.Delay(350, token).ConfigureAwait(false);
            }
        }, token);
    }

    private void ScanProcessHeapAndBuffers(int pid, string processName, CancellationToken token, bool recordAsBaselineOnly)
    {
        if (pid <= 0 || (!_isRamHunterEnabled && !recordAsBaselineOnly) || DiscoveryMode == L24DiscoveryMode.ExecutedOnly) return;
        IntPtr hProc = IntPtr.Zero;
        try
        {
            hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
            if (hProc == IntPtr.Zero) return;

            long currentAddr = 0x10000;
            long maxAddr = Environment.Is64BitOperatingSystem ? 0x7FFFFFFEFFFFL : 0x7FFF0000L;
            uint mbiSize = (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();
            const int chunkSize = 65536;
            const int overlap = 512;
            byte[] buffer = ArrayPool<byte>.Shared.Rent(chunkSize + overlap);

            try
            {
                while (currentAddr < maxAddr && !token.IsCancellationRequested)
                {
                    if (VirtualQueryEx(hProc, (IntPtr)currentAddr, out var mbi, mbiSize) == 0)
                        break;

                    uint prot = mbi.Protect & 0xFF;
                    bool isExecutableCodeSection = (prot == PAGE_EXECUTE_READ) || (mbi.Type == MEM_IMAGE && prot == PAGE_READONLY);

                    bool isScannable;
                    if (_scanDynamicHeapOnly)
                    {
                        // فحص الـ Heap الديناميكي القابل للكتابة فقط
                        isScannable = mbi.State == MEM_COMMIT &&
                                      mbi.Type == MEM_PRIVATE &&
                                      (mbi.Protect & PAGE_GUARD) == 0 &&
                                      (prot == PAGE_READWRITE || prot == PAGE_EXECUTE_READWRITE || prot == PAGE_WRITECOPY);
                    }
                    else
                    {
                        // فحص كامل الرام (مع استبعاد كود الأسمبلي المترجم PAGE_EXECUTE_READ في ملفات النظام لمنع التوقيعات الكاذبة)
                        isScannable = mbi.State == MEM_COMMIT &&
                                      (mbi.Protect & PAGE_GUARD) == 0 &&
                                      prot != PAGE_NOACCESS &&
                                      (prot == PAGE_READWRITE || prot == PAGE_EXECUTE_READWRITE ||
                                       prot == PAGE_WRITECOPY || prot == PAGE_READONLY ||
                                       (!_suppressIdleStaticBaseline && prot == PAGE_EXECUTE_READ));
                    }

                    long regionSize = mbi.RegionSize.ToInt64();
                    if (isScannable && regionSize > 0 && regionSize <= 64 * 1024 * 1024)
                    {
                        long offset = 0;
                        while (offset < regionSize && !token.IsCancellationRequested)
                        {
                            int toRead = (int)Math.Min(chunkSize + overlap, regionSize - offset);
                            long chunkAddr = currentAddr + offset;
                            if (ReadProcessMemory(hProc, (IntPtr)chunkAddr, buffer, toRead, out int bytesRead) && bytesRead > 0)
                            {
                                // فحص البصمة السريعة للشريحة (Fast Dirty-Chunk Hash): إذا لم تتغير الشريحة منذ آخر مسح، نتخطاها فوراً!
                                ulong chunkHash = ComputeFastFnv1a64(buffer, bytesRead);
                                long cacheKey = ((long)pid << 44) ^ chunkAddr;

                                if (!recordAsBaselineOnly && _chunkHashCache.TryGetValue(cacheKey, out ulong prevHash) && prevHash == chunkHash)
                                {
                                    offset += chunkSize;
                                    continue;
                                }
                                _chunkHashCache[cacheKey] = chunkHash;

                                InspectBinaryAndTextBuffer(pid, processName, chunkAddr, buffer, bytesRead, isExecutableCodeSection, recordAsBaselineOnly);
                            }
                            offset += chunkSize;
                        }
                    }

                    long nextAddr = mbi.BaseAddress.ToInt64() + Math.Max(regionSize, 4096);
                    if (nextAddr <= currentAddr) break;
                    currentAddr = nextAddr;
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }
        finally
        {
            if (hProc != IntPtr.Zero)
                CloseHandle(hProc);
        }
    }

    private static ulong ComputeFastFnv1a64(byte[] buf, int len)
    {
        ulong hash = 14695981039346656037UL;
        int step = len > 4096 ? 4 : 1; // أخذ عينة كل 4 بايتات للسرعة الفائقة مع حساسية لأي تغيير نصي
        for (int i = 0; i < len; i += step)
        {
            hash ^= buf[i];
            hash *= 1099511628211UL;
        }
        return hash;
    }

    private void InspectBinaryAndTextBuffer(int pid, string processName, long memAddress, byte[] buffer, int length, bool isExecutableCodeSection, bool recordAsBaselineOnly)
    {
        if (!recordAsBaselineOnly)
        {
            InspectRawBinarySignaturesAndCarveLoaders(pid, processName, memAddress, buffer, length, isExecutableCodeSection);
        }

        // فحص سريع: لا نحول الـ 64KB إلى String إلا إذا كانت تحتوي على أحرف قابلة للطباعة
        if (HasPrintableAsciiRun(buffer, length))
        {
            ScanStringContent(pid, processName, memAddress, Encoding.UTF8.GetString(buffer, 0, length), recordAsBaselineOnly);
        }
        if (HasPrintableUtf16Run(buffer, length))
        {
            ScanStringContent(pid, processName, memAddress, Encoding.Unicode.GetString(buffer, 0, length), recordAsBaselineOnly);
        }
    }

    private static bool HasPrintableAsciiRun(byte[] buf, int len)
    {
        int run = 0;
        for (int i = 0; i < len; i++)
        {
            byte b = buf[i];
            if (b is >= 32 and <= 126)
            {
                if (++run >= 4) return true;
            }
            else
            {
                run = 0;
            }
        }
        return false;
    }

    private static bool HasPrintableUtf16Run(byte[] buf, int len)
    {
        int run = 0;
        for (int i = 0; i < len - 1; i += 2)
        {
            if (buf[i] is >= 32 and <= 126 && buf[i + 1] == 0)
            {
                if (++run >= 4) return true;
            }
            else
            {
                run = 0;
            }
        }
        return false;
    }

    public void InspectBufferForTesting(int pid, string processName, long memAddress, byte[] buffer, int length)
    {
        InspectBinaryAndTextBuffer(pid, processName, memAddress, buffer, length, isExecutableCodeSection: false, recordAsBaselineOnly: false);
    }

    private void InspectRawBinarySignaturesAndCarveLoaders(int pid, string processName, long memAddress, byte[] buf, int len, bool isExecutableCodeSection)
    {
        for (int i = 0; i < len - 24; i++)
        {
            // ══════════════════════════════════════════════════════════════════════
            // أولاً: صائد ملفات البوت واللودر والـ DA والـ Firehose والـ IMG4 مباشرة من الرام (In-Memory Loader Carver)
            // ══════════════════════════════════════════════════════════════════════
            if (_enableInMemoryLoaderCarving && _carvedLoaderAddresses.Count < 80)
            {
                // أ) ملف MediaTek Download-Agent (MTK_DOWNLOAD_AGENT أو MTK_BLOADER_INFO) محمل في الرام
                if (buf[i] == 'M' && buf[i + 1] == 'T' && buf[i + 2] == 'K' && buf[i + 3] == '_' &&
                    ((buf[i + 4] == 'D' && buf[i + 5] == 'O' && buf[i + 6] == 'W' && buf[i + 7] == 'N') ||
                     (buf[i + 4] == 'B' && buf[i + 5] == 'L' && buf[i + 6] == 'O' && buf[i + 7] == 'A')))
                {
                    long hitAddr = memAddress + i;
                    if (_carvedLoaderAddresses.TryAdd(hitAddr >> 12, 1))
                    {
                        int extractLen = Math.Min(len - i, 65536);
                        if (extractLen >= 512)
                        {
                            byte[] carved = new byte[extractLen];
                            Buffer.BlockCopy(buf, i, carved, 0, extractLen);
                            if (L24FileArchiver.TryArchiveRawBuffer(carved, $"RAM_Carved_MTK_DA_0x{hitAddr:X8}.bin", $"InMemoryCarver ({processName})", out string savedDa, out long sLen, out _))
                            {
                                EmitDiscovered(pid, processName, hitAddr, SentinelStage.LocalFilePreparation,
                                    "In-Memory Boot / DA Loader Carved",
                                    $"💾 تم استخراج وحفظ ملف بوت/لودر MediaTek DA مباشرة من الرام: [{Path.GetFileName(savedDa)}] ({sLen:N0} بايت)",
                                    savedDa, savedDa, savedFilePath: savedDa);
                            }
                        }
                    }
                }

                // ب) ملف Apple IMG4 / IM4P (iBSS / iBEC / Ramdisk / DeviceTree / SEP) محمل في الرام
                if (buf[i] == 'I' && buf[i + 1] == 'M' && buf[i + 2] == '4' && buf[i + 3] == 'P' &&
                    i >= 4 && buf[i - 2] == 0x16 && buf[i - 1] == 0x04)
                {
                    long hitAddr = memAddress + i;
                    if (_carvedLoaderAddresses.TryAdd(hitAddr >> 12, 1))
                    {
                        string fourCc = Encoding.ASCII.GetString(buf, i + 6, 4);
                        bool isValidFourCc = fourCc.All(c => c is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9');
                        if (isValidFourCc)
                        {
                            int startIdx = Math.Max(0, i - 8);
                            int extractLen = Math.Min(len - startIdx, 65536);
                            byte[] carved = new byte[extractLen];
                            Buffer.BlockCopy(buf, startIdx, carved, 0, extractLen);
                            if (L24FileArchiver.TryArchiveRawBuffer(carved, $"RAM_Carved_Apple_{fourCc}_0x{hitAddr:X8}.im4p", $"InMemoryCarver ({processName})", out string savedIm4p, out long sLen, out _))
                            {
                                EmitDiscovered(pid, processName, hitAddr, SentinelStage.LocalFilePreparation,
                                    "In-Memory Apple IMG4/IM4P Carved",
                                    $"💾 تم استخراج وحفظ ملف بوت أبل ({fourCc}) مباشرة من الرام: [{Path.GetFileName(savedIm4p)}] ({sLen:N0} بايت)",
                                    savedIm4p, savedIm4p, savedFilePath: savedIm4p);
                            }
                        }
                    }
                }
            }

            // لا نفحص التوقيعات الثنائية القصيرة داخل أقسام الكود التنفيذي لمنع الإيجابيات الكاذبة (مثل تعليمة mov al في CDMA-YTP)
            if (isExecutableCodeSection) continue;

            // 1. حزمة بروتوكول MediaTek XFlash / DA2 الثنائية (EF EE EE FE)
            if (IsGroupEnabled(L24CommandGroup.MediaTek) && buf[i] == 0xEF && buf[i + 1] == 0xEE && buf[i + 2] == 0xEE && buf[i + 3] == 0xFE)
            {
                int cmdId = BitConverter.ToInt32(buf, i + 4);
                int dataLen = BitConverter.ToInt32(buf, i + 8);
                if (cmdId > 0 && cmdId < 0x10000 && dataLen >= 0 && dataLen <= 0x400000)
                {
                    int snapLen = Math.Min(32, len - i);
                    string hex = Convert.ToHexString(buf.AsSpan(i, snapLen));
                    EmitDiscovered(pid, processName, memAddress + i, SentinelStage.RawCommandExecution,
                        "MTK XFlash / DA Binary Packet",
                        $"حزمة أمر MediaTek DA/XFlash ثنائية [CmdID: 0x{cmdId:X4}, الطول: {dataLen} بايت]",
                        hex, "MTK USB/VCOM Stream", isAlreadyHex: true);
                }
            }

            // 2. مصافحة MediaTek BROM الكاملة (A0 0A 50 05) — مع التحقق من عدم كونها تعليمة أسمبلي x86
            if (IsGroupEnabled(L24CommandGroup.MediaTek) && buf[i] == 0xA0 && buf[i + 1] == 0x0A && buf[i + 2] == 0x50 && buf[i + 3] == 0x05)
            {
                byte nextByte = i + 4 < len ? buf[i + 4] : (byte)0;
                // استبعاد 0xC64424 (تعليمة mov byte ptr [esp+...]) التي ظهرت كإيجابية كاذبة في CDMA-YTP
                bool isX86InstructionNoise = (nextByte == 0xC6 && i + 5 < len && buf[i + 5] == 0x44);
                if (!isX86InstructionNoise && (nextByte is 0xD0 or 0xD1 or 0xD2 or 0xD4 or 0xD6 or 0xD7 or 0xD8 or 0xDA or 0xDC or 0xA0 or 0x5F))
                {
                    int snapLen = Math.Min(16, len - i);
                    string hex = Convert.ToHexString(buf.AsSpan(i, snapLen));
                    EmitDiscovered(pid, processName, memAddress + i, SentinelStage.RawCommandExecution,
                        "MTK BROM Handshake",
                        $"مصافحة وأمر معالج MediaTek BROM المباشر [Sync: A0 0A 50 05, NextOp: 0x{nextByte:X2}]",
                        hex, "MTK BROM Port", isAlreadyHex: true);
                }
            }

            // 3. ترويسة Apple AFC الثنائية (CFA6LPAA)
            if (IsGroupEnabled(L24CommandGroup.AppleIos) && buf[i] == 'C' && buf[i + 1] == 'F' && buf[i + 2] == 'A' && buf[i + 3] == '6' &&
                buf[i + 4] == 'L' && buf[i + 5] == 'P' && buf[i + 6] == 'A' && buf[i + 7] == 'A')
            {
                int snapLen = Math.Min(48, len - i);
                string asciiTail = Encoding.ASCII.GetString(buf, i, snapLen).Replace('\0', ' ').Trim();
                EmitDiscovered(pid, processName, memAddress + i, SentinelStage.RawCommandExecution,
                    "Apple AFC Protocol Packet",
                    $"حزمة نقل ملفات Apple AFC مكتشفة في الذاكرة: {asciiTail}",
                    asciiTail, "Apple AFC Channel");
            }
        }
    }

    private void ScanStringContent(int pid, string processName, long memAddress, string text, bool recordAsBaselineOnly)
    {
        var mode = DiscoveryMode;
        if (mode == L24DiscoveryMode.ExecutedOnly) return;

        // 1. أوامر المودم AT وردود الهاتف وأوامر RIL IPC الهيكس
        if (IsGroupEnabled(L24CommandGroup.ModemAt))
        {
            foreach (Match m in StrictAtCommandRegex.Matches(text))
            {
                string val = CleanToken(m.Value);
                if (val.Length < 3 || TruncatedAtPrefixes.Contains(val) || IsLikelyTruncatedAtFragment(val)) continue;
                if (ShouldSkipOrRecordBaseline(val, recordAsBaselineOnly)) continue;

                bool isReply = val.StartsWith("+");
                if (isReply && !ForensicNoiseGate.ShowPhoneResponses) continue;

                bool isRilHex = val.StartsWith("060100", StringComparison.OrdinalIgnoreCase) ||
                                val.StartsWith("120D00", StringComparison.OrdinalIgnoreCase) ||
                                val.StartsWith("514200", StringComparison.OrdinalIgnoreCase) ||
                                val.StartsWith("516400", StringComparison.OrdinalIgnoreCase);

                string cat = isRilHex ? "ADB RIL / AT IPC Command" : (isReply ? "Modem Phone Response" : "Modem AT Command");
                string desc = isRilHex
                    ? $"أمر RIL/AT هيكس مكتشف في الذاكرة: {val}"
                    : (isReply ? $"رد الهاتف المكتشف في ذاكرة الأداة: {val}" : $"أمر مودم صريح مكتشف في ذاكرة الأداة: {val}");

                string targetPort = isRilHex ? "/data/local/tmp/AT" : ActiveComAndUsbPortPoller.GetPrimaryActivePortLabel();
                EmitDiscovered(pid, processName, memAddress + m.Index, SentinelStage.RawCommandExecution, cat, desc, val, targetPort);
            }
        }

        // 2. أوامر وبروتوكولات وسجلات تنفيذ MediaTek
        if (IsGroupEnabled(L24CommandGroup.MediaTek))
        {
            foreach (Match m in MtkProtocolRegex.Matches(text))
            {
                string val = CleanToken(m.Value);
                if (val.Length < 5 || !IsCleanRamString(val) || IsHtmlOrUiFormatNoise(val)) continue;
                if (ShouldSkipOrRecordBaseline(val, recordAsBaselineOnly)) continue;

                EmitDiscovered(pid, processName, memAddress + m.Index, SentinelStage.RawCommandExecution,
                    "MediaTek BROM / DA Command",
                    $"🔶 أمر/عملية MediaTek مكتشفة في ذاكرة الأداة: {val}",
                    val, "MTK Preloader / DA Engine");
            }
        }

        // 3. أوامر ADB و Fastboot و Shell
        if (IsGroupEnabled(L24CommandGroup.AdbFastboot))
        {
            foreach (Match m in DeepAdbAndShellRegex.Matches(text))
            {
                string val = CleanToken(m.Value, allowNewLines: true);
                if (val.Length < 4 || !IsCleanRamString(val) || IsWindowsSetupApiRebootNoise(val)) continue;
                if (ShouldSkipOrRecordBaseline(val, recordAsBaselineOnly)) continue;

                EmitDiscovered(pid, processName, memAddress + m.Index, SentinelStage.RawCommandExecution,
                    "ADB / Fastboot / Shell Command",
                    $"🤖 أمر ADB/Fastboot/Shell مكتشف في ذاكرة الأداة: {val}",
                    val, "ADB / Fastboot Engine");
            }
        }

        // 4. أوامر كوالكوم و EDL الموسعة
        if (IsGroupEnabled(L24CommandGroup.Qualcomm))
        {
            foreach (Match m in QualcommCommandRegex.Matches(text))
            {
                bool isXml = m.Value.StartsWith("<", StringComparison.Ordinal);
                string val = CleanToken(m.Value, allowNewLines: isXml);
                if (val.Length < 6 || !IsCleanRamString(val) || (!isXml && IsHtmlOrUiFormatNoise(val))) continue;
                if (ShouldSkipOrRecordBaseline(val, recordAsBaselineOnly)) continue;

                bool isResp = val.StartsWith("<response", StringComparison.OrdinalIgnoreCase);
                if (isResp && !ForensicNoiseGate.ShowPhoneResponses) continue;

                string cat = isResp ? "Firehose Device Response" : "Qualcomm EDL / Sahara / Firehose Command";
                EmitDiscovered(pid, processName, memAddress + m.Index, SentinelStage.RawCommandExecution,
                    cat, $"🔷 أمر/عملية كوالكوم EDL مكتشفة في ذاكرة الأداة: {val}", val, "Qualcomm EDL 9008 / DIAG");
            }
        }

        // 5. أوامر وبروتوكولات Apple iOS (الأطوار الـ 7)
        if (IsGroupEnabled(L24CommandGroup.AppleIos))
        {
            foreach (Match m in AppleIosRamRegex.Matches(text))
            {
                string val = CleanToken(m.Value, allowNewLines: true);
                if (val.Length < 4 || !IsCleanRamString(val) || IsHtmlOrUiFormatNoise(val)) continue;
                if (ShouldSkipOrRecordBaseline(val, recordAsBaselineOnly)) continue;

                EmitDiscovered(pid, processName, memAddress + m.Index, SentinelStage.RawCommandExecution,
                    "Apple iOS / Lockdown / DFU / Pongo Command",
                    $"🍎 أمر/بروتوكول Apple iOS مكتشف في الذاكرة: {val}",
                    val, "Apple USB / Lockdown / DFU Engine");
            }
        }

        if (mode == L24DiscoveryMode.PhoneCommandsInRam)
            return;

        // 6. الروابط واستدعاءات الملفات السحابية من الخوادم (URLs & Cloud Files)
        if (!ExcludeUrls && IsGroupEnabled(L24CommandGroup.ServerCloudLogin))
        {
            foreach (Match m in CloudAndServerUrlRegex.Matches(text))
            {
                string val = CleanToken(m.Value, preserveUrlChars: true);
                if (val.Length < 10 || !IsCleanRamString(val)) continue;

                if (val.Contains("w3.org", StringComparison.OrdinalIgnoreCase) ||
                    val.Contains("schemas.microsoft.com", StringComparison.OrdinalIgnoreCase) ||
                    val.Contains("schemas.xmlsoap.org", StringComparison.OrdinalIgnoreCase) ||
                    val.Contains("ns.adobe.com", StringComparison.OrdinalIgnoreCase) ||
                    val.Contains("digicert.com", StringComparison.OrdinalIgnoreCase) ||
                    val.Contains("sectigo.com", StringComparison.OrdinalIgnoreCase) ||
                    val.Contains("verisign.com", StringComparison.OrdinalIgnoreCase) ||
                    val.Contains("chilkatsoft.com", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (ShouldSkipOrRecordBaseline(val, recordAsBaselineOnly)) continue;

                bool isCloudFile = val.Contains(".bin", StringComparison.OrdinalIgnoreCase) ||
                                   val.Contains(".mbn", StringComparison.OrdinalIgnoreCase) ||
                                   val.Contains(".elf", StringComparison.OrdinalIgnoreCase) ||
                                   val.Contains(".zip", StringComparison.OrdinalIgnoreCase) ||
                                   val.Contains(".7z", StringComparison.OrdinalIgnoreCase) ||
                                   val.Contains(".auth", StringComparison.OrdinalIgnoreCase) ||
                                   val.Contains(".plist", StringComparison.OrdinalIgnoreCase) ||
                                   val.Contains(".shsh", StringComparison.OrdinalIgnoreCase) ||
                                   val.Contains("download", StringComparison.OrdinalIgnoreCase) ||
                                   val.Contains("loader", StringComparison.OrdinalIgnoreCase) ||
                                   val.Contains("firehose", StringComparison.OrdinalIgnoreCase);

                string cat = isCloudFile ? "Cloud External File Request" : "Server / API Endpoint URL";
                string desc = isCloudFile
                    ? $"🌐 استدعاء/تحميل ملف خارجي من خادم سحابي: {val}"
                    : $"🌐 رابط خادم خارجي / نقطة API مكتشفة بالذاكرة: {val}";

                EmitDiscovered(pid, processName, memAddress + m.Index, SentinelStage.NetworkPreEncryption, cat, desc, val, val);
            }
        }

        // 7. عمليات تسجيل الدخول والمصادقة والحسابات والبيانات المرسلة/المستلمة للخوادم
        if (IsGroupEnabled(L24CommandGroup.ServerCloudLogin))
        {
            foreach (Match m in LoginAndServerAuthRegex.Matches(text))
            {
                string val = CleanToken(m.Value, allowNewLines: true, preserveUrlChars: true);
                if (val.Length < 10 || !IsCleanRamString(val)) continue;
                if (ShouldSkipOrRecordBaseline(val, recordAsBaselineOnly)) continue;

                bool isLoginOrToken = val.Contains("login", StringComparison.OrdinalIgnoreCase) ||
                                      val.Contains("password", StringComparison.OrdinalIgnoreCase) ||
                                      val.Contains("passwd", StringComparison.OrdinalIgnoreCase) ||
                                      val.Contains("username", StringComparison.OrdinalIgnoreCase) ||
                                      val.Contains("Bearer", StringComparison.OrdinalIgnoreCase) ||
                                      val.Contains("token", StringComparison.OrdinalIgnoreCase) ||
                                      val.Contains("license", StringComparison.OrdinalIgnoreCase) ||
                                      val.Contains("hwid", StringComparison.OrdinalIgnoreCase);

                string cat = isLoginOrToken
                    ? "Tool Login / Auth / Account Session"
                    : "Server HTTP / JSON Data Exchange";
                string desc = isLoginOrToken
                    ? $"🔑 عملية تسجيل دخول / مصادقة حساب / توكن مكتشفة بالذاكرة: {val}"
                    : $"📡 بيانات متبادلة مع الخادم (HTTP/JSON Payload): {val}";

                EmitDiscovered(pid, processName, memAddress + m.Index, SentinelStage.NetworkPreEncryption, cat, desc, val, "Server / Account Auth");
            }
        }

        // 8. أوامر رفع وتحميل ونقل الملفات وتجهيز اللودرات (مع محاولة حفظ الملف تلقائياً عبر L24FileArchiver!)
        if (IsGroupEnabled(L24CommandGroup.FileTransfer))
        {
            foreach (Match m in FileTransferAndLoaderRegex.Matches(text))
            {
                string val = CleanToken(m.Value);
                if (val.Length < 6 || !IsCleanRamString(val) || IsChilkatOrDummyFileNoise(val)) continue;
                if (val.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) || val.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) continue;
                if (ShouldSkipOrRecordBaseline(val, recordAsBaselineOnly)) continue;

                string savedFile = string.Empty;
                long savedSize = 0;
                if (L24FileArchiver.TryArchiveDiscoveredFile(val, $"RAM_Hunter ({processName})", out string sPath, out long sLen, out _))
                {
                    savedFile = sPath;
                    savedSize = sLen;
                }

                string saveBadge = !string.IsNullOrWhiteSpace(savedFile)
                    ? $" | 💾 تم حفظ الملف تلقائياً في: [{Path.GetFileName(savedFile)}] ({savedSize:N0} بايت)"
                    : "";

                EmitDiscovered(pid, processName, memAddress + m.Index, SentinelStage.RawCommandExecution,
                    "File Transfer / Loader Preparation",
                    $"📤 أمر نقل/رفع/تحميل أو تجهيز ملف لودر في الذاكرة: {val}{saveBadge}",
                    val, !string.IsNullOrWhiteSpace(savedFile) ? savedFile : "File Transfer / Loader Engine",
                    savedFilePath: savedFile);
            }
        }

        // 9. أوامر فتح الضغط والضغط وتفكيك الصور
        if (IsGroupEnabled(L24CommandGroup.ArchiveUnpack))
        {
            foreach (Match m in ArchiveAndUnpackCommandRegex.Matches(text))
            {
                string val = CleanToken(m.Value);
                if (val.Length < 6 || !IsCleanRamString(val)) continue;
                if (ShouldSkipOrRecordBaseline(val, recordAsBaselineOnly)) continue;

                EmitDiscovered(pid, processName, memAddress + m.Index, SentinelStage.RawCommandExecution,
                    "Archive / Unpack Command",
                    $"📦 أمر فك ضغط/تفكيك صور مكتشف في الذاكرة: {val}",
                    val, "Archive / Image Unpacker");
            }
        }

        // 10. أوامر التشفير وفك التشفير والمفاتيح والبذور الأمنية
        if (IsGroupEnabled(L24CommandGroup.CryptoAuth))
        {
            foreach (Match m in CryptoAndDecryptionCommandRegex.Matches(text))
            {
                string val = CleanToken(m.Value);
                if (val.Length < 6 || !IsCleanRamString(val) || IsChilkatOrDummyFileNoise(val)) continue;
                if (ShouldSkipOrRecordBaseline(val, recordAsBaselineOnly)) continue;

                EmitDiscovered(pid, processName, memAddress + m.Index, SentinelStage.RawCommandExecution,
                    "Encryption / Decryption / Security Seed",
                    $"🔐 عملية تشفير/فك تشفير أو بذرة أمنية مكتشفة في الذاكرة: {val}",
                    val, "Crypto / Security Engine");
            }
        }

        // 11. بروتوكولات Odin / Unisoc SPD / المسارات الحساسة / أوامر أخرى
        if (IsGroupEnabled(L24CommandGroup.OtherCommands))
        {
            foreach (Match m in OdinSpdAndOtherRegex.Matches(text))
            {
                string val = CleanToken(m.Value);
                if (val.Length < 6 || !IsCleanRamString(val)) continue;
                if (ShouldSkipOrRecordBaseline(val, recordAsBaselineOnly)) continue;

                EmitDiscovered(pid, processName, memAddress + m.Index, SentinelStage.RawCommandExecution,
                    "Other Discovered Command",
                    $"🧩 أمر/مسار مكتشف في ذاكرة الأداة: {val}",
                    val, "General Tool Command");
            }
        }
    }

    private bool ShouldSkipOrRecordBaseline(string normalizedVal, bool recordAsBaselineOnly)
    {
        if (recordAsBaselineOnly)
        {
            _idleBaselineStrings[normalizedVal] = 1;
            return true;
        }

        if (_suppressIdleStaticBaseline && _idleBaselineStrings.ContainsKey(normalizedVal))
        {
            return true;
        }

        return false;
    }

    private static bool IsLikelyTruncatedAtFragment(string val)
    {
        // استبعاد الأجزاء المقطوعة القصيرة مثل AT+CP أو AT+CH أو +CPIN: SI
        if (val.StartsWith("AT+", StringComparison.OrdinalIgnoreCase) && val.Length <= 6 && !val.Contains('=') && !val.Contains('?'))
        {
            string cmdPart = val[3..].ToUpperInvariant();
            if (cmdPart is not ("CGMR" or "CGMI" or "CGMM" or "CGSN" or "CIMI" or "CPIN" or "CNUM" or "CLAC" or "CFUN" or "CSQ"))
                return true;
        }
        if (val.StartsWith("+CPIN:", StringComparison.OrdinalIgnoreCase) && val.EndsWith("<", StringComparison.Ordinal))
            return true;
        return false;
    }

    private static bool IsHtmlOrUiFormatNoise(string val)
    {
        return val.Contains("</b>", StringComparison.OrdinalIgnoreCase) ||
               val.Contains("</li>", StringComparison.OrdinalIgnoreCase) ||
               val.Contains("</font>", StringComparison.OrdinalIgnoreCase) ||
               val.Contains("</span>", StringComparison.OrdinalIgnoreCase) ||
               val.Contains("<a href=", StringComparison.OrdinalIgnoreCase) ||
               val.Equals("bgcolor", StringComparison.OrdinalIgnoreCase) ||
               val.Equals("bgcolor=", StringComparison.OrdinalIgnoreCase) ||
               val.Equals("bgcolor-color", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsWindowsSetupApiRebootNoise(string val)
    {
        return val.StartsWith("reboot: Could not ", StringComparison.OrdinalIgnoreCase) ||
               val.StartsWith("reboot: Query remove", StringComparison.OrdinalIgnoreCase) ||
               val.StartsWith("reboot: Device has ", StringComparison.OrdinalIgnoreCase) ||
               val.StartsWith("reboot: Marked as ", StringComparison.OrdinalIgnoreCase) ||
               val.StartsWith("reboot: Retrieve device", StringComparison.OrdinalIgnoreCase) ||
               val.StartsWith("reboot: Driver did not", StringComparison.OrdinalIgnoreCase) ||
               val.StartsWith("reboot: Unable to retrieve", StringComparison.OrdinalIgnoreCase) ||
               val.StartsWith("reboot: one or more files", StringComparison.OrdinalIgnoreCase) ||
               val.StartsWith("reboot: Unexpected while", StringComparison.OrdinalIgnoreCase) ||
               val.Equals("reboot:", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsChilkatOrDummyFileNoise(string val)
    {
        return val.Contains("CXDUMMYFILE.TXT", StringComparison.OrdinalIgnoreCase) ||
               val.Contains("TRUSTPOL.TXT", StringComparison.OrdinalIgnoreCase) ||
               val.Contains("AslLog_", StringComparison.OrdinalIgnoreCase) ||
               val.Contains("chilkatsoft.com", StringComparison.OrdinalIgnoreCase) ||
               val.Contains("AES_ENCRYPT == enc", StringComparison.OrdinalIgnoreCase);
    }

    private static string CleanToken(string input, bool allowNewLines = false, bool preserveUrlChars = false)
    {
        var sb = new StringBuilder(input.Length);
        foreach (char c in input)
        {
            if (c >= 32 && c <= 126)
                sb.Append(c);
            else if (allowNewLines && (c == '\r' || c == '\n' || c == '\t'))
                sb.Append(c);
            else
                break;
        }

        string cleaned = sb.ToString().Trim();
        bool isJsonObj = cleaned.StartsWith("{", StringComparison.Ordinal);
        if (!isJsonObj && !preserveUrlChars)
        {
            int jsonSep = cleaned.IndexOf("\",\"", StringComparison.Ordinal);
            if (jsonSep > 0)
                cleaned = cleaned[..jsonSep].Trim();
            cleaned = cleaned.Trim('"', '\'', ',', ';');
        }
        else if (preserveUrlChars && !isJsonObj)
        {
            cleaned = cleaned.Trim('"', '\'', ' ');
        }

        return cleaned;
    }

    private static bool IsCleanRamString(string value)
    {
        bool isJsonOrHttp = value.StartsWith("{", StringComparison.Ordinal) ||
                            value.StartsWith("http", StringComparison.OrdinalIgnoreCase) ||
                            value.StartsWith("POST ", StringComparison.OrdinalIgnoreCase) ||
                            value.StartsWith("GET ", StringComparison.OrdinalIgnoreCase);

        if (!isJsonOrHttp && (value.Contains("\",\"", StringComparison.Ordinal) || value.Contains("\", \"", StringComparison.Ordinal)))
            return false;

        if (value.Contains("????", StringComparison.Ordinal))
            return false;

        foreach (char c in value)
        {
            if (c < 0x20 || c > 0x7E)
            {
                if (c != '\r' && c != '\n' && c != '\t')
                    return false;
            }
        }

        if (value.Contains("<<"))
        {
            string trimmed = value.TrimStart();
            bool startsWithShellVerb = false;
            foreach (var verb in AllowedShellVerbs)
            {
                if (trimmed.StartsWith(verb, StringComparison.OrdinalIgnoreCase))
                {
                    startsWithShellVerb = true;
                    break;
                }
            }
            if (!startsWithShellVerb) return false;
        }

        return true;
    }

    private void EmitDiscovered(
        int pid,
        string processName,
        long memAddress,
        SentinelStage stage,
        string category,
        string desc,
        string rawValue,
        string targetRes,
        bool isAlreadyHex = false,
        string savedFilePath = "")
    {
        string cooldownKey = $"{pid}:{category}:{rawValue}";
        DateTime now = DateTime.UtcNow;
        if (_localCooldown.TryGetValue(cooldownKey, out var lastSeen) && (now - lastSeen).TotalSeconds < 2.5)
            return;
        _localCooldown[cooldownKey] = now;

        byte[] rawBytes = Encoding.UTF8.GetBytes(rawValue);
        OnCommandCaptured?.Invoke(new SourceTelemetryEvent
        {
            ProcessId = pid,
            ThreadId = 0,
            Stage = stage,
            HookedApiName = "LiveRAM_UniversalInterceptor",
            CallerModuleOrigin = $"{processName} [RAM @ 0x{memAddress:X8}]",
            TargetResource = targetRes,
            CommandCategory = category,
            DecodedCommandText = desc,
            PureCommandText = rawValue,
            SavedFilePath = savedFilePath,
            MemoryAddress = memAddress,
            RawPayloadHex = isAlreadyHex ? rawValue : Convert.ToHexString(rawBytes),
            PayloadSize = rawBytes.Length
        });
    }

    public void StopHunting()
    {
        try
        {
            _cts?.Cancel();
            _cts?.Dispose();
        }
        catch { }
        _cts = null;
        _monitoredPids.Clear();
        _childAdbPids.Clear();
        _localCooldown.Clear();
        _chunkHashCache.Clear();
        _isWinUsbOrChildAdbActive = false;
    }

    public void Dispose() => StopHunting();
}
