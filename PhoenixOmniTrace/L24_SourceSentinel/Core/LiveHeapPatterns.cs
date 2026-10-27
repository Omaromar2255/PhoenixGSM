using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace PhoenixOmniTrace.L24_SourceSentinel.Core;

/// <summary>
/// تعبيرات الفحص النمطية (Regex) ودوال تنظيف وفلترة النصوص في الذاكرة لفاحص الرام
/// </summary>
public static class LiveHeapPatterns
{
    public static readonly string[] AllowedShellVerbs =
    {
        "cat ", "sh ", "su ", "echo ", "dd ", "chmod ", "mount ", "rm ", "cp ", "mv ", "pm ", "am ", "setprop ", "getprop "
    };

    public static readonly HashSet<string> StaticAtErrorTableEntries = new(StringComparer.OrdinalIgnoreCase)
    {
        "+CPIN: SIM PIN", "+CPIN: SIM PUK", "+CPIN: SIM PIN2", "+CPIN: SIM PUK2",
        "+CPIN: PH-SIM PIN", "+CPIN: PH-NET PIN", "+CPIN: PH-NET PUK", "+CPIN: PH-NETSUB PIN"
    };

    public static readonly HashSet<string> TruncatedAtPrefixes = new(StringComparer.OrdinalIgnoreCase)
    {
        "AT+CGM", "AT+CIM", "AT+CNM", "AT+CFU", "AT+CSC",
        "AT+CIMP", "AT+CHU", "AT+CMG", "AT+CPB", "AT+DEVCO",
        "AT+CP", "AT+CH", "AT+CU", "AT+CLI", "AT+CPM", "AT^CU",
        "AT%IA", "AT%LA", "+CPIN:", "+CPIN: SI", "+CPIN: SIM PIN<"
    };

    // 1. أوامر المودم الصريحة
    public static readonly Regex StrictAtCommandRegex = new(
        @"(?:\bAT[\+\*\^\%\$\#][A-Z0-9_]{3,28}(?:=[0-9A-Za-z,""\-\.\?\/\:]{1,140}|\?)?(?=[\r\n\x00""\s]|$)|" +
        @"\b(?:ATE0|ATE1|ATI|ATZ|AT&F|AT&W)\b|" +
        @"\+DEVCONINFO:\s*[^\r\n\x00""]{6,240}|" +
        @"\+(?:CGMI|CGMM|CGMR|CGSN|CIMI|CPIN|CNUM|CLCK|IMEITEST|IMEISIGN|MSLSECUR|AKSEEDNO|VERSNAME|RFBYCODE|LOCKSTATUS|SPD|HWVER):\s*[A-Za-z0-9\-\._\s,]{3,160}(?=[\r\n\x00""]|$)|" +
        @"\b(?:060100[0-9A-Fa-f]{6,64}|120[dD]00[0-9A-Fa-f]{10,128}|514200[0-9A-Fa-f]{4,64}|516400[0-9A-Fa-f]{6,64})\b)",
        RegexOptions.Compiled);

    // 2. أوامر وبروتوكولات وسجلات تنفيذ MediaTek الحية (تشمل سطور التنفيذ الكاملة وبافرات الواجهة الحية)
    public static readonly Regex MtkProtocolRegex = new(
        @"(<h3\s+id=""header-mark"">[^\r\n\x00]{3,140}</h3>|" +
        @"\b(?:BOOT DEVICE|ERASE FRP|FORMAT DATA|FACTORY RESET|UNLOCK BOOTLOADER|RELOCK BOOTLOADER|READ BACK|FLASH|AUTH BYPASS|DUMP NV|WRITE NV)\b|" +
        @"\b(?:Initializing usb|Waiting for device|Bypassing authentication|Analyzing|Handshaking|Reading hardware info|Sending Download-Agent(?:\s*\[\d+\])?|Syncing with device|Booting device|Syncing with DA|Reading partition info|Reading device info|Erasing FRP|Formatting userdata|Unlocking bootloader|Relocking bootloader|Rebooting device|Writing|Erasing|Reading)\.{2,3}[^\r\n\x00""]{0,140}|" +
        @"\b(?:Hardware|Security Config|MEID|SOC ID|Storage|Vendor|Boot1|Model Name|Product Name|Manufacturer|Platform|Android Version|Security Patch|Build ID)\s*:\s*[^\r\n\x00""\<]{2,140}|" +
        @"\b(?:MTK_DOWNLOAD_AGENT|MTK_BLOADER_INFO|MTK_AllInOne_DA|DA_PL_CRYPTO|Brom_[A-Za-z0-9_]{3,45}|DA_[A-Za-z0-9_]{3,45}|SLA_Challenge|DAA_Challenge|Send_DA|Jump_DA|CMD_Download_DA|CMD_Read16|CMD_Write16|CMD_Read32|CMD_Write32|CMD_GetHwCode|CMD_GetTargetConfig|CMD_GetMeId|CMD_GetSocId|XFLASH_[A-Za-z0-9_]{3,45}|EMMC_BOOT|UFS_BOOT|BROM_REGISTER_ACCESS)\b|" +
        @"\b(?:preloader_[a-zA-Z0-9_]{2,50}\.bin(?:\s*\[[^\r\n\x00]{2,60}\])?|MT[0-9]{4}_Android_scatter\.txt|auth_sv5\.auth|DA_SWSEC[A-Za-z0-9_\.]*\.bin|DA_BR[A-Za-z0-9_\.]*\.bin|da_mt[0-9]{4}[A-Za-z0-9_\.]*\.bin)\b|" +
        @"\b(?:COM\d+\s*\((?:MediaTek|PreLoader|VCOM)[^\r\n\x00\)]{0,50}\)|COM\d+\s*\[(?:BOOTROM|PRELOADER):0E8D:[0-9A-Fa-f]{4}\]|BOOTROM:0E8D:0003|PRELOADER:0E8D:2000)\b|" +
        @"\b(?:erase|read|write|format|dump|flash|wipe|unlock|relock)\s+(?:nvram|nvdata|proinfo|protect1|protect2|seccfg|lk|lk2|boot|para|misc|recovery|userdata|frp|persistent|md1img|super|vbmeta|rpmb|preloader|pgpt)\b(?![""\,])[A-Za-z0-9_\-\s\.\/]{0,45})",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // 3. جميع أطوار ADB و Fastboot و Shell
    public static readonly Regex DeepAdbAndShellRegex = new(
        @"((?:shell|host|sync|usb|reboot|remount|reverse|tcp|localabstract|abb|abb_exec|framebuffer|jdwp):[A-Za-z0-9_\-\s\.\/,\=\$\#\|\<\>\&\;'\+]{2,220}|" +
        @"\b(?:adb|fastboot)\s+(?:shell|push|pull|install|install-multiple|uninstall|sideload|backup|restore|reboot|flash|flashing|oem|getvar|erase|boot|devices|forward|reverse|wait-for-device)\b[^\r\n\x00""]{0,150}|" +
        @"(?:^|[\r\n])\s*(?:[\$\#]\s*)?(?:su\s+-c|getprop|setprop|service\s+call|logcat\s+|dumpsys\s+|pm\s+(?:uninstall|install|install-create|install-write|install-commit|clear|grant|revoke|disable|disable-user|enable|list|path)|am\s+(?:start|broadcast|force-stop|startservice)|dd\s+if=|mount\s+-o|chmod\s+[0-7]{3,4}|chown\s+|rm\s+-rf|busybox\s+|toybox\s+|/data/local/tmp/AT)[^\r\n\x00""]{0,180}|" +
        @"(?:echo|cat)\s+[^\r\n\x00""]{1,100}\s*>>?\s*\/(?:dev|data|sdcard|system|efs|vendor)\/[A-Za-z0-9_\-\.\/]+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // 4. أوامر كوالكوم و EDL الموسعة (Firehose XML / Sahara / VIP / QMSL / DIAG) مع استبعاد ترويسات SVG و <program name unknown>
    public static readonly Regex QualcommCommandRegex = new(
        @"(\b(?:QLIB_[A-Za-z0-9_]{4,65}|QPHONEMS_[A-Za-z0-9_]{4,65}|fh_loader(?:\.exe)?\s+[^\r\n\x00""]{3,160}|qsahara_server(?:\.exe)?\s+[^\r\n\x00""]{3,160}|edl(?:\.py|\.exe)?\s+[^\r\n\x00""]{3,140})\b|" +
        @"<\?xml(?![\s\S]{0,120}<svg\b)[\s\S]{10,450}?(?:</data>|</FUSMsg>|</patches>)|" +
        @"<(?!program\s+name\s+unknown)(?:program|erase|patch|read|ufs|emmc|configure|power|getstorageinfo|setbootablestoragedrive|firmwarewrite|getsha256digest|peek|poke|nop|sig|vip)\s+[A-Za-z0-9_]+\s*=\s*""[^""]*""[^>]{0,240}/?>|" +
        @"<response\s+value=""(?:ACK|NAK)""[^>]{0,180}/>|" +
        @"\b(?:Calling handler for|Chip serial num|MSM_HW_ID|OEM_PK_HASH|Sahara protocol|Sending programmer|Connecting to flash programmer|Firehose|prog_emmc_firehose|prog_ufs_firehose|rawprogram[0-9]|patch[0-9])[A-Za-z0-9_\-\.\s\:\=0x\/\[\]]{2,140})",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // 5. أنماط أجهزة Apple iOS / iPadOS الشاملة (الأطوار الـ 7)
    public static readonly Regex AppleIosRamRegex = new(
        @"(\b(?:irecovery|ideviceinfo|ideviceactivation|idevice_id|idevicepair|idevicerestore|idevicebackup2|ideviceinstaller|iproxy|gaster|checkm8|pongo|syscfg)(?:\.exe)?\s+[^\r\n\x00""\<]{2,140}|" +
        @"\b(?:CPID:[0-9A-Fa-f]{4}|ECID:[0-9A-Fa-f]{8,20}|PWND:\[[A-Za-z0-9_\-\.]+\]|SRTG:\[iBoot-[0-9\.]+\]|MODE:(?:DFU|Recovery))[^\r\n\x00""]{0,100}|" +
        @"\b(?:setenv|getenv|saveenv|fsboot|bgcolor|sep\s+auto|fuse\s+lock|modload|ramdisk|bootx|xargs|syscfg\s+(?:print|add|get|delete))\b[^\r\n\x00""\<]{0,100}|" +
        @"\b(?:mount_apfs|mount_hfs|mount_filesystems|fsck_apfs|plutil\s+-|launchctl\s+|nvram\s+|chflags\s+)[^\r\n\x00""\<]{0,120}|" +
        @"\b(?:com\.apple\.(?:mobile\.lockdown|mobile\.installation_proxy|afc|mobilebackup2|mobile\.diagnostics_relay|mobileactivationd|commcenter)|MobileGestalt|ActivationRecord|activation_record\.plist|IC-Info\.sisv|data_ark\.plist|CFA6LPAA)\b[^\r\n\x00""\<]{0,100}|" +
        @"<key>(?:Request|QueryType|UniqueDeviceID|ActivationState|ProductType|SerialNumber|InternationalMobileEquipmentIdentity|DieID|MLB#|SrNm|WmMC|BTMAC)</key>\s*<string>[^<]{1,120}</string>)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // 6. الروابط واستدعاءات الملفات الخارجية من الخوادم
    public static readonly Regex CloudAndServerUrlRegex = new(
        @"((?:https?|wss?|ftp|tcp)://[a-zA-Z0-9\-\._~:/\?#\[\]@!\$&'\(\)\*\+,;=%]{8,280}|" +
        @"(?:^|[\r\n])\s*Host:\s*[a-zA-Z0-9\-\.]{4,120}(?::\d{2,5})?)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // 7. عمليات تسجيل الدخول والمصادقة والحسابات والتراخيص والبيانات المرسلة/المستلمة للخوادم
    public static readonly Regex LoginAndServerAuthRegex = new(
        @"((?:^|[\r\n])(?:POST|GET|PUT|DELETE|PATCH)\s+\/[a-zA-Z0-9_\-\.\/\?\&\=\%]{1,220}\s+HTTP\/[12]\.[01]|" +
        @"(?:^|[\r\n])HTTP\/[12]\.[01]\s+[2345]\d\d\s+[A-Za-z0-9\s]{2,40}|" +
        @"(?:^|[\r\n])(?:Authorization:\s*(?:Bearer|Basic)\s+[A-Za-z0-9\-\._~\+\/]+=*|X-API-Key:\s*[A-Za-z0-9\-\._]{6,140}|Set-Cookie:\s*[^\r\n\x00]{6,160}|Cookie:\s*[^\r\n\x00]{6,160})|" +
        @"\{[^{}\r\n]{0,60}""(?:username|user|email|login|password|passwd|pwd|token|access_token|refresh_token|jwt|session|session_id|hwid|pc_id|license|license_key|credit|balance|expire|expire_date|imei|serial|sn|ecid|udid|device_id|challenge|sla_challenge|daa_challenge|auth_req|signature|auth_data|signed_da|sla_sig|daa_sig|download_url|file_url|ticket|status|result|server_msg)""\s*:\s*[^}\r\n]{2,240}\}|" +
        @"\b(?:username|user|email|login|password|passwd|token|access_token|session_id|hwid|license_key)\s*[=:]\s*[A-Za-z0-9_\-\.\@\$\%\+\/]{3,120})",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // 8. أوامر رفع وتحميل ونقل الملفات وتجهيز ملفات البوت واللودر والفلاش
    public static readonly Regex FileTransferAndLoaderRegex = new(
        @"(\b(?:adb\s+(?:push|pull|sync)|sync:(?:SEND|RECV|STAT|DATA|DONE)|scp\s+-[a-zA-Z0-9]+\s+[^\r\n\x00""]{3,140}|sftp\s+[^\r\n\x00""]{4,140}|curl\s+[^\r\n\x00""]{5,160}|wget\s+[^\r\n\x00""]{5,160}|Invoke-WebRequest\s+[^\r\n\x00""]{5,160}|Start-BitsTransfer\s+[^\r\n\x00""]{5,160}|ideviceinstaller(?:\.exe)?\s+-[iIuU]\s+[^\r\n\x00""]{3,140})\b|" +
        @"\b(?:WriteFileToDevice|ReadFileFromDevice|DownloadFileAsync|UploadFileAsync|SendFileToPhone|PullFileFromPhone|ReadPartitionData|WritePartitionData|Send_DA|Download_DA|EmmcRead|EmmcWrite|UfsRead|UfsWrite)\b[^\r\n\x00""]{0,90}|" +
        @"(?<![a-zA-Z0-9_])([a-zA-Z]:\\[a-zA-Z0-9_\-\.\/\\ ]{3,160}\.(?:tar|tar\.md5|7z|zip|bin|da|auth|mbn|elf|img|pit|ops|ofp|pac|qcn|xqcn|shsh2|im4p|img4|xml|json|txt))(?![a-zA-Z0-9_])|" +
        @"(?<![a-zA-Z0-9_])([a-zA-Z0-9_\-\.]{3,90}\.(?:mbn|elf|pit|ops|ofp|pac|qcn|xqcn|shsh2|im4p|img4|da|auth|scatter\.txt))(?![a-zA-Z0-9_]))",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // 9. أوامر فتح الضغط والضغط وتفكيك الصور
    public static readonly Regex ArchiveAndUnpackCommandRegex = new(
        @"(\b(?:7z|7za|unzip|unrar|tar|gzip|gunzip|bzip2|xz|lz4|zstd|brotli|simg2img|img2simg|lpunpack|payload-dumper|cabextract|expand)(?:\.exe)?\s+(?:-[a-zA-Z0-9]+\s+|x\s+|e\s+|-xf\s+|-xzf\s+|d\s+)[^\r\n\x00""]{3,150}|" +
        @"\b(?:ZipFile\.ExtractToDirectory|ArchiveExtractor\.[A-Za-z0-9_]+|SevenZipExtractor|Lz4Decompress|SparseImageConverter)\b[^\r\n\x00""]{0,90})",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // 10. أوامر التشفير وفك التشفير + صائد المفاتيح والبذور الأمنية
    public static readonly Regex CryptoAndDecryptionCommandRegex = new(
        @"(\b(?:openssl\s+(?:enc|aes-[0-9]{3}-[a-z]+|dgst|rsautl|pkeyutl)\s+[^\r\n\x00""]{4,150}|ofp_decrypt[^\r\n\x00""]{0,110}|ops_decrypt[^\r\n\x00""]{0,110}|ozipdecrypt[^\r\n\x00""]{0,110})\b|" +
        @"\b(?:AES_decrypt|AES_encrypt|AES_cbc_encrypt|RSA_private_decrypt|RSA_public_encrypt|EVP_DecryptInit|EVP_EncryptInit|CryptDecrypt|CryptEncrypt|BCryptDecrypt|BCryptEncrypt|RijndaelManaged|AesGcm|PBKDF2|HMACSHA256|DecryptFirmware|DecryptPayload|EncryptPayload|VerifyAuthSignature)\b[^\r\n\x00""]{0,70}|" +
        @"\b(?:AKSEEDNO|MSLSECUR|SimLock|NCK_CODE|MCK_CODE|SPC_CODE|AES_KEY|RSA_MODULUS|SLA_RESPONSE|DAA_RESPONSE|AUTH_SIGNATURE)\s*[:=]\s*[^\r\n\x00""]{4,140})",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // 11. بروتوكولات Odin و Unisoc SPD والمسارات الحساسة وأوامر الأدوات الأخرى
    public static readonly Regex OdinSpdAndOtherRegex = new(
        @"(\b(?:BSL_CMD_[A-Za-z0-9_]{3,40}|spd_dump(?:\.exe)?\s+[^\r\n\x00""]{3,140}|FDL1|FDL2|LOKE_[A-Za-z0-9_]{2,30}|ODIN_[A-Za-z0-9_]{2,50})\b|" +
        @"\b(?:cmd(?:\.exe)?\s+\/[cCkK]\s+[^\r\n\x00""]{4,140}|powershell(?:\.exe)?\s+-(?:Command|EncodedCommand|File|NoProfile|ExecutionPolicy)\s+[^\r\n\x00""]{4,140}|pnputil(?:\.exe)?\s+\/[a-zA-Z\-]+\s+[^\r\n\x00""]{2,100}|devcon(?:\.exe)?\s+[a-zA-Z]+\s+[^\r\n\x00""]{2,100}|filter-x(?:64|86)(?:\.exe)?\s+[^\r\n\x00""]{3,120})\b|" +
        @"(\/(?:data\/local\/tmp|dev\/block\/bootdevice\/by-name|dev\/block\/platform|dev\/block\/mapper|dev\/smd|dev\/ttyUSB|dev\/ttyACM|dev\/at_mdm|dev\/umts_ipc|efs|nvdata|nvram|persist|mnt\/vendor\/persist)\/[A-Za-z0-9_\-\.\/]{1,90})|" +
        @"(\\\\\?\\(?:usb|USB)#VID_[0-9A-Fa-f]{4}&PID_[0-9A-Fa-f]{4}#[^\s""\x00-\x1F\<\>]{4,110}))",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public static bool IsLikelyTruncatedAtFragment(string val)
    {
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

    private static readonly Regex InlineHtmlTagsRegex = new(
        @"</?(?:b|font|span|h3|div|p|i|u|strong)\b[^>]*>",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex MultiSpaceAfterDotsRegex = new(
        @"(\.{3}|\]|\:)\s{2,}",
        RegexOptions.Compiled);

    public static string StripInlineHtmlFormatting(string input)
    {
        if (string.IsNullOrEmpty(input) || !input.Contains('<'))
            return input;
        string replaced = input.Replace("<br>", "\n", StringComparison.OrdinalIgnoreCase)
                               .Replace("<br/>", "\n", StringComparison.OrdinalIgnoreCase)
                               .Replace("<br />", "\n", StringComparison.OrdinalIgnoreCase)
                               .Replace("</h3>", "\n", StringComparison.OrdinalIgnoreCase)
                               .Replace("&nbsp;", " ", StringComparison.OrdinalIgnoreCase)
                               .Replace("\0", "\n", StringComparison.Ordinal);
        string stripped = InlineHtmlTagsRegex.Replace(replaced, "");
        string joined = Regex.Replace(stripped, @"\.{3}\s*\r?\n\s*(OK(?:\s*\[\w+\])?|FAIL|COM\d+(?:\s*\[[^\r\n]+\])?|preloader_[^\r\n]+)", "... $1\n", RegexOptions.IgnoreCase);
        return MultiSpaceAfterDotsRegex.Replace(joined, "$1 ");
    }

    public static readonly System.Collections.Concurrent.ConcurrentDictionary<string, (ulong BeginAddr, ulong EndAddr, ulong SizeBytes, uint StartLba, uint Sectors)> DiscoveredGptPartitions = new(StringComparer.OrdinalIgnoreCase);

    public static string LastCarvedPreloaderPath { get; set; } = string.Empty;
    public static string LastCarvedGfhPath { get; set; } = string.Empty;
    public static string LastCarvedScatterPath { get; set; } = string.Empty;

    public static bool IsPureUiCosmeticOrDeviceInfoLine(string val)
    {
        if (string.IsNullOrWhiteSpace(val)) return true;
        if (val.StartsWith("Initializing usb", StringComparison.OrdinalIgnoreCase) ||
            val.StartsWith("Syncing with device", StringComparison.OrdinalIgnoreCase) ||
            val.StartsWith("Model Name :", StringComparison.OrdinalIgnoreCase) ||
            val.StartsWith("Product Name :", StringComparison.OrdinalIgnoreCase) ||
            val.StartsWith("Manufacturer :", StringComparison.OrdinalIgnoreCase) ||
            val.StartsWith("Platform :", StringComparison.OrdinalIgnoreCase) ||
            val.StartsWith("Android Version :", StringComparison.OrdinalIgnoreCase) ||
            val.StartsWith("Security Patch :", StringComparison.OrdinalIgnoreCase) ||
            val.StartsWith("Build ID :", StringComparison.OrdinalIgnoreCase) ||
            val.StartsWith("Build :", StringComparison.OrdinalIgnoreCase) ||
            val.StartsWith("Build Date :", StringComparison.OrdinalIgnoreCase) ||
            val.StartsWith("Vendor :", StringComparison.OrdinalIgnoreCase) ||
            val.StartsWith("Boot1 :", StringComparison.OrdinalIgnoreCase) ||
            val.Equals("BOOT DEVICE", StringComparison.OrdinalIgnoreCase) ||
            val.Equals("ERASE FRP", StringComparison.OrdinalIgnoreCase) ||
            val.Equals("FORMAT DATA", StringComparison.OrdinalIgnoreCase) ||
            val.Equals("FACTORY RESET", StringComparison.OrdinalIgnoreCase) ||
            val.Equals("READ BACK", StringComparison.OrdinalIgnoreCase) ||
            val.Equals("FLASH", StringComparison.OrdinalIgnoreCase) ||
            val.StartsWith("<h3", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }
        return false;
    }

    public static bool TryTranslateToLowLevelMtkCommand(string val, out string lowLevelCommand, out string lowLevelDesc, out string associatedFilePath)
    {
        lowLevelCommand = string.Empty;
        lowLevelDesc = string.Empty;
        associatedFilePath = string.Empty;

        if (string.IsNullOrWhiteSpace(val) || IsPureUiCosmeticOrDeviceInfoLine(val))
            return false;

        if (val.StartsWith("Waiting for device...", StringComparison.OrdinalIgnoreCase) && val.Contains("0E8D", StringComparison.OrdinalIgnoreCase))
        {
            var comM = Regex.Match(val, @"COM\d+", RegexOptions.IgnoreCase);
            string port = comM.Success ? comM.Value.ToUpperInvariant() : "VCOM";
            string mode = val.Contains("0003") ? "BOOTROM (0E8D:0003)" : "PRELOADER (0E8D:2000)";
            lowLevelCommand = $"USB_VCOM_OPEN :: CreateFile(\"\\\\.\\{port}\", GENERIC_READ|GENERIC_WRITE) [Mode={mode}]";
            lowLevelDesc = $"فتح قناة اتصال البوت المنخفضة عبر المنفذ التسلسلي ({port}) [{mode}]";
            return true;
        }

        if (val.StartsWith("Handshaking... OK", StringComparison.OrdinalIgnoreCase))
        {
            lowLevelCommand = "BROM_START_CMD :: TX=[A0 0A 50 05] -> RX=[5F F5 AF FA]";
            lowLevelDesc = "أمر مصافحة معالج MediaTek BROM الثنائي المباشر (A0 0A 50 05 -> 5F F5 AF FA)";
            return true;
        }

        if (val.StartsWith("Bypassing authentication... OK", StringComparison.OrdinalIgnoreCase))
        {
            lowLevelCommand = "BROM_SLA_DAA_BYPASS :: CMD_WRITE32(0xD4, Reg=0x10007000 [WDT_MODE], Val=0x22000064) + USB_CTRL_XFER(bmReq=0xA1, bReq=0x00, BromRegisterAccess)";
            lowLevelDesc = "أمر تعطيل المؤقت الحارس (WDT=0x10007000) وتجاوز حماية المصادقة (SLA/DAA) عبر أمر الكتابة بالمسجلات CMD_WRITE32 (0xD4)";
            if (!string.IsNullOrEmpty(LastCarvedGfhPath)) associatedFilePath = LastCarvedGfhPath;
            return true;
        }

        if (val.StartsWith("Analyzing...", StringComparison.OrdinalIgnoreCase) && val.Contains("preloader_", StringComparison.OrdinalIgnoreCase))
        {
            var m = Regex.Match(val, @"(preloader_[A-Za-z0-9_]+\.bin)\s*(?:\[([^\]]+)\])?", RegexOptions.IgnoreCase);
            string pFile = m.Success ? m.Groups[1].Value : "preloader.bin";
            string meta = m.Success && m.Groups[2].Success ? m.Groups[2].Value : "EMI";
            associatedFilePath = LastCarvedPreloaderPath;
            string savedNote = !string.IsNullOrEmpty(associatedFilePath) ? $" | SavedFile={associatedFilePath}" : "";
            lowLevelCommand = $"EMI_DRAM_PARSE :: LoadInternalPreloader(File=\"{pFile}\", Config=[{meta}], Header=MTK_BLOADER_INFO_v38){savedNote}";
            lowLevelDesc = $"تحميل وتفكيك ملف تهيئة الذاكرة الداخلي (EMI Preloader: {pFile} [{meta}]) لضبط توقيتات الـ DRAM";
            return true;
        }

        if (val.StartsWith("Hardware :", StringComparison.OrdinalIgnoreCase))
        {
            string hwInfo = val["Hardware :".Length..].Trim();
            var hexM = Regex.Match(hwInfo, @"([0-9A-Fa-f]{4})\s+([0-9A-Fa-f]{4})\s+([0-9A-Fa-f]{4})\s+([0-9A-Fa-f]{4})");
            if (!hexM.Success) return false;
            lowLevelCommand = $"BROM_GET_HW_DICT :: CMD_GET_HW_CODE(0xFD)->0x{hexM.Groups[1].Value} | CMD_GET_HW_SW_VER(0xFC)->[HW_SUB=0x{hexM.Groups[2].Value}, HW_VER=0x{hexM.Groups[3].Value}, SW_VER=0x{hexM.Groups[4].Value}] ({hwInfo})";
            lowLevelDesc = "أوامر قراءة معرف المعالج وإصدار العتاد من الـ BROM: CMD_GET_HW_CODE (0xFD) + CMD_GET_HW_SW_VER (0xFC)";
            return true;
        }

        if (val.StartsWith("Security Config :", StringComparison.OrdinalIgnoreCase))
        {
            string sec = val["Security Config :".Length..].Trim();
            if (sec.Length < 2 || (!sec.Contains("SCB", StringComparison.OrdinalIgnoreCase) && !sec.Contains("SBC", StringComparison.OrdinalIgnoreCase) && !sec.Contains("SLA", StringComparison.OrdinalIgnoreCase) && !sec.Contains("DAA", StringComparison.OrdinalIgnoreCase)))
                return false;
            lowLevelCommand = $"BROM_GET_TARGET_CONFIG :: CMD_GET_TARGET_CONFIG(0xD8) -> SEC_CFG=[{sec}]";
            lowLevelDesc = $"أمر فحص سجلات الحماية الأمنية للمعالج CMD_GET_TARGET_CONFIG (0xD8) -> [{sec}]";
            return true;
        }

        if (val.StartsWith("MEID :", StringComparison.OrdinalIgnoreCase) || val.StartsWith("SOC ID :", StringComparison.OrdinalIgnoreCase))
        {
            bool isSoc = val.StartsWith("SOC ID", StringComparison.OrdinalIgnoreCase);
            string idVal = val[(val.IndexOf(':') + 1)..].Trim();
            if (!Regex.IsMatch(idVal, @"^[0-9A-Fa-f]{16,64}$")) return false;
            lowLevelCommand = isSoc
                ? $"BROM_GET_SOC_ID :: CMD_GET_SOC_ID(0xE7) -> RX_SOC_ID[32B]={idVal}"
                : $"BROM_GET_ME_ID :: CMD_GET_ME_ID(0xE1) -> RX_MEID[16B]={idVal}";
            lowLevelDesc = isSoc
                ? $"أمر قراءة البصمة الرقمية للمعالج CMD_GET_SOC_ID (0xE7): {idVal}"
                : $"أمر قراءة الرقم التسلسلي الفريد للمعالج CMD_GET_ME_ID (0xE1): {idVal}";
            return true;
        }

        if (val.StartsWith("Sending Download-Agent", StringComparison.OrdinalIgnoreCase) && val.Contains("OK", StringComparison.OrdinalIgnoreCase))
        {
            associatedFilePath = !string.IsNullOrEmpty(LastCarvedGfhPath) ? LastCarvedGfhPath : LastCarvedPreloaderPath;
            string savedNote = !string.IsNullOrEmpty(associatedFilePath) ? $" | PayloadFile={associatedFilePath}" : "";
            lowLevelCommand = $"BROM_SEND_DA :: CMD_SEND_DA(0xD7, TargetAddr=0x00200000 [SRAM], Stage=DA_Stage1) -> ChecksumVerify=OK{savedNote}";
            lowLevelDesc = "أمر حقن وإرسال وكيل التحميل (Download-Agent Stage 1) إلى ذاكرة SRAM الداخلية (0x00200000) عبر الأمر CMD_SEND_DA (0xD7)";
            return true;
        }

        if (val.StartsWith("Booting device... OK", StringComparison.OrdinalIgnoreCase))
        {
            associatedFilePath = LastCarvedPreloaderPath;
            lowLevelCommand = "BROM_JUMP_DA :: CMD_JUMP_DA(0xD5, JumpAddr=0x00200000) -> DA_STAGE1_INIT_DRAM(EMI=preloader_u520.bin) -> DA_SEND_STAGE2(TargetAddr=0x40000000 [DRAM])";
            lowLevelDesc = "أمر القفز لتنفيذ وكيل التحميل CMD_JUMP_DA (0xD5 @ 0x00200000) وتهيئة الـ DRAM وتحميل المرحلة الثانية DA Stage 2 (@ 0x40000000)";
            return true;
        }

        if (val.StartsWith("Storage :", StringComparison.OrdinalIgnoreCase))
        {
            string st = val["Storage :".Length..].Trim();
            if (!st.Contains("CID", StringComparison.OrdinalIgnoreCase) || st.Length < 20) return false;
            lowLevelCommand = $"DA_READ_STORAGE_INFO :: DA_CMD_SYNC(0xC0) & EMMC_SEND_CID -> [{st}]";
            lowLevelDesc = $"أمر وكيل التحميل (DA) لقراءة معرف شريحة الذاكرة الداخلية (eMMC/UFS CID): {st}";
            return true;
        }

        if (val.StartsWith("Reading partition info...", StringComparison.OrdinalIgnoreCase) && val.Contains("OK", StringComparison.OrdinalIgnoreCase))
        {
            var cntM = Regex.Match(val, @"OK\s*\[(\d+)\]", RegexOptions.IgnoreCase);
            string cntStr = cntM.Success ? $"Count={cntM.Groups[1].Value}" : "OK";
            associatedFilePath = LastCarvedScatterPath;
            string savedNote = !string.IsNullOrEmpty(associatedFilePath) ? $" | ScatterFile={associatedFilePath}" : "";
            lowLevelCommand = $"DA_READ_GPT_TABLE :: DA_CMD_READ_PGPT(Addr=0x00000000, Length=0x00008000 [32KiB], Region=EMMC_USER, {cntStr}){savedNote}";
            lowLevelDesc = "أمر قراءة جدول تقسيمات الذاكرة الخام (Primary GPT @ 0x0..0x8000) عبر وكيل التحميل DA واستخراج عناوين القطاعات";
            return true;
        }

        if (val.StartsWith("Reading device info...", StringComparison.OrdinalIgnoreCase) && val.Contains("[", StringComparison.Ordinal))
        {
            var pm = Regex.Match(val, @"\[([A-Za-z0-9_]+)\]");
            string partName = pm.Success ? pm.Groups[1].Value : "super";
            string addrInfo = GetPartitionAddressTag(partName);
            lowLevelCommand = $"DA_READ_PARTITION_PROBE :: DA_CMD_READ_DATA(Partition=\"{partName}\"{addrInfo}, Target=\"build.prop\")";
            lowLevelDesc = $"أمر قراءة قطاع النظام ({partName}{addrInfo}) عبر وكيل التحميل DA لاستخراج خصائص البناء (build.prop)";
            return true;
        }

        if (val.StartsWith("Erasing ", StringComparison.OrdinalIgnoreCase) ||
            val.StartsWith("Formatting ", StringComparison.OrdinalIgnoreCase) ||
            val.StartsWith("Writing ", StringComparison.OrdinalIgnoreCase) ||
            (val.StartsWith("Reading ", StringComparison.OrdinalIgnoreCase) && !val.StartsWith("Reading hardware", StringComparison.OrdinalIgnoreCase) && !val.StartsWith("Reading partition", StringComparison.OrdinalIgnoreCase) && !val.StartsWith("Reading device", StringComparison.OrdinalIgnoreCase)))
        {
            var pm = Regex.Match(val, @"\b(nvram|nvdata|proinfo|protect1|protect2|seccfg|lk|lk2|boot|para|misc|recovery|userdata|frp|persist|md1img|super|vbmeta|vbmeta_system|vbmeta_vendor|spmfw|sspm_1|sspm_2|gz1|gz2|dtbo|logo|tee1|tee2|cache|carrier|otp|flashinfo|preloader|pgpt)\b", RegexOptions.IgnoreCase);
            string partName = pm.Success ? pm.Groups[1].Value.ToLowerInvariant() : "partition";
            string addrInfo = GetPartitionAddressTag(partName);
            string daOp = val.StartsWith("Erasing", StringComparison.OrdinalIgnoreCase) || val.StartsWith("Formatting", StringComparison.OrdinalIgnoreCase)
                ? "DA_CMD_FORMAT_PARTITION (0x010005)"
                : (val.StartsWith("Writing", StringComparison.OrdinalIgnoreCase) ? "DA_CMD_WRITE_PARTITION (0x010003)" : "DA_CMD_READ_PARTITION (0x010004)");
            lowLevelCommand = $"{daOp} :: [Partition=\"{partName}\"{addrInfo}] ({val})";
            lowLevelDesc = $"أمر تنفيذ مباشر من وكيل التحميل DA على قطاع الذاكرة [{partName}{addrInfo}]: {val}";
            return true;
        }

        return false;
    }

    public static string GetPartitionAddressTag(string partName)
    {
        if (DiscoveredGptPartitions.TryGetValue(partName, out var p))
        {
            return $", BeginAddr=0x{p.BeginAddr:X8}, EndAddr=0x{p.EndAddr:X8}, Size=0x{p.SizeBytes:X8} ({p.SizeBytes / 1024} KiB)";
        }
        return string.Empty;
    }

    public static bool IsConfirmedLiveExecutionStep(string val)
    {
        if (string.IsNullOrWhiteSpace(val) || IsPureUiCosmeticOrDeviceInfoLine(val)) return false;
        if (TryTranslateToLowLevelMtkCommand(val, out _, out _, out _))
            return true;
        if (val.Contains("[BOOTROM:0E8D:", StringComparison.OrdinalIgnoreCase) ||
            val.Contains("[PRELOADER:0E8D:", StringComparison.OrdinalIgnoreCase) ||
            val.Contains("0E8D&PID_0003", StringComparison.OrdinalIgnoreCase) ||
            val.Contains("05C6&PID_9008", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }
        return false;
    }

    public static bool IsHtmlOrUiFormatNoise(string val)
    {
        return val.Contains("</li>", StringComparison.OrdinalIgnoreCase) ||
               val.Contains("<a href=", StringComparison.OrdinalIgnoreCase) ||
               val.Contains("<svg", StringComparison.OrdinalIgnoreCase) ||
               val.Equals("bgcolor", StringComparison.OrdinalIgnoreCase) ||
               val.Equals("bgcolor=", StringComparison.OrdinalIgnoreCase) ||
               val.Equals("bgcolor-color", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsWindowsSetupApiRebootNoise(string val)
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

    public static bool IsChilkatOrDummyFileNoise(string val)
    {
        return val.Contains("CXDUMMYFILE.TXT", StringComparison.OrdinalIgnoreCase) ||
               val.Contains("TRUSTPOL.TXT", StringComparison.OrdinalIgnoreCase) ||
               val.Contains("AslLog_", StringComparison.OrdinalIgnoreCase) ||
               val.Contains("chilkatsoft.com", StringComparison.OrdinalIgnoreCase) ||
               val.Contains("AES_ENCRYPT == enc", StringComparison.OrdinalIgnoreCase);
    }

    public static string CleanToken(string input, bool allowNewLines = false, bool preserveUrlChars = false)
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

    public static bool IsCleanRamString(string value)
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
}
