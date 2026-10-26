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

    // 2. أوامر وبروتوكولات وسجلات تنفيذ MediaTek الحية
    public static readonly Regex MtkProtocolRegex = new(
        @"(\b(?:MTK_DOWNLOAD_AGENT|MTK_BLOADER_INFO|MTK_AllInOne_DA|DA_PL_CRYPTO|Brom_[A-Za-z0-9_]{3,45}|DA_[A-Za-z0-9_]{3,45}|SLA_Challenge|DAA_Challenge|Send_DA|Jump_DA|CMD_Download_DA|CMD_Read16|CMD_Write16|CMD_Read32|CMD_Write32|CMD_GetHwCode|CMD_GetTargetConfig|CMD_GetMeId|CMD_GetSocId|XFLASH_[A-Za-z0-9_]{3,45}|EMMC_BOOT|UFS_BOOT|BROM_REGISTER_ACCESS)\b|" +
        @"\b(?:preloader_[a-zA-Z0-9_]{2,50}\.bin|MT[0-9]{4}_Android_scatter\.txt|auth_sv5\.auth|DA_SWSEC[A-Za-z0-9_\.]*\.bin|DA_BR[A-Za-z0-9_\.]*\.bin|da_mt[0-9]{4}[A-Za-z0-9_\.]*\.bin)\b|" +
        @"\b(?:Waiting for device|Bypassing authentication|Handshaking|Sending Download-Agent|Booting device|Reading partition info|Erasing FRP|Formatting userdata|Unlocking bootloader|Relocking bootloader|BOOTROM:0E8D:0003|PRELOADER:0E8D:2000|Hardware\s*:\s*MT[0-9]{4}[A-Za-z0-9\s\(\)\/]*|Security Config\s*:\s*[^\r\n\x00""\<]{2,80}|MEID\s*:\s*[0-9A-Fa-f]{8,32}|SOC ID\s*:\s*[0-9A-Fa-f]{16,64})\b|" +
        @"\b(?:erase|read|write|format|dump|flash|wipe|unlock|relock)\s+(?:nvram|nvdata|proinfo|protect1|protect2|seccfg|lk|lk2|boot|para|misc|recovery|userdata|frp|persistent|md1img|super|vbmeta|rpmb|preloader|pgpt)\b(?![""\,])[A-Za-z0-9_\-\s\.\/]{0,45})",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // 3. جميع أطوار ADB و Fastboot و Shell
    public static readonly Regex DeepAdbAndShellRegex = new(
        @"((?:shell|host|sync|usb|reboot|remount|reverse|tcp|localabstract|abb|abb_exec|framebuffer|jdwp):[A-Za-z0-9_\-\s\.\/,\=\$\#\|\<\>\&\;'\+]{2,220}|" +
        @"\b(?:adb|fastboot)\s+(?:shell|push|pull|install|install-multiple|uninstall|sideload|backup|restore|reboot|flash|flashing|oem|getvar|erase|boot|devices|forward|reverse|wait-for-device)\b[^\r\n\x00""]{0,150}|" +
        @"(?:^|[\r\n])\s*(?:[\$\#]\s*)?(?:su\s+-c|getprop|setprop|service\s+call|logcat\s+|dumpsys\s+|pm\s+(?:uninstall|install|install-create|install-write|install-commit|clear|grant|revoke|disable|disable-user|enable|list|path)|am\s+(?:start|broadcast|force-stop|startservice)|dd\s+if=|mount\s+-o|chmod\s+[0-7]{3,4}|chown\s+|rm\s+-rf|busybox\s+|toybox\s+|/data/local/tmp/AT)[^\r\n\x00""]{0,180}|" +
        @"(?:echo|cat)\s+[^\r\n\x00""]{1,100}\s*>>?\s*\/(?:dev|data|sdcard|system|efs|vendor)\/[A-Za-z0-9_\-\.\/]+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // 4. أوامر كوالكوم و EDL الموسعة (Firehose XML / Sahara / VIP / QMSL / DIAG)
    public static readonly Regex QualcommCommandRegex = new(
        @"(\b(?:QLIB_[A-Za-z0-9_]{4,65}|QPHONEMS_[A-Za-z0-9_]{4,65}|fh_loader(?:\.exe)?\s+[^\r\n\x00""]{3,160}|qsahara_server(?:\.exe)?\s+[^\r\n\x00""]{3,160}|edl(?:\.py|\.exe)?\s+[^\r\n\x00""]{3,140})\b|" +
        @"<\?xml[\s\S]{10,450}?(?:</data>|</FUSMsg>|</patches>)|" +
        @"<(?:program|erase|patch|read|ufs|emmc|configure|power|getstorageinfo|setbootablestoragedrive|firmwarewrite|getsha256digest|peek|poke|nop|sig|vip)\b[^>]{2,260}/?>|" +
        @"<response\s+value=""(?:ACK|NAK)""[^>]{0,180}/>|" +
        @"\b(?:Calling handler for|Chip serial num|MSM_HW_ID|OEM_PK_HASH|Sahara protocol|Firehose|prog_emmc_firehose|prog_ufs_firehose|rawprogram[0-9]|patch[0-9])[A-Za-z0-9_\-\.\s\:\=0x\/]{2,120})",
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

    public static bool IsHtmlOrUiFormatNoise(string val)
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
