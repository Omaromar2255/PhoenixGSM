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
    private volatile bool _isWinUsbOrChildAdbActive;
    private int _parentScanCycleCounter;

    public event Action<SourceTelemetryEvent>? OnCommandCaptured;

    public L24DiscoveryMode DiscoveryMode { get; set; } = L24DiscoveryMode.FullRamDiscovery;

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
        "AT+CIMP", "AT+CHU", "AT+CMG", "AT+CPB", "AT+DEVCO"
    };

    // 1. أوامر المودم الصريحة (AT+, AT*, AT^, AT%, AT$, AT#, ATE, ATI, ATZ) + ردود الهاتف + أوامر RIL IPC الهيكس
    private static readonly Regex StrictAtCommandRegex = new(
        @"(?:\bAT[\+\*\^\%\$\#][A-Z0-9_]{2,28}(?:=[0-9A-Za-z,""\-\.\?\/\:]{1,140}|\?)?|" +
        @"\b(?:ATE0|ATE1|ATI|ATZ|AT&F|AT&W)\b|" +
        @"\+DEVCONINFO:\s*[^\r\n\x00""]{6,240}|" +
        @"\+(?:CGMI|CGMM|CGMR|CGSN|CIMI|CPIN|CNUM|CLCK|IMEITEST|IMEISIGN|MSLSECUR|AKSEEDNO|VERSNAME|RFBYCODE|LOCKSTATUS|SPD|HWVER):\s*[^\r\n\x00""]{2,160}|" +
        @"\b(?:060100[0-9A-Fa-f]{6,64}|120[dD]00[0-9A-Fa-f]{10,128}|514200[0-9A-Fa-f]{4,64}|516400[0-9A-Fa-f]{6,64})\b)",
        RegexOptions.Compiled);

    // 2. أوامر وبروتوكولات وسجلات تنفيذ MediaTek الحية (BROM / Preloader / DA / XFlash / SLA / DAA / Live Execution Stages)
    private static readonly Regex MtkProtocolRegex = new(
        @"(\b(?:MTK_DOWNLOAD_AGENT|MTK_BLOADER_INFO|MTK_AllInOne_DA|DA_PL_CRYPTO|Brom_[A-Za-z0-9_]{3,45}|DA_[A-Za-z0-9_]{3,45}|SLA_Challenge|DAA_Challenge|Send_DA|Jump_DA|CMD_Download_DA|CMD_Read16|CMD_Write16|CMD_Read32|CMD_Write32|CMD_GetHwCode|CMD_GetTargetConfig|CMD_GetMeId|CMD_GetSocId|XFLASH_[A-Za-z0-9_]{3,45}|EMMC_BOOT|UFS_BOOT|BROM_REGISTER_ACCESS)\b|" +
        @"\b(?:preloader_[a-zA-Z0-9_]{2,50}\.bin|MT[0-9]{4}_Android_scatter\.txt|auth_sv5\.auth|DA_SWSEC[A-Za-z0-9_\.]*\.bin|DA_BR[A-Za-z0-9_\.]*\.bin)\b|" +
        @"\b(?:Waiting for device|Bypassing authentication|Handshaking|Sending Download-Agent|Booting device|Reading partition info|Erasing FRP|Formatting userdata|Unlocking bootloader|Relocking bootloader|BOOTROM:0E8D:0003|PRELOADER:0E8D:2000|Hardware\s*:\s*MT[0-9]{4}[A-Za-z0-9\s\(\)\/]*|Security Config\s*:\s*[^\r\n\x00""]{2,80}|MEID\s*:\s*[0-9A-Fa-f]{8,32}|SOC ID\s*:\s*[0-9A-Fa-f]{16,64})\b|" +
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
        @"(\b(?:irecovery|ideviceinfo|ideviceactivation|idevice_id|idevicepair|idevicerestore|idevicebackup2|ideviceinstaller|iproxy|gaster|checkm8|pongo|syscfg)(?:\.exe)?\s+[^\r\n\x00""]{2,140}|" +
        @"\b(?:CPID:[0-9A-Fa-f]{4}|ECID:[0-9A-Fa-f]{8,20}|PWND:\[[A-Za-z0-9_\-\.]+\]|SRTG:\[iBoot-[0-9\.]+\]|MODE:(?:DFU|Recovery))[^\r\n\x00""]{0,100}|" +
        @"\b(?:setenv|getenv|saveenv|fsboot|bgcolor|sep\s+auto|fuse\s+lock|modload|ramdisk|bootx|xargs|syscfg\s+(?:print|add|get|delete))\b[^\r\n\x00""]{0,100}|" +
        @"\b(?:mount_apfs|mount_hfs|mount_filesystems|fsck_apfs|plutil\s+-|launchctl\s+|nvram\s+|chflags\s+|SSH-2\.0-[A-Za-z0-9_\.\-]+)[^\r\n\x00""]{0,120}|" +
        @"\b(?:com\.apple\.(?:mobile\.lockdown|mobile\.installation_proxy|afc|mobilebackup2|mobile\.diagnostics_relay|mobileactivationd|commcenter)|MobileGestalt|ActivationRecord|activation_record\.plist|IC-Info\.sisv|data_ark\.plist|CFA6LPAA)\b[^\r\n\x00""]{0,100}|" +
        @"<key>(?:Request|QueryType|UniqueDeviceID|ActivationState|ProductType|SerialNumber|InternationalMobileEquipmentIdentity|DieID|MLB#|SrNm|WmMC|BTMAC)</key>\s*<string>[^<]{1,120}</string>)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // 6. الروابط واستدعاءات الملفات الخارجية من الخوادم (URLs & Cloud Files - يسمح بـ ? و & و = بالكامل)
    private static readonly Regex CloudAndServerUrlRegex = new(
        @"((?:https?|wss?|ftp|tcp)://[a-zA-Z0-9\-\._~:/\?#\[\]@!\$&'\(\)\*\+,;=%]{8,280}|" +
        @"(?:^|[\r\n])\s*Host:\s*[a-zA-Z0-9\-\.]{4,120}(?::\d{2,5})?)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // 7. عمليات تسجيل الدخول والمصادقة والحسابات والتراخيص والبيانات المرسلة/المستلمة للخوادم (Login / Auth / Session / HTTP / JSON)
    private static readonly Regex LoginAndServerAuthRegex = new(
        @"((?:^|[\r\n])(?:POST|GET|PUT|DELETE|PATCH)\s+\/[a-zA-Z0-9_\-\.\/\?\&\=\%]{1,220}\s+HTTP\/[12]\.[01]|" +
        @"(?:^|[\r\n])HTTP\/[12]\.[01]\s+[2345]\d\d\s+[A-Za-z0-9\s]{2,40}|" +
        @"(?:^|[\r\n])(?:Authorization:\s*(?:Bearer|Basic)\s+[A-Za-z0-9\-\._~\+\/]+=*|X-API-Key:\s*[A-Za-z0-9\-\._]{6,140}|Set-Cookie:\s*[^\r\n\x00]{6,160}|Cookie:\s*[^\r\n\x00]{6,160})|" +
        @"\{[^{}\r\n]{0,60}""(?:username|user|email|login|password|passwd|pwd|token|access_token|refresh_token|jwt|session|session_id|hwid|pc_id|license|license_key|credit|balance|expire|expire_date|imei|serial|sn|ecid|udid|device_id|challenge|sla_challenge|daa_challenge|auth_req|signature|auth_data|signed_da|sla_sig|daa_sig|download_url|file_url|ticket|status|result|server_msg)""\s*:\s*[^}\r\n]{2,240}\}|" +
        @"\b(?:username|user|email|login|password|passwd|token|access_token|session_id|hwid|license_key)\s*[=:]\s*[A-Za-z0-9_\-\.\@\$\%\+\/]{3,120})",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // 8. أوامر رفع وتحميل ونقل الملفات وتجهيز ملفات البوت واللودر والفلاش (مع حفظ تلقائي للملف!)
    private static readonly Regex FileTransferAndLoaderRegex = new(
        @"(\b(?:adb\s+(?:push|pull|sync)|sync:(?:SEND|RECV|STAT|DATA|DONE)|scp\s+[^\r\n\x00""]{4,140}|sftp\s+[^\r\n\x00""]{4,140}|curl\s+[^\r\n\x00""]{5,160}|wget\s+[^\r\n\x00""]{5,160}|Invoke-WebRequest\s+[^\r\n\x00""]{5,160}|Start-BitsTransfer\s+[^\r\n\x00""]{5,160}|ideviceinstaller(?:\.exe)?\s+-[iIuU]\s+[^\r\n\x00""]{3,140})\b|" +
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
        @"(\b(?:BSL_CMD_[A-Za-z0-9_]{3,40}|spd_dump(?:\.exe)?\s+[^\r\n\x00""]{3,140}|FDL1|FDL2|LOKE_[A-Za-z0-9_]{2,30}|ODIN_[^\r\n\x00""]{2,50})\b|" +
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
                if (DiscoveryMode == L24DiscoveryMode.ExecutedOnly)
                {
                    await Task.Delay(900, token).ConfigureAwait(false);
                    continue;
                }

                foreach (var kvp in _childAdbPids)
                {
                    if (token.IsCancellationRequested) break;
                    try
                    {
                        using var proc = Process.GetProcessById(kvp.Key);
                        if (!proc.HasExited)
                            ScanProcessHeapAndBuffers(kvp.Key, kvp.Value, token);
                    }
                    catch
                    {
                        _childAdbPids.TryRemove(kvp.Key, out _);
                    }
                }

                _parentScanCycleCounter++;
                bool shouldScanParents = !_isWinUsbOrChildAdbActive || (_parentScanCycleCounter % 2 == 1);
                if (shouldScanParents)
                {
                    foreach (var target in _monitoredPids)
                    {
                        if (token.IsCancellationRequested) break;
                        try
                        {
                            using var proc = Process.GetProcessById(target.Key);
                            if (!proc.HasExited)
                                ScanProcessHeapAndBuffers(target.Key, target.Value, token);
                        }
                        catch
                        {
                            _monitoredPids.TryRemove(target.Key, out _);
                        }
                    }
                }

                await Task.Delay(900, token).ConfigureAwait(false);
            }
        }, token);
    }

    private void ScanProcessHeapAndBuffers(int pid, string processName, CancellationToken token)
    {
        if (pid <= 0 || DiscoveryMode == L24DiscoveryMode.ExecutedOnly) return;
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
                    bool isScannable = mbi.State == MEM_COMMIT &&
                                       (mbi.Protect & PAGE_GUARD) == 0 &&
                                       prot != PAGE_NOACCESS &&
                                       (prot == PAGE_READWRITE || prot == PAGE_EXECUTE_READWRITE ||
                                        prot == PAGE_EXECUTE_READ || prot == PAGE_WRITECOPY || prot == PAGE_READONLY);

                    long regionSize = mbi.RegionSize.ToInt64();
                    if (isScannable && regionSize > 0 && regionSize <= 64 * 1024 * 1024)
                    {
                        long offset = 0;
                        while (offset < regionSize && !token.IsCancellationRequested)
                        {
                            int toRead = (int)Math.Min(chunkSize + overlap, regionSize - offset);
                            if (ReadProcessMemory(hProc, (IntPtr)(currentAddr + offset), buffer, toRead, out int bytesRead) && bytesRead > 0)
                            {
                                InspectBinaryAndTextBuffer(pid, processName, currentAddr + offset, buffer, bytesRead);
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

    private void InspectBinaryAndTextBuffer(int pid, string processName, long memAddress, byte[] buffer, int length)
    {
        InspectRawBinarySignatures(pid, processName, memAddress, buffer, length);
        ScanStringContent(pid, processName, memAddress, Encoding.UTF8.GetString(buffer, 0, length));
        ScanStringContent(pid, processName, memAddress, Encoding.Unicode.GetString(buffer, 0, length));
    }

    public void InspectBufferForTesting(int pid, string processName, long memAddress, byte[] buffer, int length)
    {
        InspectBinaryAndTextBuffer(pid, processName, memAddress, buffer, length);
    }

    private void InspectRawBinarySignatures(int pid, string processName, long memAddress, byte[] buf, int len)
    {
        for (int i = 0; i < len - 16; i++)
        {
            // 1. حزمة بروتوكول MediaTek XFlash / DA2 الثنائية (EF EE EE FE)
            if (buf[i] == 0xEF && buf[i + 1] == 0xEE && buf[i + 2] == 0xEE && buf[i + 3] == 0xFE)
            {
                int cmdId = BitConverter.ToInt32(buf, i + 4);
                int dataLen = BitConverter.ToInt32(buf, i + 8);
                if (cmdId > 0 && cmdId < 0x100000 && dataLen >= 0 && dataLen <= 0x400000)
                {
                    int snapLen = Math.Min(32, len - i);
                    string hex = Convert.ToHexString(buf.AsSpan(i, snapLen));
                    EmitDiscovered(pid, processName, memAddress + i, SentinelStage.RawCommandExecution,
                        "MTK XFlash / DA Binary Packet",
                        $"حزمة أمر MediaTek DA/XFlash ثنائية [CmdID: 0x{cmdId:X4}, الطول: {dataLen} بايت]",
                        hex, "MTK USB/VCOM Stream", isAlreadyHex: true);
                }
            }

            // 2. مصافحة MediaTek BROM الكاملة (A0 0A 50 05)
            if (buf[i] == 0xA0 && buf[i + 1] == 0x0A && buf[i + 2] == 0x50 && buf[i + 3] == 0x05)
            {
                byte nextByte = i + 4 < len ? buf[i + 4] : (byte)0;
                if (nextByte is >= 0xC1 and <= 0xDF or 0xA0 or 0x5F)
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
            if (buf[i] == 'C' && buf[i + 1] == 'F' && buf[i + 2] == 'A' && buf[i + 3] == '6' &&
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

    private void ScanStringContent(int pid, string processName, long memAddress, string text)
    {
        var mode = DiscoveryMode;
        if (mode == L24DiscoveryMode.ExecutedOnly) return;

        // 1. أوامر المودم AT وردود الهاتف وأوامر RIL IPC الهيكس
        foreach (Match m in StrictAtCommandRegex.Matches(text))
        {
            string val = CleanToken(m.Value);
            if (val.Length < 2 || TruncatedAtPrefixes.Contains(val)) continue;

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

        // 2. أوامر وبروتوكولات وسجلات تنفيذ MediaTek
        foreach (Match m in MtkProtocolRegex.Matches(text))
        {
            string val = CleanToken(m.Value);
            if (val.Length < 5 || !IsCleanRamString(val)) continue;

            EmitDiscovered(pid, processName, memAddress + m.Index, SentinelStage.RawCommandExecution,
                "MediaTek BROM / DA Command",
                $"🔶 أمر/عملية MediaTek مكتشفة في ذاكرة الأداة: {val}",
                val, "MTK Preloader / DA Engine");
        }

        // 3. أوامر ADB و Fastboot و Shell
        foreach (Match m in DeepAdbAndShellRegex.Matches(text))
        {
            string val = CleanToken(m.Value, allowNewLines: true);
            if (val.Length < 4 || !IsCleanRamString(val)) continue;

            EmitDiscovered(pid, processName, memAddress + m.Index, SentinelStage.RawCommandExecution,
                "ADB / Fastboot / Shell Command",
                $"🤖 أمر ADB/Fastboot/Shell مكتشف في ذاكرة الأداة: {val}",
                val, "ADB / Fastboot Engine");
        }

        // 4. أوامر كوالكوم و EDL الموسعة
        foreach (Match m in QualcommCommandRegex.Matches(text))
        {
            bool isXml = m.Value.StartsWith("<", StringComparison.Ordinal);
            string val = CleanToken(m.Value, allowNewLines: isXml);
            if (val.Length < 6 || !IsCleanRamString(val)) continue;

            bool isResp = val.StartsWith("<response", StringComparison.OrdinalIgnoreCase);
            if (isResp && !ForensicNoiseGate.ShowPhoneResponses) continue;

            string cat = isResp ? "Firehose Device Response" : "Qualcomm EDL / Sahara / Firehose Command";
            EmitDiscovered(pid, processName, memAddress + m.Index, SentinelStage.RawCommandExecution,
                cat, $"🔷 أمر/عملية كوالكوم EDL مكتشفة في ذاكرة الأداة: {val}", val, "Qualcomm EDL 9008 / DIAG");
        }

        // 5. أوامر وبروتوكولات Apple iOS (الأطوار الـ 7)
        foreach (Match m in AppleIosRamRegex.Matches(text))
        {
            string val = CleanToken(m.Value, allowNewLines: true);
            if (val.Length < 4 || !IsCleanRamString(val)) continue;

            EmitDiscovered(pid, processName, memAddress + m.Index, SentinelStage.RawCommandExecution,
                "Apple iOS / Lockdown / DFU / Pongo Command",
                $"🍎 أمر/بروتوكول Apple iOS مكتشف في الذاكرة: {val}",
                val, "Apple USB / Lockdown / DFU Engine");
        }

        if (mode == L24DiscoveryMode.PhoneCommandsInRam)
            return;

        // 6. الروابط واستدعاءات الملفات السحابية من الخوادم (URLs & Cloud Files)
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
                val.Contains("verisign.com", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

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

        // 7. عمليات تسجيل الدخول والمصادقة والحسابات والبيانات المرسلة/المستلمة للخوادم
        foreach (Match m in LoginAndServerAuthRegex.Matches(text))
        {
            string val = CleanToken(m.Value, allowNewLines: true, preserveUrlChars: true);
            if (val.Length < 10 || !IsCleanRamString(val)) continue;

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

        // 8. أوامر رفع وتحميل ونقل الملفات وتجهيز اللودرات (مع محاولة حفظ الملف تلقائياً عبر L24FileArchiver!)
        foreach (Match m in FileTransferAndLoaderRegex.Matches(text))
        {
            string val = CleanToken(m.Value);
            if (val.Length < 6 || !IsCleanRamString(val)) continue;
            if (val.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) || val.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) continue;

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

        // 9. أوامر فتح الضغط والضغط وتفكيك الصور
        foreach (Match m in ArchiveAndUnpackCommandRegex.Matches(text))
        {
            string val = CleanToken(m.Value);
            if (val.Length < 6 || !IsCleanRamString(val)) continue;

            EmitDiscovered(pid, processName, memAddress + m.Index, SentinelStage.RawCommandExecution,
                "Archive / Unpack Command",
                $"📦 أمر فك ضغط/تفكيك صور مكتشف في الذاكرة: {val}",
                val, "Archive / Image Unpacker");
        }

        // 10. أوامر التشفير وفك التشفير والمفاتيح والبذور الأمنية
        foreach (Match m in CryptoAndDecryptionCommandRegex.Matches(text))
        {
            string val = CleanToken(m.Value);
            if (val.Length < 6 || !IsCleanRamString(val)) continue;

            EmitDiscovered(pid, processName, memAddress + m.Index, SentinelStage.RawCommandExecution,
                "Encryption / Decryption / Security Seed",
                $"🔐 عملية تشفير/فك تشفير أو بذرة أمنية مكتشفة في الذاكرة: {val}",
                val, "Crypto / Security Engine");
        }

        // 11. بروتوكولات Odin / Unisoc SPD / المسارات الحساسة / أوامر أخرى
        foreach (Match m in OdinSpdAndOtherRegex.Matches(text))
        {
            string val = CleanToken(m.Value);
            if (val.Length < 6 || !IsCleanRamString(val)) continue;

            EmitDiscovered(pid, processName, memAddress + m.Index, SentinelStage.RawCommandExecution,
                "Other Discovered Command",
                $"🧩 أمر/مسار مكتشف في ذاكرة الأداة: {val}",
                val, "General Tool Command");
        }
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
        _isWinUsbOrChildAdbActive = false;
    }

    public void Dispose() => StopHunting();
}
