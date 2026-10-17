using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
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
    private readonly ConcurrentDictionary<string, DateTime> _seenPayloads = new(StringComparer.OrdinalIgnoreCase);
    public event Action<SourceTelemetryEvent>? OnCommandCaptured;

    // === الوضع المزدوج المتوافق مع فلتر WinUSB / ADB / MTK ===
    // يمسح عمليات adb.exe الفرعية مع الاستمرار في مسح خفيف للعملية الأم لالتقاط أوامر MTK والمودم والبورتات
    private volatile bool _isWinUsbOrChildAdbActive;
    private int _parentScanCycleCounter;
    private readonly ConcurrentDictionary<int, string> _childAdbPids = new();

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
    private const uint PAGE_READWRITE = 0x04;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;

    private static readonly HashSet<string> TruncatedAtPrefixes = new(StringComparer.OrdinalIgnoreCase)
    {
        "AT+CGM", "AT+CIM", "AT+CNM", "AT+CFU", "AT+CSC",
        "AT+CIMP", "AT+CHU", "AT+CMG", "AT+CPB", "AT+DEVCO"
    };

    // 1. أوامر المودم الصريحة (AT+, AT*, AT^, AT%, AT$, AT#, ATE, ATI, ATZ) + ردود الهاتف + أوامر RIL IPC الهيكس
    private static readonly Regex StrictAtCommandRegex = new(
        @"(?:\bAT[\+\*\^\%\$\#][A-Z0-9_]{2,28}(?:=[0-9A-Za-z,""\-\.\?\/\:]{1,120}|\?)?|" +
        @"\b(?:ATE0|ATE1|ATI|ATZ|AT&F|AT&W)\b|" +
        @"\+DEVCONINFO:\s*[^\r\n\x00]{4,220}|" +
        @"\+(?:CGMI|CGMM|CGMR|CGSN|CIMI|CPIN|CNUM|CLCK|IMEITEST|IMEISIGN|MSLSECUR|AKSEEDNO|VERSNAME|RFBYCODE):\s*[^\r\n\x00]{2,140}|" +
        @"\b(?:060100[0-9A-Fa-f]{6,64}|120[dD]00[0-9A-Fa-f]{10,128}|514200[0-9A-Fa-f]{4,64}|516400[0-9A-Fa-f]{6,64})\b)",
        RegexOptions.Compiled);

    // 2. أوامر وبروتوكولات MediaTek (BROM / Preloader / DA / XFlash / Partition Operations)
    private static readonly Regex MtkProtocolRegex = new(
        @"(\b(?:MTK_DOWNLOAD_AGENT|MTK_BLOADER_INFO|MTK_AllInOne_DA|DA_PL_CRYPTO|Brom_[A-Za-z0-9_]{3,40}|DA_[A-Za-z0-9_]{3,40}|SLA_Challenge|DAA_Challenge|Send_DA|Jump_DA|CMD_Download_DA|CMD_Read16|CMD_Write16|CMD_Read32|CMD_Write32|CMD_GetHwCode|CMD_GetTargetConfig|XFLASH_[A-Za-z0-9_]{3,40}|EMMC_BOOT|UFS_BOOT|ERASE_FRP|UNLOCK_BL)\b|" +
        @"\b(?:preloader_[a-zA-Z0-9_]{2,40}\.bin|MT[0-9]{4}_Android_scatter\.txt|auth_sv5\.auth|DA_SWSEC[A-Za-z0-9_\.]*\.bin)\b|" +
        @"\b(?:erase|read|write|format|dump|flash|wipe)\s+(?:nvram|nvdata|proinfo|protect1|protect2|seccfg|lk|lk2|boot|para|misc|recovery|userdata|frp|persistent|md1img|super|vbmeta)\b[^\r\n\x00]{0,60})",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // 3. ملفات البوت واللودر واستخراج الملفات
    private static readonly Regex BootLoaderAndFileOpsRegex = new(
        @"((?<![a-zA-Z0-9_])([a-zA-Z0-9_\-\./\\]{2,120}\.(?:tar|7z|bin|mbn|elf|img|pit|ops|ofp|pac|qcn))(?![a-zA-Z0-9_])|" +
        @"\b(?:prog_emmc_firehose|prog_ufs_firehose|rawprogram[0-9]|patch[0-9]|gpt_main[0-9]|gpt_backup[0-9])[A-Za-z0-9_\-\.]*\.(?:mbn|elf|xml|bin)\b|" +
        @"\b(?:unzip|lz4|simg2img|img2simg)\s+[^\r\n\x00]{3,100})",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // 4. جميع أطوار ADB و Shell (Wire Protocol + Interactive $ / # + Heredoc << + Linux Commands + /data/local/tmp/AT)
    private static readonly Regex DeepAdbAndShellRegex = new(
        @"((?:shell|host|sync|usb|reboot|remount|reverse|tcp|localabstract|abb|abb_exec):[A-Za-z0-9_\-\s\.\/,\=\$\#\|\<\>\&\;""'\+]{1,220}|" +
        @"(?:^|[\r\n])\s*(?:[\$\#]\s*)?(?:su\s+-c|getprop|setprop|service\s+call|logcat\s+|dumpsys\s+|pm\s+(?:uninstall|install|clear|grant|revoke|disable|disable-user|enable|list|path)|am\s+(?:start|broadcast|force-stop|startservice)|dd\s+if=|mount\s+-o|chmod\s+[0-7]{3,4}|chown\s+|rm\s+-rf|cat\s+|echo\s+|sh\s+|busybox\s+|toybox\s+|/data/local/tmp/AT)[^\r\n\x00]{0,200}|" +
        @"[A-Za-z0-9_\-\.\/]+\s*<<-?\s*['""]?[A-Za-z0-9_]+['""]?[\s\S]{1,240}|" +
        @"(?:echo|cat)\s+[^\r\n\x00]{1,100}\s*>>?\s*\/(?:dev|data|sdcard|system|efs|vendor)\/[A-Za-z0-9_\-\.\/]+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // 5. أوامر Fastboot و Qualcomm Firehose XML و QMSL
    private static readonly Regex ExecutionCommandRegex = new(
        @"(\b(?:adb|fastboot)\s+(?:shell|push|pull|install|reboot|flash|flashing|oem|getvar|erase|boot|devices|forward)\b[A-Za-z0-9_\-\s\.\/\:]{0,120}|" +
        @"\bQLIB_[A-Za-z0-9_]{5,60}\b|" +
        @"<\?xml[\s\S]{10,350}?(?:</data>|</FUSMsg>)|" +
        @"<response\s+value=""(?:ACK|NAK)""[^>]{0,150}/>)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // 6. المصيدة الاستدلالية للمسارات داخل الهاتف
    private static readonly Regex HeuristicPhonePathRegex = new(
        @"(\/(?:data\/local\/tmp|dev\/block\/bootdevice\/by-name|dev\/block\/platform|dev\/smd|dev\/ttyUSB|dev\/ttyACM|dev\/at_mdm|dev\/umts_ipc|efs|nvdata|persist|sdcard\/Download)\/[A-Za-z0-9_\-\.\/]{1,80})",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // 7. مسارات الأجهزة الفيزيائية المتصلة فعلياً ومنافذ COM
    private static readonly Regex ActiveDevicePathRegex = new(
        @"(\\\\\?\\(?:usb|USB)#VID_[0-9A-Fa-f]{4}&PID_[0-9A-Fa-f]{4}#[^\s""\x00-\x1F\<\>]{4,110}|\\\\\.\\COM\d+\b|\bCOM\d{1,3}\b)",
        RegexOptions.Compiled);

    public void StartHunting(int targetPid, string processName)
    {
        _cts?.Cancel();
        _cts = new CancellationTokenSource();
        var token = _cts.Token;

        Task.Run(async () =>
        {
            while (!token.IsCancellationRequested)
            {
                if (_isWinUsbOrChildAdbActive)
                {
                    // 1. مسح مستمر للعمليات الفرعية (adb.exe / fastboot.exe)
                    foreach (var kvp in _childAdbPids)
                    {
                        if (token.IsCancellationRequested) break;
                        try
                        {
                            using var proc = Process.GetProcessById(kvp.Key);
                            if (!proc.HasExited)
                            {
                                ScanProcessHeapAndBuffers(kvp.Key, kvp.Value, token);
                            }
                        }
                        catch
                        {
                            _childAdbPids.TryRemove(kvp.Key, out _);
                        }
                    }

                    // 2. الاستمرار بمسح العملية الأم كل دورة ثانية لالتقاط أوامر MTK والمودم والبورتات المباشرة دون إبطاء WinUSB
                    _parentScanCycleCounter++;
                    if (_parentScanCycleCounter % 2 == 1)
                    {
                        ScanProcessHeapAndBuffers(targetPid, processName, token);
                    }
                }
                else
                {
                    ScanProcessHeapAndBuffers(targetPid, processName, token);
                }

                await Task.Delay(850, token);
            }
        }, token);
    }

    private void ScanProcessHeapAndBuffers(int pid, string processName, CancellationToken token)
    {
        if (pid <= 0) return;
        IntPtr hProc = IntPtr.Zero;
        try
        {
            hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
            if (hProc == IntPtr.Zero) return;

            long currentAddr = 0x10000;
            long maxAddr = 0x7FFF0000;
            uint mbiSize = (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();
            byte[] buffer = ArrayPool<byte>.Shared.Rent(65536);

            try
            {
                while (currentAddr < maxAddr && !token.IsCancellationRequested)
                {
                    if (VirtualQueryEx(hProc, (IntPtr)currentAddr, out var mbi, mbiSize) == 0)
                        break;

                    bool isReadableWritable = mbi.State == MEM_COMMIT &&
                        (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_EXECUTE_READWRITE);

                    long regionSize = mbi.RegionSize.ToInt64();
                    if (isReadableWritable && regionSize > 0 && regionSize <= 16 * 1024 * 1024)
                    {
                        long offset = 0;
                        while (offset < regionSize && !token.IsCancellationRequested)
                        {
                            int toRead = (int)Math.Min(buffer.Length, regionSize - offset);
                            if (ReadProcessMemory(hProc, (IntPtr)(currentAddr + offset), buffer, toRead, out int bytesRead) && bytesRead > 0)
                            {
                                InspectBinaryAndTextBuffer(pid, processName, currentAddr + offset, buffer, bytesRead);
                            }
                            offset += toRead;
                        }
                    }

                    currentAddr = mbi.BaseAddress.ToInt64() + Math.Max(regionSize, 4096);
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
        ScanStringContent(pid, processName, memAddress, Encoding.ASCII.GetString(buffer, 0, length));
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
            // 1. كشف حزمة بروتوكول MediaTek XFlash / DA2 الثنائية (تبدأ بـ EF EE EE FE)
            if (buf[i] == 0xEF && buf[i + 1] == 0xEE && buf[i + 2] == 0xEE && buf[i + 3] == 0xFE)
            {
                int cmdId = BitConverter.ToInt32(buf, i + 4);
                int dataLen = BitConverter.ToInt32(buf, i + 8);
                if (cmdId > 0 && cmdId < 0x100000 && dataLen >= 0 && dataLen <= 0x400000)
                {
                    int snapLen = Math.Min(32, len - i);
                    string hex = Convert.ToHexString(buf.AsSpan(i, snapLen));
                    EmitUnique(pid, processName, memAddress + i, SentinelStage.RawCommandExecution,
                        "MTK XFlash / DA Binary Packet",
                        $"حزمة أمر MediaTek DA/XFlash ثنائية [CmdID: 0x{cmdId:X4}, الطول: {dataLen} بايت]",
                        hex, "MTK USB/VCOM Stream", isAlreadyHex: true);
                }
            }

            // 2. كشف مصافحة MediaTek BROM الكاملة (A0 0A 50 05) متبوعة بأمر BROM (D0..DF أو C1..C7)
            if (buf[i] == 0xA0 && buf[i + 1] == 0x0A && buf[i + 2] == 0x50 && buf[i + 3] == 0x05)
            {
                byte nextByte = i + 4 < len ? buf[i + 4] : (byte)0;
                if (nextByte is >= 0xC1 and <= 0xDF or 0xA0 or 0x5F)
                {
                    int snapLen = Math.Min(16, len - i);
                    string hex = Convert.ToHexString(buf.AsSpan(i, snapLen));
                    EmitUnique(pid, processName, memAddress + i, SentinelStage.RawCommandExecution,
                        "MTK BROM Handshake",
                        $"مصافحة وأمر معالج MediaTek BROM المباشر [Sync: A0 0A 50 05, NextOp: 0x{nextByte:X2}]",
                        hex, "MTK BROM Port", isAlreadyHex: true);
                }
            }

            // 3. كشف حزمة ADB Wire Protocol المباشرة (CNXN / OPEN / WRTE) التي تمر عبر AdbWinApi.dll
            if ((buf[i] == 'O' && buf[i + 1] == 'P' && buf[i + 2] == 'E' && buf[i + 3] == 'N') ||
                (buf[i] == 'W' && buf[i + 1] == 'R' && buf[i + 2] == 'T' && buf[i + 3] == 'E'))
            {
                uint cmd = BitConverter.ToUInt32(buf, i);
                int dataLen = BitConverter.ToInt32(buf, i + 12);
                uint magic = BitConverter.ToUInt32(buf, i + 20);
                // التحقق من صحة ترويسة ADB أو وجود حمولة منطقية
                bool validMagic = (cmd ^ 0xFFFFFFFF) == magic || magic == 0;
                if (validMagic && dataLen > 2 && dataLen <= 512 && i + 24 + dataLen <= len)
                {
                    string adbPayload = CleanControlChars(Encoding.ASCII.GetString(buf, i + 24, dataLen), allowNewLines: true);
                    if (adbPayload.Length >= 3 && WinUsbFilterAdbBridge.IsCleanPrintableOrHexCommand(adbPayload))
                    {
                        string packetType = Encoding.ASCII.GetString(buf, i, 4);
                        EmitUnique(pid, processName, memAddress + i, SentinelStage.RawCommandExecution,
                            $"ADB Wire [{packetType}] Packet",
                            $"أمر ADB سلكي مباشر عبر AdbWinApi [{packetType}]: {adbPayload}",
                            adbPayload, "AdbWinUsb Endpoint");
                    }
                }
            }
        }
    }

    private static string CleanControlChars(string input, bool allowNewLines = false)
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
        return sb.ToString().Trim();
    }

    private static bool IsCleanRamString(string value)
    {
        foreach (char c in value)
        {
            if (c == '?') return false;
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

    private void ScanStringContent(int pid, string processName, long memAddress, string text)
    {
        // 1. أوامر المودم AT وردود الهاتف وأوامر RIL IPC الهيكس
        foreach (Match m in StrictAtCommandRegex.Matches(text))
        {
            string val = CleanControlChars(m.Value);
            if (val.Length < 2 || TruncatedAtPrefixes.Contains(val)) continue;
            if (val.Contains('?') && !val.EndsWith("=?") && !val.EndsWith("?")) continue;

            bool isRilHex = val.StartsWith("060100", StringComparison.OrdinalIgnoreCase) ||
                            val.StartsWith("120D00", StringComparison.OrdinalIgnoreCase) ||
                            val.StartsWith("514200", StringComparison.OrdinalIgnoreCase) ||
                            val.StartsWith("516400", StringComparison.OrdinalIgnoreCase);

            bool isReply = val.StartsWith("+");
            string cat = isRilHex ? "ADB RIL / AT IPC Command" : (isReply ? "Modem Phone Response" : "Modem AT Command");
            string desc = isRilHex
                ? $"أمر RIL/AT هيكس ممرر عبر أداة الهاتف: {val}"
                : (isReply ? $"رد الهاتف الفعلي على أمر المودم: {val}" : $"أمر مودم صريح صادر من الأداة: {val}");

            EmitUnique(pid, processName, memAddress, SentinelStage.RawCommandExecution,
                cat, desc, val, isRilHex ? "/data/local/tmp/AT" : "Active Modem Buffer");
        }

        // 2. أوامر وبروتوكولات MediaTek (BROM / DA / Partition Commands)
        foreach (Match m in MtkProtocolRegex.Matches(text))
        {
            string val = CleanControlChars(m.Value);
            if (val.Length < 5) continue;
            if (!IsCleanRamString(val)) continue;

            EmitUnique(pid, processName, memAddress, SentinelStage.RawCommandExecution,
                "MediaTek BROM / DA Command",
                $"أمر/بروتوكول MediaTek مكتشف في ذاكرة الأداة: {val}",
                val, "MTK Preloader / DA Engine");
        }

        // 3. ملفات البوت واللودر واستخراج الملفات
        foreach (Match m in BootLoaderAndFileOpsRegex.Matches(text))
        {
            string val = CleanControlChars(m.Value);
            if (val.Length < 6) continue;
            if (val.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) || val.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) continue;
            if (!IsCleanRamString(val)) continue;

            EmitUnique(pid, processName, memAddress, SentinelStage.LocalFilePreparation,
                "Boot Loader / DA / Firmware File",
                $"استدعاء/تجهيز ملف بوت أو لودر أو عملية استخراج: {val}",
                val, val);
        }

        // 4. جميع أساليب ADB و Shell ($ / # / << Heredoc / Direct Shell)
        foreach (Match m in DeepAdbAndShellRegex.Matches(text))
        {
            string val = CleanControlChars(m.Value, allowNewLines: true);
            if (val.Length < 4) continue;
            if (!IsCleanRamString(val)) continue;

            bool isHeredoc = val.Contains("<<") || val.Contains(">>");
            EmitUnique(pid, processName, memAddress, SentinelStage.RawCommandExecution,
                isHeredoc ? "Shell Script / Heredoc Injection (<<)" : "ADB / Interactive Shell Command ($/#)",
                isHeredoc ? $"تمرير سكربت أو توجيه ملف أوامر للهاتف (<< / >>): {val}" : $"أمر شل/ADB مباشر منفذ على الهاتف: {val}",
                val, "ADB / Shell Pipe");
        }

        // 5. أوامر Fastboot و Firehose XML و QMSL
        foreach (Match m in ExecutionCommandRegex.Matches(text))
        {
            bool isXml = m.Value.StartsWith("<", StringComparison.Ordinal);
            string val = CleanControlChars(m.Value, allowNewLines: isXml);
            if (val.Length < 10) continue;

            string category = isXml
                ? (val.StartsWith("<response", StringComparison.OrdinalIgnoreCase) ? "Firehose Device Response" : "Qualcomm Firehose / Samsung FUS XML")
                : val.StartsWith("QLIB_", StringComparison.OrdinalIgnoreCase)
                    ? "Qualcomm QMSL DIAG API"
                    : "Verified Execution Command";

            EmitUnique(pid, processName, memAddress, SentinelStage.RawCommandExecution,
                category, $"أمر تنفيذي مكتشف في ذاكرة الأداة: {val}", val, "Command Execution Buffer");
        }

        // 6. المصيدة الاستدلالية لمسارات الهاتف
        foreach (Match m in HeuristicPhonePathRegex.Matches(text))
        {
            string val = CleanControlChars(m.Value);
            if (val.Length < 8) continue;
            if (!IsCleanRamString(val)) continue;

            EmitUnique(pid, processName, memAddress, SentinelStage.RawCommandExecution,
                "Heuristic Phone Path / Partition Target",
                $"رصد تعامل مع مسار داخلي حساس في الهاتف: {val}",
                val, val);
        }

        // 7. مسارات USB الفيزيائية ومنافذ COM
        foreach (Match m in ActiveDevicePathRegex.Matches(text))
        {
            string val = CleanControlChars(m.Value);
            if (val.Length < 4) continue;

            bool isComPort = val.StartsWith(@"\\.\COM", StringComparison.OrdinalIgnoreCase) ||
                             val.StartsWith("COM", StringComparison.OrdinalIgnoreCase);
            EmitUnique(pid, processName, memAddress,
                isComPort ? SentinelStage.PortConfiguration : SentinelStage.PortAndDeviceRadar,
                isComPort ? "Serial COM Port Target" : "Connected USB Device Path",
                isComPort ? $"الأداة تتعامل مباشرة مع المنفذ التسلسلي: {val}" : $"رادار الأداة يتعامل مع جهاز USB متصل فعلياً: {val}",
                val, val);
        }
    }

    private void EmitUnique(int pid, string processName, long memAddress, SentinelStage stage, string category, string desc, string rawValue, string targetRes, bool isAlreadyHex = false)
    {
        string key = $"{pid}:{category}:{rawValue}";
        DateTime now = DateTime.UtcNow;
        if (_seenPayloads.TryGetValue(key, out var lastSeen) && (now - lastSeen).TotalSeconds < 3.0)
            return;
        _seenPayloads[key] = now;

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
            RawPayloadHex = isAlreadyHex ? rawValue : Convert.ToHexString(rawBytes),
            PayloadSize = rawBytes.Length
        });
    }

    public void Dispose() => _cts?.Cancel();
}
