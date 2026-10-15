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
    private readonly ConcurrentDictionary<string, bool> _seenPayloads = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<int, int> _staticVidPidCounter = new();
    public event Action<SourceTelemetryEvent>? OnCommandCaptured;

    // === الوضع المتوافق مع فلتر WinUSB / ADB (Filter-Friendly Passive Mode) ===
    // عند تفعيله، يتوقف المسح المتكرر عن العملية الأم المحمية ويحوّل المسح لعملية adb.exe الفرعية فقط
    private volatile bool _isWinUsbOrChildAdbActive;
    private volatile bool _initialParentScanDone;
    private readonly ConcurrentDictionary<int, string> _childAdbPids = new();

    /// <summary>
    /// خاصية تفعيل الوضع المتوافق مع فلتر WinUSB / ADB.
    /// عند تفعيلها، يتوقف المسح المتكرر للذاكرة عن العملية الأم المحمية (مرة واحدة فقط عند الإقلاع)
    /// ويحوّل المسح إلى عمليات adb.exe الفرعية فقط لترك أوامر الأداة تمر عبر WinUSB بحرية.
    /// </summary>
    public bool IsWinUsbOrChildAdbActive
    {
        get => _isWinUsbOrChildAdbActive;
        set => _isWinUsbOrChildAdbActive = value;
    }

    /// <summary>
    /// تسجيل عملية adb.exe فرعية لمسح ذاكرتها بدلاً من العملية الأم المحمية.
    /// </summary>
    public void RegisterChildAdbProcess(int childPid, string processName)
    {
        _childAdbPids[childPid] = processName;
        _isWinUsbOrChildAdbActive = true;
    }

    // === أفعال الشل الصريحة المسموح بها لفلترة سلاسل "<<" ===
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

    // قائمة استبعاد البادئات المقطوعة التي ظهرت في السجل السابق
    private static readonly HashSet<string> TruncatedAtPrefixes = new(StringComparer.OrdinalIgnoreCase)
    {
        "AT+CGM", "AT+CIM", "AT+CNM", "AT+CFU", "AT+CSC",
        "AT+CIMP", "AT+CHU", "AT+CMG", "AT+CPB", "AT+DEVCO"
    };

    // 1. أوامر المودم الصريحة + ردود الهاتف
    private static readonly Regex StrictAtCommandRegex = new(
        @"(?:\bAT\+[A-Z0-9_]{3,24}(?:=[0-9A-Za-z,""\-\.\?]{1,60}|\?)?|" +
        @"\+DEVCONINFO:\s*[^\r\n\x00]{4,220}|" +
        @"\+(?:CGMI|CGMM|CGMR|CGSN|CIMI|CPIN|CNUM):\s*[^\r\n\x00]{2,120}|" +
        @"\bAT\$(?:QCDMG|QCPWRDN)\b)",
        RegexOptions.Compiled);

    // 2. أوامر وبروتوكولات MediaTek (BROM / Preloader / DA / XFlash / Partition Operations)
    private static readonly Regex MtkProtocolRegex = new(
        @"(\b(?:MTK_DOWNLOAD_AGENT|MTK_BLOADER_INFO|MTK_AllInOne_DA|DA_PL_CRYPTO|Brom_[A-Za-z0-9_]{3,40}|DA_[A-Za-z0-9_]{3,40}|SLA_Challenge|Send_DA|Jump_DA|CMD_Download_DA|CMD_Read16|CMD_Write16|XFLASH_[A-Za-z0-9_]{3,40})\b|" +
        @"\b(?:preloader_[a-zA-Z0-9_]{2,40}\.bin|MT[0-9]{4}_Android_scatter\.txt|auth_sv5\.auth)\b|" +
        @"\b(?:erase|read|write|format)\s+(?:nvram|nvdata|proinfo|protect1|protect2|seccfg|lk|boot|recovery|userdata|frp|persistent)\b[^\r\n\x00]{0,60})",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // 3. ملفات البوت واللودر واستخراج الملفات (DA / Firehose / Programmer / Scatter / Archive Extraction)
    // فلترة: يشترط وجود اسم ملف ينتهي بامتداد صريح مسبوق بنقطة لمنع التقاط كلمات tar أو 7z المجردة
    private static readonly Regex BootLoaderAndFileOpsRegex = new(
        @"((?<![a-zA-Z0-9_])([a-zA-Z0-9_\-\./\\]{2,120}\.(?:tar|7z|bin|mbn|elf|img|pit|ops|ofp|pac|qcn))(?![a-zA-Z0-9_])|" +
        @"\b(?:prog_emmc_firehose|prog_ufs_firehose|rawprogram[0-9]|patch[0-9]|gpt_main[0-9]|gpt_backup[0-9])[A-Za-z0-9_\-\.]*\.(?:mbn|elf|xml|bin)\b|" +
        @"\b(?:unzip|lz4|simg2img|img2simg)\s+[^\r\n\x00]{3,100})",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // 4. جميع أطوار ADB و Shell (Wire Protocol + Interactive $ / # + Heredoc << + Linux Commands)
    private static readonly Regex DeepAdbAndShellRegex = new(
        @"((?:shell|host|sync):[A-Za-z0-9_\-\s\.\/,\=\$\#\|\<\>\&\;""'\+]{2,160}|" +
        @"(?:^|[\r\n])\s*(?:[\$\#]\s*)?(?:su\s+-c|getprop|setprop|pm\s+(?:uninstall|install|clear|grant|revoke|disable|disable-user|enable)|am\s+(?:start|broadcast|force-stop)|dd\s+if=|mount\s+-o|chmod\s+[0-7]{3,4}|chown\s+|rm\s+-rf|cat\s+|echo\s+-e|sh\s+|busybox\s+|toybox\s+)[^\r\n\x00]{2,160}|" +
        @"[A-Za-z0-9_\-\.\/]+\s*<<-?\s*['""]?[A-Za-z0-9_]+['""]?[\s\S]{1,240}|" +
        @"(?:echo|cat)\s+[^\r\n\x00]{1,100}\s*>>?\s*\/(?:dev|data|sdcard|system|efs|vendor)\/[A-Za-z0-9_\-\.\/]+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // 5. أوامر Fastboot و Qualcomm Firehose XML (غير جشعة Non-Greedy لفصل كل XML على حدة) و QMSL
    private static readonly Regex ExecutionCommandRegex = new(
        @"(\b(?:adb|fastboot)\s+(?:shell|push|pull|install|reboot|flash|flashing|oem|getvar|erase|boot|devices|forward)\b[A-Za-z0-9_\-\s\.\/\:]{0,90}|" +
        @"\bQLIB_[A-Za-z0-9_]{5,60}\b|" +
        @"<\?xml[\s\S]{10,350}?(?:</data>|</FUSMsg>)|" +
        @"<response\s+value=""(?:ACK|NAK)""[^>]{0,150}/>)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // 6. المصيدة الاستدلالية للأساليب غير المتوقعة (أي تعامل مع مسارات داخل الهاتف /dev/ أو /data/local/tmp/ إلخ)
    private static readonly Regex HeuristicPhonePathRegex = new(
        @"(\/(?:data\/local\/tmp|dev\/block\/bootdevice\/by-name|dev\/block\/platform|dev\/smd|dev\/ttyUSB|dev\/at_mdm|efs|nvdata|persist|sdcard\/Download)\/[A-Za-z0-9_\-\.\/]{1,80})",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // 7. مسارات الأجهزة الفيزيائية المتصلة فعلياً ومنافذ COM
    private static readonly Regex ActiveDevicePathRegex = new(
        @"(\\\\\?\\(?:usb|USB)#VID_[0-9A-Fa-f]{4}&PID_[0-9A-Fa-f]{4}#[^\s""\x00-\x1F\<\>]{4,110}|\\\\\.\\COM\d+\b)",
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
                // === الوضع المتوافق مع فلتر WinUSB / ADB ===
                if (_isWinUsbOrChildAdbActive)
                {
                    // مسح العملية الأم المحمية مرة واحدة فقط عند الإقلاع
                    if (!_initialParentScanDone)
                    {
                        ScanProcessHeapAndBuffers(targetPid, processName, token);
                        _initialParentScanDone = true;
                    }

                    // مسح عمليات adb.exe الفرعية فقط بدلاً من العملية الأم
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
                            // العملية الفرعية انتهت، إزالتها من القائمة
                            _childAdbPids.TryRemove(kvp.Key, out _);
                        }
                    }
                }
                else
                {
                    // الوضع العادي: مسح العملية الأم مباشرة
                    ScanProcessHeapAndBuffers(targetPid, processName, token);
                }

                await Task.Delay(900, token);
            }
        }, token);
    }

    private void ScanProcessHeapAndBuffers(int pid, string processName, CancellationToken token)
    {
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
            // ضمان إغلاق مقبض العملية دائماً داخل بلوك finally
            if (hProc != IntPtr.Zero)
                CloseHandle(hProc);
        }
    }

    private void InspectBinaryAndTextBuffer(int pid, string processName, long memAddress, byte[] buffer, int length)
    {
        // أ) فحص التواقيع الثنائية الخام لبروتوكول MediaTek (XFlash / BROM / DA) وبروتوكول ADB المباشر
        InspectRawBinarySignatures(pid, processName, memAddress, buffer, length);

        // ب) فحص السلاسل النصية بترميزي ASCII و UTF-16
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

            // 2. كشف حزمة ADB Wire Protocol المباشرة (CNXN / OPEN / WRTE) التي تمر عبر AdbWinApi.dll
            if ((buf[i] == 'O' && buf[i + 1] == 'P' && buf[i + 2] == 'E' && buf[i + 3] == 'N') ||
                (buf[i] == 'W' && buf[i + 1] == 'R' && buf[i + 2] == 'T' && buf[i + 3] == 'E'))
            {
                int dataLen = BitConverter.ToInt32(buf, i + 12);
                if (dataLen > 2 && dataLen <= 512 && i + 24 + dataLen <= len)
                {
                    string adbPayload = CleanControlChars(Encoding.ASCII.GetString(buf, i + 24, dataLen), allowNewLines: true);
                    if (adbPayload.Length >= 3)
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
                break; // قص محارف التحكم مثل \u0007OnClick فوراً
        }
        return sb.ToString().Trim();
    }

    /// <summary>
    /// فلتر تنظيف الضوضاء: يتحقق من صلاحية السلسلة النصية المستخرجة من الرام.
    /// يرفض السلاسل التي تحتوي على '?' أو محارف غير قابلة للطباعة أو سلاسل "<<" غير المبررة.
    /// </summary>
    private static bool IsCleanRamString(string value)
    {
        // 1. منع السلاسل التالفة: علامة استفهام أو محارف غير قابلة للطباعة
        foreach (char c in value)
        {
            if (c == '?') return false;
            if (c < 0x20 || c > 0x7E)
            {
                // السماح بمحارف التحكم الأساسية فقط (CR/LF/TAB)
                if (c != '\r' && c != '\n' && c != '\t')
                    return false;
            }
        }

        // 2. فلترة علامة "<<": لا تقبلها إلا إذا بدأت بأحد أفعال الشل الصريحة
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
        // 1. أوامر المودم AT وردود الهاتف
        foreach (Match m in StrictAtCommandRegex.Matches(text))
        {
            string val = CleanControlChars(m.Value);
            if (val.Length < 6 || TruncatedAtPrefixes.Contains(val)) continue;
            if (val.Contains('?') && !val.EndsWith("=?")) continue;

            bool isReply = val.StartsWith("+");
            EmitUnique(pid, processName, memAddress, SentinelStage.RawCommandExecution,
                isReply ? "Modem Phone Response" : "Modem AT Command",
                isReply ? $"رد الهاتف الفعلي على أمر المودم: {val}" : $"أمر مودم صريح صادر من الأداة: {val}",
                val, "Active Modem Buffer");
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

        // 3. ملفات البوت واللودر واستخراج الملفات (DA, Firehose, Scatter, Auth, Extraction)
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
            if (val.Length < 5) continue;
            if (!IsCleanRamString(val)) continue;

            bool isHeredoc = val.Contains("<<") || val.Contains(">>");
            EmitUnique(pid, processName, memAddress, SentinelStage.RawCommandExecution,
                isHeredoc ? "Shell Script / Heredoc Injection (<<)" : "ADB / Interactive Shell Command ($/#)",
                isHeredoc ? $"تمرير سكربت أو توجيه ملف أوامر للهاتف (<< / >>): {val}" : $"أمر شل/ADB مباشر منفذ على الهاتف: {val}",
                val, "ADB / Shell Pipe");
        }

        // 5. أوامر Fastboot و Firehose XML (منفصلة وغير مدمجة) و QMSL
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

        // 6. المصيدة الاستدلالية لمسارات الهاتف غير المتوقعة
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
            if (val.Length < 7) continue;

            bool isComPort = val.StartsWith(@"\\.\COM", StringComparison.OrdinalIgnoreCase);
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
        if (_seenPayloads.TryAdd(key, true))
        {
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
    }

    public void Dispose() => _cts?.Cancel();
}
