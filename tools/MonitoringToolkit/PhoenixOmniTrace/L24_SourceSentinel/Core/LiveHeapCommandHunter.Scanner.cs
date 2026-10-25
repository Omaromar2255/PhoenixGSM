using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using PhoenixOmniTrace.L24_SourceSentinel.Models;

namespace PhoenixOmniTrace.L24_SourceSentinel.Core;

public sealed partial class LiveHeapCommandHunter
{
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

    private void InspectRawBinarySignaturesAndCarveLoaders(int pid, string processName, long memAddress, byte[] buf, int len, bool isExecutableCodeSection)
    {
        for (int i = 0; i < len - 24; i++)
        {
            // ══════════════════════════════════════════════════════════════════════
            // أولاً: صائد ملفات البوت واللودر والـ DA والـ Firehose والـ IMG4 مباشرة من الرام
            // ══════════════════════════════════════════════════════════════════════
            if (_enableInMemoryLoaderCarving && _carvedLoaderAddresses.Count < 80)
            {
                // أ) ملف MediaTek Download-Agent محمل في الرام
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

                // ب) ملف Apple IMG4 / IM4P محمل في الرام
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

            // لا نفحص التوقيعات الثنائية القصيرة داخل أقسام الكود التنفيذي لمنع الإيجابيات الكاذبة
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

            // 2. مصافحة MediaTek BROM الكاملة (A0 0A 50 05)
            if (IsGroupEnabled(L24CommandGroup.MediaTek) && buf[i] == 0xA0 && buf[i + 1] == 0x0A && buf[i + 2] == 0x50 && buf[i + 3] == 0x05)
            {
                byte nextByte = i + 4 < len ? buf[i + 4] : (byte)0;
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
            foreach (Match m in LiveHeapPatterns.StrictAtCommandRegex.Matches(text))
            {
                string val = LiveHeapPatterns.CleanToken(m.Value);
                if (val.Length < 3 || LiveHeapPatterns.TruncatedAtPrefixes.Contains(val) || LiveHeapPatterns.IsLikelyTruncatedAtFragment(val)) continue;
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
            foreach (Match m in LiveHeapPatterns.MtkProtocolRegex.Matches(text))
            {
                string val = LiveHeapPatterns.CleanToken(m.Value);
                if (val.Length < 5 || !LiveHeapPatterns.IsCleanRamString(val) || LiveHeapPatterns.IsHtmlOrUiFormatNoise(val)) continue;
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
            foreach (Match m in LiveHeapPatterns.DeepAdbAndShellRegex.Matches(text))
            {
                string val = LiveHeapPatterns.CleanToken(m.Value, allowNewLines: true);
                if (val.Length < 4 || !LiveHeapPatterns.IsCleanRamString(val) || LiveHeapPatterns.IsWindowsSetupApiRebootNoise(val)) continue;
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
            foreach (Match m in LiveHeapPatterns.QualcommCommandRegex.Matches(text))
            {
                bool isXml = m.Value.StartsWith("<", StringComparison.Ordinal);
                string val = LiveHeapPatterns.CleanToken(m.Value, allowNewLines: isXml);
                if (val.Length < 6 || !LiveHeapPatterns.IsCleanRamString(val) || (!isXml && LiveHeapPatterns.IsHtmlOrUiFormatNoise(val))) continue;
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
            foreach (Match m in LiveHeapPatterns.AppleIosRamRegex.Matches(text))
            {
                string val = LiveHeapPatterns.CleanToken(m.Value, allowNewLines: true);
                if (val.Length < 4 || !LiveHeapPatterns.IsCleanRamString(val) || LiveHeapPatterns.IsHtmlOrUiFormatNoise(val)) continue;
                if (ShouldSkipOrRecordBaseline(val, recordAsBaselineOnly)) continue;

                EmitDiscovered(pid, processName, memAddress + m.Index, SentinelStage.RawCommandExecution,
                    "Apple iOS / Lockdown / DFU / Pongo Command",
                    $"🍎 أمر/بروتوكول Apple iOS مكتشف في الذاكرة: {val}",
                    val, "Apple USB / Lockdown / DFU Engine");
            }
        }

        if (mode == L24DiscoveryMode.PhoneCommandsInRam)
            return;

        // 6. الروابط واستدعاءات الملفات السحابية من الخوادم
        if (!ExcludeUrls && IsGroupEnabled(L24CommandGroup.ServerCloudLogin))
        {
            foreach (Match m in LiveHeapPatterns.CloudAndServerUrlRegex.Matches(text))
            {
                string val = LiveHeapPatterns.CleanToken(m.Value, preserveUrlChars: true);
                if (val.Length < 10 || !LiveHeapPatterns.IsCleanRamString(val)) continue;

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

        // 7. عمليات تسجيل الدخول والمصادقة والحسابات
        if (IsGroupEnabled(L24CommandGroup.ServerCloudLogin))
        {
            foreach (Match m in LiveHeapPatterns.LoginAndServerAuthRegex.Matches(text))
            {
                string val = LiveHeapPatterns.CleanToken(m.Value, allowNewLines: true, preserveUrlChars: true);
                if (val.Length < 10 || !LiveHeapPatterns.IsCleanRamString(val)) continue;
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

        // 8. أوامر رفع وتحميل ونقل الملفات وتجهيز اللودرات
        if (IsGroupEnabled(L24CommandGroup.FileTransfer))
        {
            foreach (Match m in LiveHeapPatterns.FileTransferAndLoaderRegex.Matches(text))
            {
                string val = LiveHeapPatterns.CleanToken(m.Value);
                if (val.Length < 6 || !LiveHeapPatterns.IsCleanRamString(val) || LiveHeapPatterns.IsChilkatOrDummyFileNoise(val)) continue;
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
            foreach (Match m in LiveHeapPatterns.ArchiveAndUnpackCommandRegex.Matches(text))
            {
                string val = LiveHeapPatterns.CleanToken(m.Value);
                if (val.Length < 6 || !LiveHeapPatterns.IsCleanRamString(val)) continue;
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
            foreach (Match m in LiveHeapPatterns.CryptoAndDecryptionCommandRegex.Matches(text))
            {
                string val = LiveHeapPatterns.CleanToken(m.Value);
                if (val.Length < 6 || !LiveHeapPatterns.IsCleanRamString(val) || LiveHeapPatterns.IsChilkatOrDummyFileNoise(val)) continue;
                if (ShouldSkipOrRecordBaseline(val, recordAsBaselineOnly)) continue;

                EmitDiscovered(pid, processName, memAddress + m.Index, SentinelStage.RawCommandExecution,
                    "Encryption / Decryption / Security Seed",
                    $"🔐 عملية تشفير/فك تشفير أو بذرة أمنية مكتشفة في الذاكرة: {val}",
                    val, "Crypto / Security Engine");
            }
        }

        // 11. بروتوكولات Odin / Unisoc SPD / المسارات الحساسة
        if (IsGroupEnabled(L24CommandGroup.OtherCommands))
        {
            foreach (Match m in LiveHeapPatterns.OdinSpdAndOtherRegex.Matches(text))
            {
                string val = LiveHeapPatterns.CleanToken(m.Value);
                if (val.Length < 6 || !LiveHeapPatterns.IsCleanRamString(val)) continue;
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
}
