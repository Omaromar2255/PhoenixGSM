using System;
using System.IO;
using System.Text.RegularExpressions;
using PhoenixOmniTrace.L24_SourceSentinel.Models;

namespace PhoenixOmniTrace.L24_SourceSentinel.Core;

public sealed partial class LiveHeapCommandHunter
{
    private void ScanStringContent(int pid, string processName, long memAddress, string rawText, bool recordAsBaselineOnly)
    {
        var mode = DiscoveryMode;
        string text = LiveHeapPatterns.StripInlineHtmlFormatting(rawText);

        // 1. أوامر المودم AT وردود الهاتف وأوامر RIL IPC الهيكس
        if (IsGroupEnabled(L24CommandGroup.ModemAt))
        {
            string activePort = ActiveComAndUsbPortPoller.GetPrimaryActivePortLabel();
            bool isBromOrPreloaderPort = activePort.Contains("BROM", StringComparison.OrdinalIgnoreCase) ||
                                         activePort.Contains("Preloader", StringComparison.OrdinalIgnoreCase) ||
                                         activePort.Contains("0E8D", StringComparison.OrdinalIgnoreCase) ||
                                         activePort.Contains("9008", StringComparison.OrdinalIgnoreCase);
            bool hasActiveModemHardwarePort = activePort.StartsWith("COM", StringComparison.OrdinalIgnoreCase) && !isBromOrPreloaderPort;

            foreach (Match m in LiveHeapPatterns.StrictAtCommandRegex.Matches(text))
            {
                string val = LiveHeapPatterns.CleanToken(m.Value);
                if (val.Length < 3 || LiveHeapPatterns.TruncatedAtPrefixes.Contains(val) || LiveHeapPatterns.StaticAtErrorTableEntries.Contains(val) || LiveHeapPatterns.IsLikelyTruncatedAtFragment(val)) continue;
                if (ShouldSkipOrRecordBaseline(val, recordAsBaselineOnly)) continue;

                bool isReply = val.StartsWith("+");
                if (isReply && !ForensicNoiseGate.ShowPhoneResponses) continue;

                bool isRilHex = val.StartsWith("060100", StringComparison.OrdinalIgnoreCase) ||
                                val.StartsWith("120D00", StringComparison.OrdinalIgnoreCase) ||
                                val.StartsWith("514200", StringComparison.OrdinalIgnoreCase) ||
                                val.StartsWith("516400", StringComparison.OrdinalIgnoreCase);

                bool isExecutedModem = isRilHex || (hasActiveModemHardwarePort && (isReply || val.Contains('=') || val.Contains('?') || val.Length >= 6));
                if (mode == L24DiscoveryMode.ExecutedOnly && !isExecutedModem) continue;

                string cat = isRilHex ? "ADB RIL / AT IPC Command" : (isReply ? "Modem Phone Response" : "Modem AT Command");
                string targetPort = isRilHex ? "/data/local/tmp/AT" : (hasActiveModemHardwarePort ? activePort : "Modem / AT Engine (RAM)");
                string desc = isRilHex
                    ? $"أمر RIL/AT هيكس منفذ في الذاكرة: {val}"
                    : (isReply ? $"رد الهاتف المستلم في ذاكرة الأداة ({targetPort}): {val}" : $"أمر مودم صادر في ذاكرة الأداة ({targetPort}): {val}");

                EmitDiscovered(pid, processName, memAddress + m.Index, SentinelStage.RawCommandExecution, cat, desc, val, targetPort, isConfirmedExecution: isExecutedModem);
            }
        }

        // 2. أوامر وبروتوكولات وسجلات تنفيذ MediaTek
        if (IsGroupEnabled(L24CommandGroup.MediaTek))
        {
            string activePort = ActiveComAndUsbPortPoller.GetPrimaryActivePortLabel();
            string mtkTarget = (activePort.Contains("MediaTek", StringComparison.OrdinalIgnoreCase) ||
                                activePort.Contains("Bootrom", StringComparison.OrdinalIgnoreCase) ||
                                activePort.Contains("0E8D", StringComparison.OrdinalIgnoreCase))
                ? activePort
                : "USB\\VID_0E8D&PID_0003 (MediaTek BROM / DA)";

            foreach (Match m in LiveHeapPatterns.MtkProtocolRegex.Matches(text))
            {
                string val = LiveHeapPatterns.CleanToken(m.Value);
                if (val.Length < 5 || !LiveHeapPatterns.IsCleanRamString(val) || LiveHeapPatterns.IsHtmlOrUiFormatNoise(val)) continue;
                if (LiveHeapPatterns.IsPureUiCosmeticOrDeviceInfoLine(val)) continue;
                if (ShouldSkipOrRecordBaseline(val, recordAsBaselineOnly)) continue;

                if (LiveHeapPatterns.TryTranslateToLowLevelMtkCommand(val, out string lowCmd, out string lowDesc, out string assocFile))
                {
                    EmitDiscovered(pid, processName, memAddress + m.Index, SentinelStage.RawCommandExecution,
                        "MediaTek Low-Level Command",
                        $"⚡ {lowDesc} ({mtkTarget}) :: {lowCmd}",
                        lowCmd, mtkTarget, savedFilePath: assocFile, isConfirmedExecution: true);
                    continue;
                }

                bool isLiveExec = LiveHeapPatterns.IsConfirmedLiveExecutionStep(val);
                if (mode == L24DiscoveryMode.ExecutedOnly && !isLiveExec) continue;

                string cat = isLiveExec ? "MediaTek Low-Level Command" : "MediaTek BROM / DA Command";
                string badge = isLiveExec ? "⚡ تنفيذ MediaTek حي على الهاتف" : "🔶 أمر/عملية MediaTek في ذاكرة الأداة";

                EmitDiscovered(pid, processName, memAddress + m.Index, SentinelStage.RawCommandExecution,
                    cat,
                    $"{badge} ({mtkTarget}): {val}",
                    val, mtkTarget, isConfirmedExecution: isLiveExec);
            }
        }

        // 3. أوامر ADB و Fastboot و Shell
        if (IsGroupEnabled(L24CommandGroup.AdbFastboot) && mode != L24DiscoveryMode.ExecutedOnly)
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
            string activePort = ActiveComAndUsbPortPoller.GetPrimaryActivePortLabel();
            bool isMtkActive = activePort.Contains("MediaTek", StringComparison.OrdinalIgnoreCase) ||
                               activePort.Contains("BROM", StringComparison.OrdinalIgnoreCase) ||
                               activePort.Contains("Preloader", StringComparison.OrdinalIgnoreCase) ||
                               activePort.Contains("0E8D", StringComparison.OrdinalIgnoreCase);
            string qcomTarget = (activePort.StartsWith("COM", StringComparison.OrdinalIgnoreCase) && !isMtkActive)
                ? activePort
                : "Qualcomm EDL 9008 / DIAG";

            foreach (Match m in LiveHeapPatterns.QualcommCommandRegex.Matches(text))
            {
                bool isXml = m.Value.StartsWith("<", StringComparison.Ordinal);
                string val = LiveHeapPatterns.CleanToken(m.Value, allowNewLines: isXml);
                if (val.Length < 6 || !LiveHeapPatterns.IsCleanRamString(val) || LiveHeapPatterns.IsHtmlOrUiFormatNoise(val)) continue;
                if (val.Contains("<svg", StringComparison.OrdinalIgnoreCase) || val.Equals("<?xml version=\"1.0\" ?>", StringComparison.OrdinalIgnoreCase) || val.Equals("<?xml version=\"1.0\"?>", StringComparison.OrdinalIgnoreCase)) continue;
                if (ShouldSkipOrRecordBaseline(val, recordAsBaselineOnly)) continue;

                bool isResp = val.StartsWith("<response", StringComparison.OrdinalIgnoreCase);
                if (isResp && !ForensicNoiseGate.ShowPhoneResponses) continue;

                bool isLiveEdl = !isMtkActive && (isXml || LiveHeapPatterns.IsConfirmedLiveExecutionStep(val) ||
                                 val.StartsWith("fh_loader", StringComparison.OrdinalIgnoreCase) ||
                                 val.StartsWith("qsahara", StringComparison.OrdinalIgnoreCase));
                if (mode == L24DiscoveryMode.ExecutedOnly && !isLiveEdl) continue;

                string cat = isResp ? "Firehose Device Response" : "Qualcomm EDL / Sahara / Firehose Command";
                EmitDiscovered(pid, processName, memAddress + m.Index, SentinelStage.RawCommandExecution,
                    cat, $"🔷 أمر/عملية كوالكوم EDL ({qcomTarget}): {val}", val, qcomTarget, isConfirmedExecution: isLiveEdl);
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
