using System;
using System.Text.RegularExpressions;

namespace PhoenixOmniTrace.L24_SourceSentinel.Core;

public static partial class LiveHeapPatterns
{
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

        if (val.StartsWith("Selected ", StringComparison.OrdinalIgnoreCase) && val.Contains(":", StringComparison.Ordinal))
        {
            string selVal = val[(val.IndexOf(':') + 1)..].Trim();
            if (selVal.Length < 2 || selVal.Contains('%')) return false;
            LastSelectedAuthOrDaName = selVal;
            associatedFilePath = !string.IsNullOrEmpty(LastCarvedDaAllInOnePath) ? LastCarvedDaAllInOnePath : LastCarvedGfhPath;
            string savedNote = !string.IsNullOrEmpty(associatedFilePath) ? $" | Container={associatedFilePath}" : "";
            lowLevelCommand = $"MTK_SELECT_CUSTOM_DA_AUTH :: Profile=\"{selVal}\"{savedNote}";
            lowLevelDesc = $"تحديد ملف البوت/المصادقة المخصص في الأداة (Selected Auth/DA Profile: {selVal})";
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
            if (sec.Contains('%') || sec.Length < 2 || (!sec.Contains("SCB", StringComparison.OrdinalIgnoreCase) && !sec.Contains("SBC", StringComparison.OrdinalIgnoreCase) && !sec.Contains("SLA", StringComparison.OrdinalIgnoreCase) && !sec.Contains("DAA", StringComparison.OrdinalIgnoreCase)))
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
            associatedFilePath = !string.IsNullOrEmpty(LastCarvedDaStage1Path)
                ? LastCarvedDaStage1Path
                : (!string.IsNullOrEmpty(LastCarvedDaAllInOnePath) ? LastCarvedDaAllInOnePath : LastCarvedGfhPath);
            string daVerTag = !string.IsNullOrEmpty(LastCarvedDaVersion) ? $", DA_Ver=\"{LastCarvedDaVersion}\"" : "";
            string authTag = !string.IsNullOrEmpty(LastSelectedAuthOrDaName) ? $", SelectedProfile=\"{LastSelectedAuthOrDaName}\"" : "";
            string savedNote = !string.IsNullOrEmpty(associatedFilePath) ? $" | DA_Stage1_File={associatedFilePath}" : "";
            lowLevelCommand = $"BROM_SEND_DA :: CMD_SEND_DA(0xD7, TargetAddr=0x00200000 [SRAM], Size=0x38B18 [232216B], SigLen=0x100, Stage=DA_Stage1{daVerTag}{authTag}) -> ChecksumVerify=OK{savedNote}";
            lowLevelDesc = "أمر حقن وإرسال وكيل التحميل الفعلي (Download-Agent Stage 1 - 232KB) إلى ذاكرة SRAM الداخلية (0x00200000) عبر الأمر CMD_SEND_DA (0xD7)";
            return true;
        }

        if (val.StartsWith("Booting device... OK", StringComparison.OrdinalIgnoreCase))
        {
            associatedFilePath = !string.IsNullOrEmpty(LastCarvedDaStage2Path)
                ? LastCarvedDaStage2Path
                : (!string.IsNullOrEmpty(LastCarvedDaAllInOnePath) ? LastCarvedDaAllInOnePath : LastCarvedPreloaderPath);
            string emiName = !string.IsNullOrEmpty(LastCarvedPreloaderPath) ? System.IO.Path.GetFileName(LastCarvedPreloaderPath) : "preloader_u520.bin";
            string stg2Note = !string.IsNullOrEmpty(associatedFilePath) ? $" | DA_Stage2_File={associatedFilePath}" : "";
            lowLevelCommand = $"BROM_JUMP_DA :: CMD_JUMP_DA(0xD5, JumpAddr=0x00200000) -> DA_STAGE1_INIT_DRAM(EMI={emiName}) -> DA_SEND_STAGE2(TargetAddr=0x40000000 [DRAM], Size=0x4ABEC [306156B]){stg2Note}";
            lowLevelDesc = "أمر القفز لتنفيذ وكيل التحميل CMD_JUMP_DA (0xD5 @ 0x00200000) وتهيئة الـ DRAM بملف الـ EMI ثم إرسال المرحلة الثانية DA Stage 2 (306KB @ 0x40000000)";
            return true;
        }

        if (val.StartsWith("Storage :", StringComparison.OrdinalIgnoreCase))
        {
            string st = val["Storage :".Length..].Trim();
            if (st.Contains('%') || !st.Contains("CID", StringComparison.OrdinalIgnoreCase) || st.Length < 20) return false;
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

        if ((val.StartsWith("Erasing ", StringComparison.OrdinalIgnoreCase) ||
             val.StartsWith("Formatting ", StringComparison.OrdinalIgnoreCase) ||
             val.StartsWith("Writing ", StringComparison.OrdinalIgnoreCase) ||
             (val.StartsWith("Reading ", StringComparison.OrdinalIgnoreCase) && !val.StartsWith("Reading hardware", StringComparison.OrdinalIgnoreCase) && !val.StartsWith("Reading partition", StringComparison.OrdinalIgnoreCase) && !val.StartsWith("Reading device", StringComparison.OrdinalIgnoreCase))) &&
            val.Contains("OK", StringComparison.OrdinalIgnoreCase) &&
            !val.Contains('%'))
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
}
