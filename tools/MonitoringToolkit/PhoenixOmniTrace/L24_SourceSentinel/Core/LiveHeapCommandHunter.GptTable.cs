using System;
using System.IO;
using System.Linq;
using System.Text;
using PhoenixOmniTrace.L24_SourceSentinel.Models;

namespace PhoenixOmniTrace.L24_SourceSentinel.Core;

public sealed partial class LiveHeapCommandHunter
{
    private int _lastArchivedPartitionTableCount;

    private void InspectGptPartitionStructs(int pid, string processName, long memAddress, byte[] buf, int len)
    {
        if (!IsGroupEnabled(L24CommandGroup.MediaTek)) return;

        bool foundNewPartitionsInChunk = false;
        long firstPartitionHitAddr = 0;

        for (int i = 0; i < len - 24; i++)
        {
            if (i + 0x40 > len) break;

            int nameLen = buf[i];
            if (nameLen is >= 2 and <= 15)
            {
                bool validPartName = true;
                for (int k = 1; k <= nameLen; k++)
                {
                    byte ch = buf[i + k];
                    if (!((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_'))
                    {
                        validPartName = false;
                        break;
                    }
                }

                if (validPartName)
                {
                    ulong beginAddr = BitConverter.ToUInt64(buf, i + 0x28);
                    uint startLba = BitConverter.ToUInt32(buf, i + 0x30);
                    uint sectors = BitConverter.ToUInt32(buf, i + 0x34);
                    uint sizeKiB = BitConverter.ToUInt32(buf, i + 0x38);

                    if (sectors > 0 && (ulong)startLba * 512UL == beginAddr && sizeKiB == sectors / 2)
                    {
                        string partName = Encoding.ASCII.GetString(buf, i + 1, nameLen);
                        ulong partSize = (ulong)sectors * 512UL;
                        ulong endAddr = beginAddr + partSize;
                        if (!LiveHeapPatterns.DiscoveredGptPartitions.TryGetValue(partName, out var existing) || existing.BeginAddr != beginAddr)
                        {
                            LiveHeapPatterns.DiscoveredGptPartitions[partName] = (beginAddr, endAddr, partSize, startLba, sectors);
                            foundNewPartitionsInChunk = true;
                            if (firstPartitionHitAddr == 0) firstPartitionHitAddr = memAddress + i;
                        }
                    }
                }
            }
        }

        // إذا اكتشفنا جدول تقسيمات الذاكرة الكامل في الرام، نحفظ ملف الـ Scatter ونصدر أمر جدول الـ GPT التفصيلي
        if (foundNewPartitionsInChunk && LiveHeapPatterns.DiscoveredGptPartitions.Count >= 10 &&
            LiveHeapPatterns.DiscoveredGptPartitions.Count != _lastArchivedPartitionTableCount)
        {
            _lastArchivedPartitionTableCount = LiveHeapPatterns.DiscoveredGptPartitions.Count;
            ArchiveAndEmitExtractedPartitionTable(pid, processName, firstPartitionHitAddr);
        }
    }

    private void ArchiveAndEmitExtractedPartitionTable(int pid, string processName, long memAddr)
    {
        var sorted = LiveHeapPatterns.DiscoveredGptPartitions
            .Select(kv => (Name: kv.Key, kv.Value.BeginAddr, kv.Value.EndAddr, kv.Value.SizeBytes, kv.Value.StartLba, kv.Value.Sectors))
            .OrderBy(p => p.BeginAddr)
            .ToList();

        var sb = new StringBuilder();
        sb.AppendLine("############################################################################################################");
        sb.AppendLine("# General Setting - Extracted Live from Tool RAM by PhoenixOmniTrace L24_SourceSentinel");
        sb.AppendLine("############################################################################################################");
        sb.AppendLine("- general: MTK_PLATFORM_CFG");
        sb.AppendLine("  info:");
        sb.AppendLine("    - config_version: V1.1.2");
        sb.AppendLine("      platform: MT6761");
        sb.AppendLine("      storage: EMMC");
        sb.AppendLine("      boot_channel: MSDC_0");
        sb.AppendLine("      block_size: 0x20000");
        sb.AppendLine();
        sb.AppendLine("# ==========================================================================================================");
        sb.AppendLine("# Summary Partition Table (BeginAddr .. EndAddr | Size | LBA)");
        sb.AppendLine("# ==========================================================================================================");
        sb.AppendLine($"# [00] preloader        Begin=0x000000000 End=0x000080000 Size=0x000080000 (   512 KiB) [Region=EMMC_BOOT_1] File=preloader_u520.bin");
        sb.AppendLine($"# [01] pgpt             Begin=0x000000000 End=0x000008000 Size=0x000008000 (    32 KiB) [Region=EMMC_USER]   File=pgpt.bin");

        int idx = 2;
        foreach (var p in sorted)
        {
            string ext = p.Name is "recovery" or "boot" or "dtbo" or "vbmeta" or "vbmeta_system" or "vbmeta_vendor" or "super" or "userdata" or "cache" or "md1img" or "persist" or "nvdata" or "protect1" or "protect2" ? ".img" : ".bin";
            sb.AppendLine($"# [{idx:D2}] {p.Name,-16} Begin=0x{p.BeginAddr:X9} End=0x{p.EndAddr:X9} Size=0x{p.SizeBytes:X9} ({p.SizeBytes / 1024,8} KiB) [LBA=0x{p.StartLba:X}..0x{p.StartLba + p.Sectors - 1:X}] File={p.Name}{ext}");
            idx++;
        }
        sb.AppendLine();

        int sysIdx = 0;
        sb.AppendLine($"- partition_index: SYS{sysIdx++}");
        sb.AppendLine("  partition_name: preloader");
        sb.AppendLine("  file_name: preloader_u520.bin");
        sb.AppendLine("  is_download: true");
        sb.AppendLine("  type: SV5_BL_BIN");
        sb.AppendLine("  linear_start_addr: 0x0");
        sb.AppendLine("  physical_start_addr: 0x0");
        sb.AppendLine("  partition_size: 0x80000");
        sb.AppendLine("  region: EMMC_BOOT_1");
        sb.AppendLine();

        sb.AppendLine($"- partition_index: SYS{sysIdx++}");
        sb.AppendLine("  partition_name: pgpt");
        sb.AppendLine("  file_name: pgpt.bin");
        sb.AppendLine("  is_download: false");
        sb.AppendLine("  type: NORMAL_ROM");
        sb.AppendLine("  linear_start_addr: 0x0");
        sb.AppendLine("  physical_start_addr: 0x0");
        sb.AppendLine("  partition_size: 0x8000");
        sb.AppendLine("  region: EMMC_USER");
        sb.AppendLine();

        foreach (var p in sorted)
        {
            string ext = p.Name is "recovery" or "boot" or "dtbo" or "vbmeta" or "vbmeta_system" or "vbmeta_vendor" or "super" or "userdata" or "cache" or "md1img" or "persist" or "nvdata" or "protect1" or "protect2" ? ".img" : ".bin";
            sb.AppendLine($"- partition_index: SYS{sysIdx++}");
            sb.AppendLine($"  partition_name: {p.Name}");
            sb.AppendLine($"  file_name: {p.Name}{ext}");
            sb.AppendLine("  is_download: true");
            sb.AppendLine("  type: NORMAL_ROM");
            sb.AppendLine($"  linear_start_addr: 0x{p.BeginAddr:X}");
            sb.AppendLine($"  physical_start_addr: 0x{p.BeginAddr:X}");
            sb.AppendLine($"  partition_size: 0x{p.SizeBytes:X}");
            sb.AppendLine("  region: EMMC_USER");
            sb.AppendLine();
        }

        byte[] scatterBytes = Encoding.UTF8.GetBytes(sb.ToString());
        if (L24FileArchiver.TryArchiveRawBuffer(scatterBytes, "MT6761_Android_scatter.txt", $"InMemoryCarver_GPT ({processName} @ 0x{memAddr:X8})", out string savedScatter, out long sLen, out _))
        {
            LiveHeapPatterns.LastCarvedScatterPath = savedScatter;
            EmitDiscovered(pid, processName, memAddr, SentinelStage.LocalFilePreparation,
                "In-Memory GPT Scatter Table Carved",
                $"💾 تم استخراج وحفظ ملف خارطة تقسيمات الذاكرة الكامل [{Path.GetFileName(savedScatter)}] ({sorted.Count + 2} قطاع | {sLen:N0} بايت)",
                savedScatter, savedScatter, savedFilePath: savedScatter);

            var keyParts = sorted
                .Where(p => p.Name is "boot_para" or "recovery" or "frp" or "nvcfg" or "nvdata" or "protect1" or "protect2" or "seccfg" or "persist" or "nvram" or "lk" or "boot" or "super" or "userdata")
                .Select(p => $"{p.Name}@0x{p.BeginAddr:X}(0x{p.SizeBytes:X})")
                .ToList();

            string lowCmd = $"DA_CMD_READ_GPT_TABLE (0x010008 / PGPT) :: TotalPartitions={sorted.Count + 2} [preloader@0x0(0x80000), pgpt@0x0(0x8000), {string.Join(", ", keyParts)}] | ScatterFile={savedScatter}";
            EmitDiscovered(pid, processName, memAddr, SentinelStage.RawCommandExecution,
                "MediaTek Low-Level Command",
                $"⚡ أمر قراءة واستخراج جدول تقسيمات الذاكرة الكامل (GPT/Scatter: {sorted.Count + 2} قطاع) من الرام: {lowCmd}",
                lowCmd, "USB\\VID_0E8D&PID_0003 (MediaTek BROM / DA)", savedFilePath: savedScatter, isConfirmedExecution: true);
        }
    }
}
