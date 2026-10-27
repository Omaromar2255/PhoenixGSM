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
        InspectRawBinarySignaturesAndCarveLoaders(pid, processName, memAddress, buffer, length, isExecutableCodeSection);

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

    private int _lastArchivedPartitionTableCount;

    private void InspectRawBinarySignaturesAndCarveLoaders(int pid, string processName, long memAddress, byte[] buf, int len, bool isExecutableCodeSection)
    {
        bool foundNewPartitionsInChunk = false;
        long firstPartitionHitAddr = 0;

        for (int i = 0; i < len - 24; i++)
        {
            // ══════════════════════════════════════════════════════════════════════
            // أولاً: صائد ملفات البوت واللودر والـ DA والـ GFH والـ Preloader EMI والـ IMG4 مباشرة من الرام
            // ══════════════════════════════════════════════════════════════════════
            if (_enableInMemoryLoaderCarving && _carvedLoaderAddresses.Count < 120)
            {
                // أ-1) ملف تهيئة الذاكرة الداخلي MediaTek Preloader EMI (MTK_BLOADER_INFO_vXX)
                if (i + 0x80 <= len &&
                    buf[i] == 'M' && buf[i + 1] == 'T' && buf[i + 2] == 'K' && buf[i + 3] == '_' &&
                    buf[i + 4] == 'B' && buf[i + 5] == 'L' && buf[i + 6] == 'O' && buf[i + 7] == 'A' &&
                    buf[i + 0x64] == 'M' && buf[i + 0x65] == 'T' && buf[i + 0x66] == 'K' && buf[i + 0x67] == '_')
                {
                    long hitAddr = memAddress + i;
                    string headerVer = Encoding.ASCII.GetString(buf, i, 20).TrimEnd('\0');
                    string preloaderFile = Encoding.ASCII.GetString(buf, i + 0x1B, 60).Split('\0')[0].Trim();
                    if (string.IsNullOrWhiteSpace(preloaderFile) || !preloaderFile.EndsWith(".bin", StringComparison.OrdinalIgnoreCase))
                        preloaderFile = $"preloader_carved_0x{hitAddr:X8}.bin";

                    string subVer = Encoding.ASCII.GetString(buf, i + 0x58, 4).TrimEnd('\0');
                    uint emiCount = BitConverter.ToUInt32(buf, i + 0x6C);
                    if (emiCount == 0 || emiCount > 32) emiCount = 6;

                    int entryStride = 0xA0; // 160 bytes per EMI entry in v38+
                    int exactSize = Math.Min(len - i, 0x70 + (int)emiCount * entryStride);
                    if (exactSize >= 0x70 && _carvedLoaderAddresses.TryAdd(hitAddr >> 8, 1))
                    {
                        var mcpList = new System.Collections.Generic.List<string>();
                        for (int e = 0; e < (int)emiCount; e++)
                        {
                            int eOff = i + 0x70 + e * entryStride;
                            if (eOff + 0x30 > len) break;
                            var mcpSb = new StringBuilder();
                            for (int k = 0x10; k < 0x28; k++)
                            {
                                byte b = buf[eOff + k];
                                if (b is >= (byte)'0' and <= (byte)'9' or >= (byte)'A' and <= (byte)'Z' or >= (byte)'a' and <= (byte)'z' or (byte)'_')
                                    mcpSb.Append((char)b);
                                else if (mcpSb.Length >= 4)
                                    break;
                                else
                                    mcpSb.Clear();
                            }
                            if (mcpSb.Length >= 4) mcpList.Add(mcpSb.ToString());
                        }

                        byte[] carved = new byte[exactSize];
                        Buffer.BlockCopy(buf, i, carved, 0, exactSize);
                        if (L24FileArchiver.TryArchiveRawBuffer(carved, preloaderFile, $"InMemoryCarver_EMI ({processName} @ 0x{hitAddr:X8})", out string savedEmi, out long sLen, out _))
                        {
                            LiveHeapPatterns.LastCarvedPreloaderPath = savedEmi;
                            string mcpSummary = mcpList.Count > 0 ? string.Join(", ", mcpList) : "DRAM_EMI";
                            EmitDiscovered(pid, processName, hitAddr, SentinelStage.LocalFilePreparation,
                                "In-Memory Preloader / EMI File Carved",
                                $"💾 تم استخراج وحفظ ملف البريلودر الداخلي [{Path.GetFileName(savedEmi)}] ({sLen:N0} بايت | {headerVer} | عدد شرائح الذاكرة={emiCount}: {mcpSummary})",
                                savedEmi, savedEmi, savedFilePath: savedEmi);

                            string lowCmd = $"EMI_PRELOADER_DRAM_INIT :: Header={headerVer} ({subVer}), File=\"{preloaderFile}\", Size={sLen}B (0x{sLen:X}), EMI_Entries={emiCount}, MCP_Table=[{mcpSummary}] | SavedFile={savedEmi}";
                            EmitDiscovered(pid, processName, hitAddr, SentinelStage.RawCommandExecution,
                                "MediaTek Low-Level Command",
                                $"⚡ أمر تهيئة شرائح الذاكرة (DRAM/eMMC EMI) بالملف المستخرج [{preloaderFile}] ({sLen} بايت): {lowCmd}",
                                lowCmd, "USB\\VID_0E8D&PID_0003 (MediaTek BROM / DA)", savedFilePath: savedEmi, isConfirmedExecution: true);
                        }
                    }
                }

                // أ-2) ملف ترويسة الإقلاع/اللودر الموقع MediaTek GFH_FILE_INFO (MMM\x00\x38\x00\x00\x00FILE_INFO)
                if (!isExecutableCodeSection && i + 56 <= len &&
                    buf[i] == 'M' && buf[i + 1] == 'M' && buf[i + 2] == 'M' && (buf[i + 3] == 0x00 || buf[i + 3] == 0x01) &&
                    buf[i + 4] == 0x38 && buf[i + 5] == 0x00 &&
                    buf[i + 8] == 'F' && buf[i + 9] == 'I' && buf[i + 10] == 'L' && buf[i + 11] == 'E' &&
                    buf[i + 12] == '_' && buf[i + 13] == 'I' && buf[i + 14] == 'N' && buf[i + 15] == 'F')
                {
                    ushort fileType = BitConverter.ToUInt16(buf, i + 24);
                    byte flashDev = buf[i + 26];
                    byte sigType = buf[i + 27];
                    uint loadAddr = BitConverter.ToUInt32(buf, i + 28);
                    uint fileLen = BitConverter.ToUInt32(buf, i + 32);
                    uint contentOff = BitConverter.ToUInt32(buf, i + 40);
                    uint sigLen = BitConverter.ToUInt32(buf, i + 44);

                    if (fileLen >= 256 && fileLen <= 16 * 1024 * 1024 && i + (int)fileLen <= len)
                    {
                        long hitAddr = memAddress + i;
                        if (_carvedLoaderAddresses.TryAdd(hitAddr >> 8, 1))
                        {
                            int extractLen = (int)fileLen;
                            byte[] carved = new byte[extractLen];
                            Buffer.BlockCopy(buf, i, carved, 0, extractLen);
                            string gfhName = $"MTK_GFH_BootPayload_Type0x{fileType:X4}_{extractLen}B.bin";
                            if (L24FileArchiver.TryArchiveRawBuffer(carved, gfhName, $"InMemoryCarver_GFH ({processName} @ 0x{hitAddr:X8})", out string savedGfh, out long sLen, out _))
                            {
                                LiveHeapPatterns.LastCarvedGfhPath = savedGfh;
                                EmitDiscovered(pid, processName, hitAddr, SentinelStage.LocalFilePreparation,
                                    "In-Memory GFH Boot / DA Payload Carved",
                                    $"💾 تم استخراج وحفظ ملف إقلاع/مصادقة MediaTek GFH_FILE_INFO مباشرة من الرام: [{Path.GetFileName(savedGfh)}] ({sLen:N0} بايت)",
                                    savedGfh, savedGfh, savedFilePath: savedGfh);

                                string lowCmd = $"BROM_SEND_GFH_BOOT_PAYLOAD :: GFH_FILE_INFO [FileType=0x{fileType:X4}, FlashDev=0x{flashDev:X2}, SigType=0x{sigType:X2}, LoadAddr=0x{loadAddr:X8}, FileLen=0x{fileLen:X} ({fileLen}B), ContentOff=0x{contentOff:X}, SigLen=0x{sigLen:X}] | SavedFile={savedGfh}";
                                EmitDiscovered(pid, processName, hitAddr, SentinelStage.RawCommandExecution,
                                    "MediaTek Low-Level Command",
                                    $"⚡ أمر إرسال حزمة الإقلاع الموقعة (GFH_FILE_INFO) للهاتف [{Path.GetFileName(savedGfh)}]: {lowCmd}",
                                    lowCmd, "USB\\VID_0E8D&PID_0003 (MediaTek BROM / DA)", savedFilePath: savedGfh, isConfirmedExecution: true);
                            }
                        }
                    }
                }

                // أ-3) ملف MediaTek Download-Agent الكامل (مع استبعاد جدول النصوص داخل FlashToolLib.dll)
                if (i + 64 <= len &&
                    buf[i] == 'M' && buf[i + 1] == 'T' && buf[i + 2] == 'K' && buf[i + 3] == '_' &&
                    buf[i + 4] == 'D' && buf[i + 5] == 'O' && buf[i + 6] == 'W' && buf[i + 7] == 'N' &&
                    !(buf[i + 20] == 'D' && buf[i + 21] == 'A' && buf[i + 22] == '_'))
                {
                    long hitAddr = memAddress + i;
                    if (_carvedLoaderAddresses.TryAdd(hitAddr >> 12, 1))
                    {
                        int extractLen = Math.Min(len - i, 65536);
                        if (extractLen >= 512)
                        {
                            byte[] carved = new byte[extractLen];
                            Buffer.BlockCopy(buf, i, carved, 0, extractLen);
                            if (L24FileArchiver.TryArchiveRawBuffer(carved, $"MTK_AllInOne_DA_0x{hitAddr:X8}.bin", $"InMemoryCarver ({processName})", out string savedDa, out long sLen, out _))
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

            // ج) صائد جدول تقسيمات الذاكرة الثنائي المباشر (GPT Partition Table Structs in RAM)
            if (IsGroupEnabled(L24CommandGroup.MediaTek) && i + 0x40 <= len)
            {
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
                        $"حزمة أمر MediaTek DA/XFlash ثنائية منفذة [CmdID: 0x{cmdId:X4}, الطول: {dataLen} بايت]",
                        hex, "MTK USB/VCOM Stream", isAlreadyHex: true, isConfirmedExecution: true);
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
                    string opName = nextByte switch
                    {
                        0xD0 => "CMD_READ32 (0xD0)",
                        0xD1 => "CMD_READ16 (0xD1)",
                        0xD2 => "CMD_WRITE16 (0xD2)",
                        0xD4 => "CMD_WRITE32 (0xD4 - Register/WDT Write)",
                        0xD5 => "CMD_JUMP_DA (0xD5)",
                        0xD7 => "CMD_SEND_DA (0xD7)",
                        0xD8 => "CMD_GET_TARGET_CONFIG (0xD8)",
                        0xE1 => "CMD_GET_ME_ID (0xE1)",
                        0xE7 => "CMD_GET_SOC_ID (0xE7)",
                        0xFC => "CMD_GET_HW_SW_VER (0xFC)",
                        0xFD => "CMD_GET_HW_CODE (0xFD)",
                        _ => $"BROM_OP_0x{nextByte:X2}"
                    };
                    string lowCmd = $"BROM_PACKET_TX :: Sync=[A0 0A 50 05], Opcode={opName}, RawHex={hex}";
                    EmitDiscovered(pid, processName, memAddress + i, SentinelStage.RawCommandExecution,
                        "MTK BROM Handshake",
                        $"⚡ حزمة مصافحة وأمر معالج MediaTek BROM المباشر [{opName}]: {lowCmd}",
                        lowCmd, "MTK BROM Port", isConfirmedExecution: true);
                }
            }

            // 2b. حزمة مصافحة كوالكوم Sahara الصارمة (Hello / HelloResp / ReadData / Done)
            if (IsGroupEnabled(L24CommandGroup.Qualcomm) && i + 24 <= len &&
                buf[i] is 0x01 or 0x02 && buf[i + 1] == 0x00 && buf[i + 2] == 0x00 && buf[i + 3] == 0x00 &&
                buf[i + 4] == 0x30 && buf[i + 5] == 0x00 && buf[i + 6] == 0x00 && buf[i + 7] == 0x00 &&
                buf[i + 8] == 0x02 && buf[i + 9] == 0x00 && buf[i + 10] == 0x00 && buf[i + 11] == 0x00 &&
                buf[i + 12] == 0x01 && buf[i + 13] == 0x00 && buf[i + 14] == 0x00 && buf[i + 15] == 0x00 &&
                buf[i + 20] <= 0x03 && buf[i + 21] == 0x00 && buf[i + 22] == 0x00 && buf[i + 23] == 0x00)
            {
                string saharaCmd = buf[i] == 0x01 ? "SAHARA_HELLO_REQ" : "SAHARA_HELLO_RESP";
                string hex = Convert.ToHexString(buf.AsSpan(i, 24));
                EmitDiscovered(pid, processName, memAddress + i, SentinelStage.RawCommandExecution,
                    "Qualcomm Sahara Binary Packet",
                    $"🔷 حزمة مصافحة كوالكوم EDL Sahara الثنائية [{saharaCmd}, Ver: 2, Mode: {buf[i + 20]}]",
                    hex, "Qualcomm EDL 9008", isAlreadyHex: true, isConfirmedExecution: true);
            }

            // 2c. ترويسة سامسونج Odin / LOKE الثنائية
            if (IsGroupEnabled(L24CommandGroup.OtherCommands) && i + 8 <= len &&
                ((buf[i] == 'O' && buf[i + 1] == 'D' && buf[i + 2] == 'I' && buf[i + 3] == 'N' && buf[i + 4] == 0) ||
                 (buf[i] == 'L' && buf[i + 1] == 'O' && buf[i + 2] == 'K' && buf[i + 3] == 'E' && buf[i + 4] == 0)))
            {
                string sig = Encoding.ASCII.GetString(buf, i, 4);
                EmitDiscovered(pid, processName, memAddress + i, SentinelStage.RawCommandExecution,
                    "Samsung Odin Handshake",
                    $"⚡ مصافحة وضع الداونلود سامسونج Odin المباشرة [{sig}]",
                    sig, "Samsung Odin Port", isConfirmedExecution: true);
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

    private void ScanStringContent(int pid, string processName, long memAddress, string rawText, bool recordAsBaselineOnly)
    {
        var mode = DiscoveryMode;
        string text = LiveHeapPatterns.StripInlineHtmlFormatting(rawText);

        // 1. أوامر المودم AT وردود الهاتف وأوامر RIL IPC الهيكس
        if (IsGroupEnabled(L24CommandGroup.ModemAt))
        {
            string activePort = ActiveComAndUsbPortPoller.GetPrimaryActivePortLabel();
            bool hasActiveHardwarePort = activePort.StartsWith("COM", StringComparison.OrdinalIgnoreCase);

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

                bool isExecutedModem = isReply || isRilHex || (hasActiveHardwarePort && (val.Contains('=') || val.Contains('?') || val.Length >= 6));
                if (mode == L24DiscoveryMode.ExecutedOnly && !isExecutedModem) continue;

                string cat = isRilHex ? "ADB RIL / AT IPC Command" : (isReply ? "Modem Phone Response" : "Modem AT Command");
                string desc = isRilHex
                    ? $"أمر RIL/AT هيكس منفذ في الذاكرة: {val}"
                    : (isReply ? $"رد الهاتف المستلم في ذاكرة الأداة ({activePort}): {val}" : $"أمر مودم صادر في ذاكرة الأداة ({activePort}): {val}");

                string targetPort = isRilHex ? "/data/local/tmp/AT" : activePort;
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
            string qcomTarget = activePort.StartsWith("COM", StringComparison.OrdinalIgnoreCase) ? activePort : "Qualcomm EDL 9008 / DIAG";

            foreach (Match m in LiveHeapPatterns.QualcommCommandRegex.Matches(text))
            {
                bool isXml = m.Value.StartsWith("<", StringComparison.Ordinal);
                string val = LiveHeapPatterns.CleanToken(m.Value, allowNewLines: isXml);
                if (val.Length < 6 || !LiveHeapPatterns.IsCleanRamString(val) || LiveHeapPatterns.IsHtmlOrUiFormatNoise(val)) continue;
                if (val.Contains("<svg", StringComparison.OrdinalIgnoreCase)) continue;
                if (ShouldSkipOrRecordBaseline(val, recordAsBaselineOnly)) continue;

                bool isResp = val.StartsWith("<response", StringComparison.OrdinalIgnoreCase);
                if (isResp && !ForensicNoiseGate.ShowPhoneResponses) continue;

                bool isLiveEdl = isXml || LiveHeapPatterns.IsConfirmedLiveExecutionStep(val) ||
                                 val.StartsWith("fh_loader", StringComparison.OrdinalIgnoreCase) ||
                                 val.StartsWith("qsahara", StringComparison.OrdinalIgnoreCase);
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
