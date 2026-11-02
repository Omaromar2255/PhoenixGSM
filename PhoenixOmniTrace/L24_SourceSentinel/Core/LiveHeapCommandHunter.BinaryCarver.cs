using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using PhoenixOmniTrace.L24_SourceSentinel.Models;

namespace PhoenixOmniTrace.L24_SourceSentinel.Core;

public sealed partial class LiveHeapCommandHunter
{
    private void InspectRawBinarySignaturesAndCarveLoaders(
        IntPtr hProc,
        int pid,
        string processName,
        long memAddress,
        byte[] buf,
        int len,
        bool isExecutableCodeSection)
    {
        if (_enableInMemoryLoaderCarving && _carvedLoaderAddresses.Count < 120)
        {
            CarveInMemoryLoaders(hProc, pid, processName, memAddress, buf, len, isExecutableCodeSection);
        }

        // لا نفحص التوقيعات الثنائية القصيرة داخل أقسام الكود التنفيذي لمنع الإيجابيات الكاذبة
        if (isExecutableCodeSection) return;

        InspectGptPartitionStructs(pid, processName, memAddress, buf, len);
        InspectWirePackets(pid, processName, memAddress, buf, len);
    }

    private void CarveInMemoryLoaders(
        IntPtr hProc,
        int pid,
        string processName,
        long memAddress,
        byte[] buf,
        int len,
        bool isExecutableCodeSection)
    {
        for (int i = 0; i < len - 24; i++)
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
                    var mcpList = new List<string>();
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

            // أ-3) ملف MediaTek Download-Agent الفعلي الكامل (MTK_DOWNLOAD_AGENT + Magic 0x22668899 + تفكيك Stage 0/1/2)
            if (!isExecutableCodeSection && i + 0xC0 <= len &&
                buf[i] == 'M' && buf[i + 1] == 'T' && buf[i + 2] == 'K' && buf[i + 3] == '_' &&
                buf[i + 4] == 'D' && buf[i + 5] == 'O' && buf[i + 6] == 'W' && buf[i + 7] == 'N' &&
                buf[i + 0x64] == 0x99 && buf[i + 0x65] == 0x88 && buf[i + 0x66] == 0x66 && buf[i + 0x67] == 0x22)
            {
                long hitAddr = memAddress + i;
                string daVer = Encoding.ASCII.GetString(buf, i + 0x20, 64).Split('\0')[0].Trim();
                if (string.IsNullOrWhiteSpace(daVer)) daVer = "MTK_AllInOne_DA";
                ushort daMagic = BitConverter.ToUInt16(buf, i + 0x6C);
                ushort hwCode = BitConverter.ToUInt16(buf, i + 0x6E);
                ushort hwSub = BitConverter.ToUInt16(buf, i + 0x70);
                ushort hwVer = BitConverter.ToUInt16(buf, i + 0x72);

                uint r0Off = BitConverter.ToUInt32(buf, i + 0x80);
                uint r0Len = BitConverter.ToUInt32(buf, i + 0x84);
                uint r0Addr = BitConverter.ToUInt32(buf, i + 0x88);

                uint s1Off = BitConverter.ToUInt32(buf, i + 0x94);
                uint s1Len = BitConverter.ToUInt32(buf, i + 0x98);
                uint s1Addr = BitConverter.ToUInt32(buf, i + 0x9C);
                uint s1Sig = BitConverter.ToUInt32(buf, i + 0xA4);

                uint s2Off = BitConverter.ToUInt32(buf, i + 0xA8);
                uint s2Len = BitConverter.ToUInt32(buf, i + 0xAC);
                uint s2Addr = BitConverter.ToUInt32(buf, i + 0xB0);

                uint totalDaSize = Math.Max(s2Off + s2Len, s1Off + s1Len);
                if (daMagic == 0xDADA && totalDaSize >= 0x4000 && totalDaSize <= 32 * 1024 * 1024 &&
                    _carvedLoaderAddresses.TryAdd(hitAddr >> 12, 1))
                {
                    byte[]? fullDa = null;
                    if (i + (int)totalDaSize <= len)
                    {
                        fullDa = new byte[totalDaSize];
                        Buffer.BlockCopy(buf, i, fullDa, 0, (int)totalDaSize);
                    }
                    else if (hProc != IntPtr.Zero)
                    {
                        byte[] tmp = new byte[totalDaSize];
                        if (ReadProcessMemory(hProc, (IntPtr)hitAddr, tmp, (int)totalDaSize, out int rDa) && rDa == (int)totalDaSize)
                            fullDa = tmp;
                    }

                    if (fullDa != null)
                    {
                        LiveHeapPatterns.LastCarvedDaVersion = daVer;
                        string cleanVer = Regex.Replace(daVer, @"[^A-Za-z0-9_\-\.]", "_");
                        string allInOneName = $"{cleanVer}_MT{hwCode:X4}.bin";

                        if (L24FileArchiver.TryArchiveRawBuffer(fullDa, allInOneName, $"InMemoryCarver_DA_Full ({processName} @ 0x{hitAddr:X8})", out string savedFullDa, out long fullLen, out string fullSha))
                        {
                            LiveHeapPatterns.LastCarvedDaAllInOnePath = savedFullDa;
                            EmitDiscovered(pid, processName, hitAddr, SentinelStage.LocalFilePreparation,
                                "In-Memory Boot / DA Loader Carved",
                                $"💾 تم استخراج وحفظ حاوية وكيل التحميل الكاملة (All-In-One DA) مباشرة من الرام: [{Path.GetFileName(savedFullDa)}] ({fullLen:N0} بايت | SoC=MT{hwCode:X4} | SHA256={fullSha[..12]})",
                                savedFullDa, savedFullDa, savedFilePath: savedFullDa);
                        }

                        string savedS1Path = string.Empty;
                        if (s1Off > 0 && s1Len > 0 && s1Off + s1Len <= fullDa.Length)
                        {
                            byte[] s1Bytes = new byte[s1Len];
                            Buffer.BlockCopy(fullDa, (int)s1Off, s1Bytes, 0, (int)s1Len);
                            string s1Name = $"DA_Stage1_SRAM_MT{hwCode:X4}_0x{s1Addr:X8}_{s1Len}B.bin";
                            if (L24FileArchiver.TryArchiveRawBuffer(s1Bytes, s1Name, $"InMemoryCarver_DA_Stage1 ({processName} @ 0x{hitAddr + s1Off:X8})", out savedS1Path, out long s1SavedLen, out _))
                            {
                                LiveHeapPatterns.LastCarvedDaStage1Path = savedS1Path;
                                EmitDiscovered(pid, processName, hitAddr + s1Off, SentinelStage.LocalFilePreparation,
                                    "In-Memory DA Stage 1 (SRAM) Carved",
                                    $"💾 تم استخراج وحفظ ملف البوت المرحلة الأولى (DA Stage 1 - SRAM @ 0x{s1Addr:X8}): [{Path.GetFileName(savedS1Path)}] ({s1SavedLen:N0} بايت)",
                                    savedS1Path, savedS1Path, savedFilePath: savedS1Path);
                            }
                        }

                        string savedS2Path = string.Empty;
                        if (s2Off > 0 && s2Len > 0 && s2Off + s2Len <= fullDa.Length)
                        {
                            byte[] s2Bytes = new byte[s2Len];
                            Buffer.BlockCopy(fullDa, (int)s2Off, s2Bytes, 0, (int)s2Len);
                            string s2Name = $"DA_Stage2_DRAM_MT{hwCode:X4}_0x{s2Addr:X8}_{s2Len}B.bin";
                            if (L24FileArchiver.TryArchiveRawBuffer(s2Bytes, s2Name, $"InMemoryCarver_DA_Stage2 ({processName} @ 0x{hitAddr + s2Off:X8})", out savedS2Path, out long s2SavedLen, out _))
                            {
                                LiveHeapPatterns.LastCarvedDaStage2Path = savedS2Path;
                                EmitDiscovered(pid, processName, hitAddr + s2Off, SentinelStage.LocalFilePreparation,
                                    "In-Memory DA Stage 2 (DRAM) Carved",
                                    $"💾 تم استخراج وحفظ ملف البوت المرحلة الثانية (DA Stage 2 - DRAM @ 0x{s2Addr:X8}): [{Path.GetFileName(savedS2Path)}] ({s2SavedLen:N0} بايت)",
                                    savedS2Path, savedS2Path, savedFilePath: savedS2Path);
                            }
                        }

                        string lowCmd = $"DA_BINARY_CONTAINER_PARSED :: Ver=\"{daVer}\", SoC=0x{hwCode:X4} (Sub=0x{hwSub:X4}, Ver=0x{hwVer:X4}), TotalSize={fullDa.Length}B (0x{fullDa.Length:X}) | Stage0=[Off=0x{r0Off:X}, Len=0x{r0Len:X}, Addr=0x{r0Addr:X8}] | Stage1_SRAM=[Off=0x{s1Off:X}, Len=0x{s1Len:X} ({s1Len}B), LoadAddr=0x{s1Addr:X8}, SigLen=0x{s1Sig:X}] | Stage2_DRAM=[Off=0x{s2Off:X}, Len=0x{s2Len:X} ({s2Len}B), LoadAddr=0x{s2Addr:X8}] | SavedContainer={savedFullDa} | SavedStage1={savedS1Path} | SavedStage2={savedS2Path}";
                        EmitDiscovered(pid, processName, hitAddr, SentinelStage.RawCommandExecution,
                            "MediaTek Low-Level Command",
                            $"⚡ تفكيك واستخراج وكيل التحميل الفعلي من الرام [{daVer}] (الحجم الكلي: {fullDa.Length:N0} بايت | Stage1={s1Len:N0}B @ 0x{s1Addr:X8} | Stage2={s2Len:N0}B @ 0x{s2Addr:X8}): {lowCmd}",
                            lowCmd, "USB\\VID_0E8D&PID_0003 (MediaTek BROM / DA)", savedFilePath: !string.IsNullOrEmpty(savedFullDa) ? savedFullDa : savedS1Path, isConfirmedExecution: true);
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
    }
}
