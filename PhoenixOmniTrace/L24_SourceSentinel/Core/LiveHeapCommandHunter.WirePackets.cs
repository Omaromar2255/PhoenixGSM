using System;
using System.Text;
using PhoenixOmniTrace.L24_SourceSentinel.Models;

namespace PhoenixOmniTrace.L24_SourceSentinel.Core;

public sealed partial class LiveHeapCommandHunter
{
    private void InspectWirePackets(int pid, string processName, long memAddress, byte[] buf, int len)
    {
        for (int i = 0; i < len - 24; i++)
        {
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
                bool isValidAckOrOp = (nextByte == 0x5F && i + 7 < len && buf[i + 5] == 0xF5 && buf[i + 6] == 0xAF && buf[i + 7] == 0xFA) ||
                                      (nextByte is 0xD0 or 0xD1 or 0xD2 or 0xD4 or 0xD5 or 0xD6 or 0xD7 or 0xD8 or 0xDA or 0xDC or 0xE1 or 0xE7 or 0xFC or 0xFD &&
                                       i + 7 < len && (buf[i + 5] == 0x00 || buf[i + 5] == 0x10 || buf[i + 5] == 0x20));
                if (!isX86InstructionNoise && isValidAckOrOp)
                {
                    int snapLen = Math.Min(16, len - i);
                    string hex = Convert.ToHexString(buf.AsSpan(i, snapLen));
                    string opName = nextByte switch
                    {
                        0x5F => "BROM_HANDSHAKE_SYNC_ACK (5F F5 AF FA)",
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
    }
}
