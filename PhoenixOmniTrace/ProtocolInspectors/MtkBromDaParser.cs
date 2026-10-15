using System;

namespace PhoenixGSM.OmniTrace.ProtocolInspectors;

/// <summary>
/// محلل أوامر ميديا تيك (MediaTek BROM/DA Parser)
/// </summary>
public class MtkBromDaParser
{
    private const string ProtocolName = "MTK_BROM_DA";

    // MTK DA Commands (Partial list for detection)
    private const byte DA_FORMAT = 0xD6;
    private const byte DA_WRITE_FLASH = 0xD5;
    private const byte DA_READ_FLASH = 0xD4;
    private const byte DA_JUMP = 0xD8;
    
    // BROM SLA/DAA Commands
    private const byte BROM_CMD_SLA_CHALLENGE = 0xFE; 

    /// <summary>
    /// فحص إطار بيانات ميديا تيك (Inspect MediaTek frame)
    /// </summary>
    public FlashingInspectionResult? InspectBromFrame(ReadOnlySpan<byte> frame)
    {
        if (frame.Length == 0)
            return null;

        try
        {
            byte cmdId = frame[0];
            FlashingOperationType opType = FlashingOperationType.Unknown;
            FlashingRiskLevel risk = FlashingRiskLevel.Safe;
            string desc = string.Empty;

            // فحص الأوامر بناءً على الـ Byte الأول (Check commands based on first byte)
            switch (cmdId)
            {
                case DA_FORMAT:
                    opType = FlashingOperationType.FormatStorage;
                    risk = FlashingRiskLevel.High;
                    desc = "DA FORMAT command detected (Danger: erases flash possibly including NVRAM/IMEI).";
                    break;

                case DA_WRITE_FLASH:
                    opType = FlashingOperationType.WritePartition;
                    risk = FlashingRiskLevel.Medium;
                    desc = "DA WRITE_FLASH command detected.";
                    break;

                case DA_READ_FLASH:
                    opType = FlashingOperationType.Read;
                    risk = FlashingRiskLevel.Low;
                    desc = "DA READ_FLASH command detected.";
                    break;

                case DA_JUMP:
                    opType = FlashingOperationType.PeekPoke;
                    risk = FlashingRiskLevel.Critical;
                    desc = "DA JUMP command detected (Executing arbitrary code).";
                    break;

                case BROM_CMD_SLA_CHALLENGE:
                    opType = FlashingOperationType.DisableAuth;
                    risk = FlashingRiskLevel.Critical;
                    desc = "BROM SLA/DAA Challenge command detected (Bypassing auth).";
                    break;

                default:
                    // Not a recognized high-risk frame or just normal traffic
                    // تجاهل الأوامر العادية لتفادي الضوضاء
                    return null;
            }

            return new FlashingInspectionResult(
                Protocol: ProtocolName,
                Operation: opType,
                TargetPartition: null, // BROM/DA doesn't easily expose partition names in the header
                MemoryAddress: null,
                Length: frame.Length,
                RiskLevel: risk,
                Description: desc,
                RawXmlOrCommand: RawCommandBytes(frame)
            );
        }
        catch (Exception ex)
        {
            // Fail-open: do not crash on parse errors
            Console.WriteLine($"[MtkBromDaParser] Frame parsing error: {ex.Message}");
            return null;
        }
    }

    private string RawCommandBytes(ReadOnlySpan<byte> frame)
    {
        // نحتفظ بأول 16 بايت فقط للتوضيح
        // Keep first 16 bytes for logging
        int len = Math.Min(frame.Length, 16);
        return BitConverter.ToString(frame.Slice(0, len).ToArray());
    }
}
