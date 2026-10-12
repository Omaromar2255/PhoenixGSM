using System;
using System.Text;

namespace PhoenixGSM.OmniTrace.BinaryAnalysis;

public class PartitionHeaderInfo
{
    public string PartitionType { get; set; } = "Unknown";
    public bool IsRecognized { get; set; }
}

/// <summary>
/// Analyzes raw firmware image headers.
/// يحلل ترويسات صور البرامج الثابتة الخام.
/// </summary>
public class FirmwarePartitionParser : IDisposable
{
    private static readonly byte[] AndroidMagic = Encoding.ASCII.GetBytes("ANDROID!");
    private const uint SparseMagic = 0x3AFF26ED;
    private const ushort Ext4Magic = 0xEF53;

    /// <summary>
    /// Identifies the partition type from the header bytes.
    /// يحدد نوع القسم من بايتات الترويسة.
    /// </summary>
    public PartitionHeaderInfo IdentifyPartitionType(ReadOnlySpan<byte> headerBytes)
    {
        var info = new PartitionHeaderInfo();

        try
        {
            if (headerBytes.Length < 8) return info;

            // 1. Android Boot Image
            // 1. صورة إقلاع أندرويد
            if (headerBytes.Slice(0, 8).SequenceEqual(AndroidMagic))
            {
                info.PartitionType = "Android Boot Image";
                info.IsRecognized = true;
                return info;
            }

            // 2. Sparse Image
            // 2. صورة متفرقة (Sparse)
            uint magic32 = BitConverter.ToUInt32(headerBytes.Slice(0, 4).ToArray(), 0);
            if (magic32 == SparseMagic)
            {
                info.PartitionType = "Android Sparse Image";
                info.IsRecognized = true;
                return info;
            }

            // 3. Ext4 Filesystem (Superblock magic at offset 0x38, assuming header points there)
            // 3. نظام ملفات Ext4
            if (headerBytes.Length >= 0x40)
            {
                ushort ext4MagicCheck = BitConverter.ToUInt16(headerBytes.Slice(0x38, 2).ToArray(), 0);
                if (ext4MagicCheck == Ext4Magic)
                {
                    info.PartitionType = "Ext4 Filesystem";
                    info.IsRecognized = true;
                    return info;
                }
            }
            
            // 4. ELF / Qualcomm MBN (Starts with ELF magic)
            // 4. صورة ELF / MBN
            if (headerBytes[0] == 0x7F && headerBytes[1] == 0x45 && headerBytes[2] == 0x4C && headerBytes[3] == 0x46)
            {
                info.PartitionType = "ELF / Qualcomm MBN";
                info.IsRecognized = true;
                return info;
            }

            return info;
        }
        catch (Exception ex)
        {
            // Fail-open
            // نمط تجاوز الفشل
            Console.WriteLine($"[FirmwarePartitionParser Error]: {ex.Message}");
            return info;
        }
    }

    public void Dispose()
    {
        // Cleanup
        // تنظيف
    }
}
