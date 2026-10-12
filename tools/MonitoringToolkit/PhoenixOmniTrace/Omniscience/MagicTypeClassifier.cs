using System;

namespace PhoenixGSM.OmniTrace.Omniscience
{
    /// <summary>
    /// Magic-byte identification of touched files and streams.
    /// تصنيف الملفات بناءً على البايتات السحرية
    /// </summary>
    public static class MagicTypeClassifier
    {
        public static string IdentifyFileType(ReadOnlySpan<byte> buffer)
        {
            try
            {
                if (buffer.Length < 4) return "Unknown";

                // ZIP, APK, JAR
                if (buffer[0] == 0x50 && buffer[1] == 0x4B && buffer[2] == 0x03 && buffer[3] == 0x04)
                    return "ZIP_APK_JAR";
                
                // 7Z
                if (buffer.Length >= 6 && buffer[0] == 0x37 && buffer[1] == 0x7A && buffer[2] == 0xBC && buffer[3] == 0xAF && buffer[4] == 0x27 && buffer[5] == 0x1C)
                    return "7Z";

                // RAR
                if (buffer.Length >= 7 && buffer[0] == 0x52 && buffer[1] == 0x61 && buffer[2] == 0x72 && buffer[3] == 0x21 && buffer[4] == 0x1A && buffer[5] == 0x07)
                    return "RAR";

                // GZIP
                if (buffer[0] == 0x1F && buffer[1] == 0x8B)
                    return "GZIP";

                // CAB
                if (buffer[0] == 0x4D && buffer[1] == 0x53 && buffer[2] == 0x43 && buffer[3] == 0x46)
                    return "CAB";

                // PE (EXE/DLL)
                if (buffer[0] == 0x4D && buffer[1] == 0x5A)
                    return "PE";

                // ELF
                if (buffer[0] == 0x7F && buffer[1] == 0x45 && buffer[2] == 0x4C && buffer[3] == 0x46)
                    return "ELF";

                // DEX
                if (buffer.Length >= 8 && buffer[0] == 0x64 && buffer[1] == 0x65 && buffer[2] == 0x78 && buffer[3] == 0x0A)
                    return "DEX";

                // SQLite
                if (buffer.Length >= 16)
                {
                    var sqliteMagic = "SQLite format 3\0"u8;
                    if (buffer.Slice(0, 16).SequenceEqual(sqliteMagic))
                        return "SQLite";
                }

                // XML
                if (buffer.Length >= 5)
                {
                    var xmlMagic = "<?xml"u8;
                    if (buffer.Slice(0, 5).SequenceEqual(xmlMagic))
                        return "XML";
                }

                return "Unknown/RawEncryptedBlob"; // نوع غير معروف
            }
            catch
            {
                return "Error"; // Fail-open
            }
        }

        public static bool IsArchiveOrCompressed(ReadOnlySpan<byte> buffer)
        {
            try
            {
                string type = IdentifyFileType(buffer);
                return type == "ZIP_APK_JAR" || type == "7Z" || type == "RAR" || type == "GZIP" || type == "CAB";
            }
            catch
            {
                return false;
            }
        }
    }
}
