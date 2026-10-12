using System;

namespace PhoenixGSM.OmniTrace.MemoryForensics
{
    public class ShellcodePatternMatcher
    {
        // فحص الأنماط للبحث عن شفرات ضارة - Scan patterns for malicious shellcode
        public bool MatchShellcodeHeuristics(ReadOnlySpan<byte> buffer, out string patternName)
        {
            patternName = string.Empty;
            try
            {
                if (buffer.Length < 10) return false;

                // 1. NOP Sled detection (long sequence of 0x90)
                int nopCount = 0;
                for (int i = 0; i < buffer.Length; i++)
                {
                    if (buffer[i] == 0x90) nopCount++;
                    else nopCount = 0;

                    if (nopCount >= 20)
                    {
                        patternName = "NOP Sled (0x90 sequence)";
                        return true;
                    }
                }

                // 2. Call/Pop getPC pattern (e.g., E8 00 00 00 00 58)
                for (int i = 0; i < buffer.Length - 5; i++)
                {
                    if (buffer[i] == 0xE8 && buffer[i+1] == 0x00 && buffer[i+2] == 0x00 && 
                        buffer[i+3] == 0x00 && buffer[i+4] == 0x00 && buffer[i+5] == 0x58)
                    {
                        patternName = "Call/Pop getPC Pattern";
                        return true;
                    }
                }

                // 3. Common Metasploit payload headers (example MZ stub or specific bytes)
                // Just an example check
                if (buffer[0] == 0xFC && buffer[1] == 0xE8)
                {
                    patternName = "Suspicious MSF-like Header (FC E8)";
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                // منع التوقف المفاجئ - Prevent crash
                Console.WriteLine($"[ShellcodePatternMatcher] Error: {ex.Message}");
                return false;
            }
        }
    }
}
