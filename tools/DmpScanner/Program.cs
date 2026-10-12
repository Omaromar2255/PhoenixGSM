using System;

class BcdDecoder
{
    static void Main()
    {
        string hex = "421F0100421F0200421F0300421F0400421F1000421F1100";
        Console.WriteLine("Raw Hex: " + hex);

        // Let's decode each 8-byte or 4-byte MCC-MNC chunk
        // 421F0100 (4 bytes = 8 hex chars)
        for (int i = 0; i < hex.Length; i += 8)
        {
            string chunk = hex.Substring(i, 8);
            Console.WriteLine($"Chunk: {chunk}");
        }
    }
}
