using System;
using System.Collections.Generic;
using System.Text;
using PhoenixGSM.UsbMonitor.Models;
using PhoenixGSM.UsbMonitor.Protocol;

namespace PhoenixGSM.UsbMonitor;

public static class AdbProtocolTests
{
    public static bool RunAllTests()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("+========================================================================+");
        Console.WriteLine("|                 PhoenixGSM — ADB Protocol Parser Tests                 |");
        Console.WriteLine("+========================================================================+");
        Console.ResetColor();

        int passed = 0;
        int total = 0;

        total++; if (TestSingleFrame()) passed++;
        total++; if (TestMultipleFramesInSingleChunk()) passed++;
        total++; if (TestPayloadFragmentation()) passed++;
        total++; if (TestHeaderFragmentation()) passed++;
        total++; if (TestAuthSecretRedaction()) passed++;
        total++; if (TestResyncOnGarbageBytes()) passed++;
        total++; if (TestFullLifecycleSequence()) passed++;

        Console.WriteLine();
        if (passed == total)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  [PASSED] All {passed}/{total} ADB protocol parser tests passed successfully!\n");
            Console.ResetColor();
            return true;
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  [FAILED] {total - passed}/{total} tests failed!\n");
            Console.ResetColor();
            return false;
        }
    }

    private static byte[] BuildAdbPacket(uint cmd, uint arg0, uint arg1, byte[]? payload = null)
    {
        uint dataLen = (uint)(payload?.Length ?? 0);
        uint dataCheck = 0;
        if (payload != null)
        {
            foreach (var b in payload) dataCheck += b;
        }
        uint magic = cmd ^ 0xFFFFFFFF;

        byte[] packet = new byte[24 + dataLen];
        Array.Copy(BitConverter.GetBytes(cmd), 0, packet, 0, 4);
        Array.Copy(BitConverter.GetBytes(arg0), 0, packet, 4, 4);
        Array.Copy(BitConverter.GetBytes(arg1), 0, packet, 8, 4);
        Array.Copy(BitConverter.GetBytes(dataLen), 0, packet, 12, 4);
        Array.Copy(BitConverter.GetBytes(dataCheck), 0, packet, 16, 4);
        Array.Copy(BitConverter.GetBytes(magic), 0, packet, 20, 4);

        if (payload != null && dataLen > 0)
        {
            Array.Copy(payload, 0, packet, 24, (int)dataLen);
        }

        return packet;
    }

    private static bool TestSingleFrame()
    {
        var parser = new AdbProtocolParser();
        var payload = Encoding.UTF8.GetBytes("host::features=shell_v2,cmd\0");
        var raw = BuildAdbPacket(AdbProtocolParser.A_CNXN, 0x01000000, 262144, payload);

        var frames = parser.ProcessChunk(raw, "OUT");
        bool ok = frames.Count == 1 &&
                  frames[0].Command == "CNXN" &&
                  frames[0].Arg0 == 0x01000000 &&
                  frames[0].Arg1 == 262144 &&
                  frames[0].DataLength == payload.Length;

        PrintTestResult("Single CNXN Frame Decoding", ok);
        return ok;
    }

    private static bool TestMultipleFramesInSingleChunk()
    {
        var parser = new AdbProtocolParser();
        // Frame 1: OKAY (24 bytes)
        var pkt1 = BuildAdbPacket(AdbProtocolParser.A_OKAY, 1, 2);
        // Frame 2: WRTE (24 bytes + payload)
        var payload2 = Encoding.UTF8.GetBytes("PHOENIX_TEST\n");
        var pkt2 = BuildAdbPacket(AdbProtocolParser.A_WRTE, 1, 2, payload2);

        // Concatenate into one single USB transfer
        byte[] combined = new byte[pkt1.Length + pkt2.Length];
        Array.Copy(pkt1, 0, combined, 0, pkt1.Length);
        Array.Copy(pkt2, 0, combined, pkt1.Length, pkt2.Length);

        var frames = parser.ProcessChunk(combined, "IN");
        bool ok = frames.Count == 2 &&
                  frames[0].Command == "OKAY" &&
                  frames[1].Command == "WRTE" &&
                  frames[1].PayloadPreview?.Contains("PHOENIX_TEST") == true;

        PrintTestResult("Multiple Frames in Single USB Transfer", ok);
        return ok;
    }

    private static bool TestPayloadFragmentation()
    {
        var parser = new AdbProtocolParser();
        var payload = Encoding.UTF8.GetBytes("shell:echo PHOENIX_TEST\0");
        var fullPacket = BuildAdbPacket(AdbProtocolParser.A_OPEN, 100, 0, payload);

        // Split packet across 2 separate USB chunks
        // Chunk 1: Header (24 bytes) + first 5 bytes of payload
        byte[] chunk1 = new byte[29];
        Array.Copy(fullPacket, 0, chunk1, 0, 29);

        // Chunk 2: Remaining bytes of payload
        byte[] chunk2 = new byte[fullPacket.Length - 29];
        Array.Copy(fullPacket, 29, chunk2, 0, chunk2.Length);

        var frames1 = parser.ProcessChunk(chunk1, "OUT");
        var frames2 = parser.ProcessChunk(chunk2, "OUT");

        bool ok = frames1.Count == 0 && // Should buffer while incomplete
                  frames2.Count == 1 && // Should emit when reassembly completes
                  frames2[0].Command == "OPEN" &&
                  frames2[0].PayloadPreview?.Contains("shell:echo PHOENIX_TEST") == true;

        PrintTestResult("Payload Fragmentation Across Multiple Transfers", ok);
        return ok;
    }

    private static bool TestHeaderFragmentation()
    {
        var parser = new AdbProtocolParser();
        var fullPacket = BuildAdbPacket(AdbProtocolParser.A_CLSE, 100, 200);

        // Split header across 2 USB transfers: 16 bytes, then 8 bytes
        byte[] chunk1 = new byte[16];
        byte[] chunk2 = new byte[8];
        Array.Copy(fullPacket, 0, chunk1, 0, 16);
        Array.Copy(fullPacket, 16, chunk2, 0, 8);

        var frames1 = parser.ProcessChunk(chunk1, "OUT");
        var frames2 = parser.ProcessChunk(chunk2, "OUT");

        bool ok = frames1.Count == 0 &&
                  frames2.Count == 1 &&
                  frames2[0].Command == "CLSE" &&
                  frames2[0].Arg0 == 100 &&
                  frames2[0].Arg1 == 200;

        PrintTestResult("Header Fragmentation Split Across Transfers", ok);
        return ok;
    }

    private static bool TestAuthSecretRedaction()
    {
        var parser = new AdbProtocolParser();
        byte[] secretToken = new byte[20];
        new Random(42).NextBytes(secretToken);
        var raw = BuildAdbPacket(AdbProtocolParser.A_AUTH, 1, 0, secretToken);

        var frames = parser.ProcessChunk(raw, "IN");
        bool ok = frames.Count == 1 &&
                  frames[0].Command == "AUTH" &&
                  frames[0].PayloadPreview is { } preview &&
                  preview.Contains("REDACTED") &&
                  !preview.Contains(BitConverter.ToString(secretToken));

        PrintTestResult("Security: Authentication Secret Redaction", ok);
        return ok;
    }

    private static bool TestResyncOnGarbageBytes()
    {
        var parser = new AdbProtocolParser();
        byte[] garbage = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03 };
        var validPacket = BuildAdbPacket(AdbProtocolParser.A_OKAY, 5, 10);

        byte[] noisy = new byte[garbage.Length + validPacket.Length];
        Array.Copy(garbage, 0, noisy, 0, garbage.Length);
        Array.Copy(validPacket, 0, noisy, garbage.Length, validPacket.Length);

        var frames = parser.ProcessChunk(noisy, "IN");
        bool ok = frames.Count == 1 &&
                  frames[0].Command == "OKAY" &&
                  frames[0].Arg0 == 5 &&
                  frames[0].Arg1 == 10;

        PrintTestResult("Stream Resynchronization on Corrupt Prefix", ok);
        return ok;
    }

    private static bool TestFullLifecycleSequence()
    {
        var parser = new AdbProtocolParser();
        var allFrames = new List<AdbUsbFrame>();

        // 1. Host sends CNXN
        allFrames.AddRange(parser.ProcessChunk(BuildAdbPacket(AdbProtocolParser.A_CNXN, 0x01000000, 262144, Encoding.UTF8.GetBytes("host::\0")), "OUT"));
        // 2. Device responds with CNXN
        allFrames.AddRange(parser.ProcessChunk(BuildAdbPacket(AdbProtocolParser.A_CNXN, 0x01000000, 262144, Encoding.UTF8.GetBytes("device::ro.product.model=SM-S908B\0")), "IN"));
        // 3. Host sends OPEN shell:getprop
        allFrames.AddRange(parser.ProcessChunk(BuildAdbPacket(AdbProtocolParser.A_OPEN, 1, 0, Encoding.UTF8.GetBytes("shell:getprop\0")), "OUT"));
        // 4. Device responds OKAY
        allFrames.AddRange(parser.ProcessChunk(BuildAdbPacket(AdbProtocolParser.A_OKAY, 2, 1), "IN"));
        // 5. Device sends WRTE
        allFrames.AddRange(parser.ProcessChunk(BuildAdbPacket(AdbProtocolParser.A_WRTE, 2, 1, Encoding.UTF8.GetBytes("[ro.build.version.release]: [13]\n")), "IN"));
        // 6. Device sends CLSE
        allFrames.AddRange(parser.ProcessChunk(BuildAdbPacket(AdbProtocolParser.A_CLSE, 2, 1), "IN"));

        bool ok = allFrames.Count == 6 &&
                  allFrames[0].Command == "CNXN" &&
                  allFrames[1].Command == "CNXN" &&
                  allFrames[2].Command == "OPEN" &&
                  allFrames[3].Command == "OKAY" &&
                  allFrames[4].Command == "WRTE" &&
                  allFrames[5].Command == "CLSE";

        PrintTestResult("Full ADB Lifecycle Sequence Emulation", ok);
        return ok;
    }

    private static void PrintTestResult(string name, bool passed)
    {
        if (passed)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  [+] PASS: {name}");
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  [!] FAIL: {name}");
        }
        Console.ResetColor();
    }
}
