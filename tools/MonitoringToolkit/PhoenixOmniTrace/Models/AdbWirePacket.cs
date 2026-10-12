using System;
using System.Text;

namespace PhoenixGSM.OmniTrace.Models;

public sealed class AdbWirePacket
{
    public const uint A_CNXN = 0x4e584e43;
    public const uint A_AUTH = 0x48545541;
    public const uint A_OPEN = 0x4e45504f;
    public const uint A_OKAY = 0x59414b4f;
    public const uint A_CLSE = 0x45534c43;
    public const uint A_WRTE = 0x45545257;

    public uint Command { get; set; }
    public string CommandName { get; set; } = string.Empty;
    public uint Arg0 { get; set; }
    public uint Arg1 { get; set; }
    public uint DataLength { get; set; }
    public uint DataCheck { get; set; }
    public uint Magic { get; set; }
    public byte[] Payload { get; set; } = Array.Empty<byte>();

    public bool IsValid => (Command ^ 0xFFFFFFFF) == Magic;

    public static string GetCommandName(uint cmd) => cmd switch
    {
        A_CNXN => "CNXN",
        A_AUTH => "AUTH",
        A_OPEN => "OPEN",
        A_OKAY => "OKAY",
        A_CLSE => "CLSE",
        A_WRTE => "WRTE",
        _ => $"UNKNOWN(0x{cmd:X8})"
    };

    public static byte[] BuildPacket(uint cmd, uint arg0, uint arg1, byte[]? payload = null)
    {
        uint len = (uint)(payload?.Length ?? 0);
        uint check = 0;
        if (payload != null)
        {
            foreach (byte b in payload) check += b;
        }
        uint magic = cmd ^ 0xFFFFFFFF;

        byte[] pkt = new byte[24 + len];
        BitConverter.GetBytes(cmd).CopyTo(pkt, 0);
        BitConverter.GetBytes(arg0).CopyTo(pkt, 4);
        BitConverter.GetBytes(arg1).CopyTo(pkt, 8);
        BitConverter.GetBytes(len).CopyTo(pkt, 12);
        BitConverter.GetBytes(check).CopyTo(pkt, 16);
        BitConverter.GetBytes(magic).CopyTo(pkt, 20);

        if (payload != null && len > 0)
        {
            Array.Copy(payload, 0, pkt, 24, (int)len);
        }

        return pkt;
    }

    public override string ToString()
    {
        return $"[{CommandName} Arg0=0x{Arg0:X8} Arg1=0x{Arg1:X8} Len={DataLength}]";
    }
}
