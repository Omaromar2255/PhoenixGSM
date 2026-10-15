using System;
using System.Collections.Generic;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.Decoders;

/// <summary>
/// LAYER 8 — ADB Wire Protocol Decoder
/// Parses CNXN, AUTH, OPEN, OKAY, WRTE, CLSE.
/// Respects transport framing boundaries: avoids blind readPos++ scanning on invalid streams.
/// Safely handles fragmentation and coalescing.
/// </summary>
public sealed class AdbWireDecoder
{
    public const int HeaderSize = 24;

    public List<AdbWirePacket> DecodePackets(byte[] streamData, out int bytesConsumed)
    {
        var packets = new List<AdbWirePacket>();
        bytesConsumed = 0;

        if (streamData == null || streamData.Length < HeaderSize)
        {
            return packets;
        }

        int offset = 0;
        int max = streamData.Length;

        while (offset + HeaderSize <= max)
        {
            uint cmd = BitConverter.ToUInt32(streamData, offset);
            uint arg0 = BitConverter.ToUInt32(streamData, offset + 4);
            uint arg1 = BitConverter.ToUInt32(streamData, offset + 8);
            uint dataLen = BitConverter.ToUInt32(streamData, offset + 12);
            uint dataCheck = BitConverter.ToUInt32(streamData, offset + 16);
            uint magic = BitConverter.ToUInt32(streamData, offset + 20);

            // Verify ADB Wire magic: (cmd ^ 0xFFFFFFFF) == magic
            if ((cmd ^ 0xFFFFFFFF) != magic)
            {
                // Magic check failed: transport boundary does not align with ADB wire header.
                // Stop parsing immediately to preserve raw stream without blind readPos++ skipping.
                break;
            }

            // Bound validation: Android ADB max transfer is bounded (typically 256KB to 1MB)
            if (dataLen > 16 * 1024 * 1024)
            {
                // Malformed / impossible length
                break;
            }

            // Check if full payload is present in reassembly buffer
            if (offset + HeaderSize + dataLen <= max)
            {
                byte[] payload = new byte[dataLen];
                if (dataLen > 0)
                {
                    Array.Copy(streamData, offset + HeaderSize, payload, 0, (int)dataLen);
                }

                var pkt = new AdbWirePacket
                {
                    Command = cmd,
                    CommandName = AdbWirePacket.GetCommandName(cmd),
                    Arg0 = arg0,
                    Arg1 = arg1,
                    DataLength = dataLen,
                    DataCheck = dataCheck,
                    Magic = magic,
                    Payload = payload
                };

                packets.Add(pkt);
                offset += HeaderSize + (int)dataLen;
                bytesConsumed = offset;
            }
            else
            {
                // Header is valid, but payload is fragmented/incomplete.
                // Leave unconsumed in reassembly buffer to await remaining bytes.
                break;
            }
        }

        return packets;
    }
}
