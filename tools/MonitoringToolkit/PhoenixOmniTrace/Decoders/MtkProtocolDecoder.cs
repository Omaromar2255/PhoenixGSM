using System;
using System.Collections.Generic;
using System.Text;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.Decoders;

/// <summary>
/// Information model for a decoded MediaTek (MTK) BROM or DA protocol event.
/// </summary>
public sealed class MtkDecodedPacket
{
    public string Stage { get; set; } = "BROM"; // BROM or DA or PRELOADER
    public byte OpCode { get; set; }
    public string CommandName { get; set; } = string.Empty;
    public string ChipName { get; set; } = string.Empty;
    public ushort HardwareCode { get; set; }
    public string Summary { get; set; } = string.Empty;
    public Dictionary<string, string> Details { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    public override string ToString()
    {
        string chip = !string.IsNullOrEmpty(ChipName) ? $" [{ChipName}]" : "";
        return $"[MTK {Stage}] {CommandName}{chip}: {Summary}";
    }
}

/// <summary>
/// LAYER 7C — MediaTek (MTK) BROM & Download Agent (DA) Protocol Decoder
/// Decodes BROM start handshake sync bytes, hardware identification requests,
/// SLA/DAA security authentication challenges, and DA flashing / partition operations.
/// </summary>
public static class MtkProtocolDecoder
{
    // BROM Handshake Sync sequences
    public static readonly byte[] BromSyncPatternHost = [0xA0, 0x0A, 0x50, 0x05];
    public static readonly byte[] BromSyncPatternDev  = [0x5F, 0xF5, 0xAF, 0xFA];

    // Known MTK Hardware Codes mapping
    private static readonly Dictionary<ushort, string> KnownChipsets = new()
    {
        [0x6572] = "MT6572",
        [0x6580] = "MT6580",
        [0x6582] = "MT6582",
        [0x6592] = "MT6592",
        [0x6735] = "MT6735",
        [0x6737] = "MT6737",
        [0x6739] = "MT6739",
        [0x6750] = "MT6750",
        [0x6752] = "MT6752",
        [0x6755] = "MT6755 (Helio P10)",
        [0x6757] = "MT6757 (Helio P20)",
        [0x0766] = "MT6762 (Helio P22 / A22)",
        [0x0768] = "MT6765 (Helio G25 / G35 / P35)",
        [0x0788] = "MT6768 (Helio G80 / G85)",
        [0x0707] = "MT6785 (Helio G90 / G95)",
        [0x0816] = "MT6833 (Dimensity 700 / 6020)",
        [0x0886] = "MT6877 (Dimensity 900 / 1080)",
        [0x0989] = "MT6893 (Dimensity 1200)",
        [0x0996] = "MT6983 (Dimensity 9000)",
        [0x8163] = "MT8163",
        [0x8167] = "MT8167",
        [0x8173] = "MT8173"
    };

    // BROM Command Table
    private static readonly Dictionary<byte, string> BromCommands = new()
    {
        [0xA0] = "BROM_SYNC_PING",
        [0x5F] = "BROM_SYNC_PONG",
        [0x0A] = "BROM_SYNC_STEP2",
        [0xF5] = "BROM_SYNC_ACK2",
        [0x50] = "BROM_SYNC_STEP3",
        [0xAF] = "BROM_SYNC_ACK3",
        [0x05] = "BROM_SYNC_STEP4",
        [0xFA] = "BROM_SYNC_ACK4",
        [0xD0] = "GET_TARGET_CONFIG",
        [0xD1] = "SEND_DA",
        [0xD2] = "JUMP_DA",
        [0xD3] = "GET_HW_SW_VER",
        [0xD4] = "GET_HW_CODE",
        [0xD5] = "SEND_EPP",
        [0xD6] = "CMD_READ16",
        [0xD7] = "CMD_WRITE16",
        [0xD8] = "CMD_READ32",
        [0xD9] = "CMD_WRITE32",
        [0xDA] = "GET_BL_VER",
        [0xDC] = "SLA_DAA_AUTH_CHALLENGE",
        [0xDD] = "CMD_PWR_INIT",
        [0xDE] = "CMD_PWR_DEINIT",
        [0xDF] = "CMD_PWR_READ16"
    };

    // DA (Download Agent) Command Table
    private static readonly Dictionary<byte, string> DaCommands = new()
    {
        [0x10] = "DA_SYNC",
        [0x11] = "DA_CONFIG_EMI",
        [0x12] = "DA_POST_PROCESS",
        [0x13] = "DA_SET_SPEED",
        [0x20] = "DA_MEM_READ",
        [0x21] = "DA_MEM_WRITE",
        [0x30] = "DA_FORMAT",
        [0x31] = "DA_ERASE",
        [0x32] = "DA_WRITE_PARTITION",
        [0x33] = "DA_READ_PARTITION",
        [0x34] = "DA_READ_PARTITION_TABLE",
        [0x35] = "DA_WRITE_PARTITION_TABLE",
        [0x38] = "DA_FRP_UNLOCK",
        [0x40] = "DA_REBOOT",
        [0x41] = "DA_SHUTDOWN",
        [0x5A] = "DA_STATUS_OK",
        [0x5B] = "DA_STATUS_FAIL",
        [0xD4] = "DA_READ_FLASH",
        [0xD5] = "DA_WRITE_FLASH",
        [0xD6] = "DA_FORMAT_STORAGE",
        [0xD8] = "DA_JUMP_EXEC"
    };

    /// <summary>
    /// Evaluates if buffer matches MediaTek BROM / PreLoader framing.
    /// </summary>
    public static double EvaluateMtk(ReadOnlySpan<byte> buf)
    {
        if (buf.Length == 0) return 0.0;

        // 1. Handshake sync sequence
        if (buf.Length >= 4)
        {
            if (buf[0] == 0xA0 && buf[1] == 0x0A && buf[2] == 0x50 && buf[3] == 0x05) return 0.99;
            if (buf[0] == 0x5F && buf[1] == 0xF5 && buf[2] == 0xAF && buf[3] == 0xFA) return 0.99;
        }

        // 2. Single-byte handshake
        if (buf.Length == 1)
        {
            byte b = buf[0];
            if (b is 0xA0 or 0x5F or 0xF5 or 0x50 or 0xAF or 0xFA) return 0.96;
            if (BromCommands.ContainsKey(b) && b is not (0x0A or 0x05)) return 0.88;
        }

        // 3. BROM command opcode
        byte op = buf[0];
        if (BromCommands.ContainsKey(op) && op is not (0x0A or 0x05))
        {
            if (op is 0xD0 or 0xD1 or 0xD2 or 0xD3 or 0xD4 or 0xDC) return 0.95;
            return 0.85;
        }

        // Guard against printable ASCII strings (like "[ro.boot...", "10-14...", "AuthKey...", "shell...")
        bool isAsciiString = buf.Length > 1 && 
                             op is >= 0x20 and <= 0x7E && 
                             buf[1] is >= 0x20 and <= 0x7E && 
                             (buf.Length < 3 || buf[2] is >= 0x20 and <= 0x7E);

        if (isAsciiString)
        {
            return 0.0;
        }

        // 4. DA stage signatures
        if (DaCommands.ContainsKey(op))
        {
            if (op is >= 0x20 and <= 0x7E)
            {
                // Printable ASCII character cannot be matched as DA command without binary framing
                return 0.0;
            }
            return 0.85;
        }

        if (buf.Length >= 4 && !isAsciiString && (buf[0] == 0x10 || buf[0] == 0x32 || buf[0] == 0x33))
        {
            return 0.82;
        }

        return 0.0;
    }

    /// <summary>
    /// Decodes an MTK protocol packet.
    /// </summary>
    public static MtkDecodedPacket? DecodePacket(ReadOnlySpan<byte> buffer, PacketDirection direction)
    {
        if (buffer.Length == 0) return null;

        // Check full 4-byte sync sequence
        if (buffer.Length >= 4)
        {
            if (buffer[0] == 0xA0 && buffer[1] == 0x0A && buffer[2] == 0x50 && buffer[3] == 0x05)
            {
                return new MtkDecodedPacket
                {
                    Stage = "BROM",
                    OpCode = 0xA0,
                    CommandName = "BROM_HANDSHAKE_START",
                    Summary = "Host initiated BROM synchronization ping sequence (0xA0 0x0A 0x50 0x05)"
                };
            }
            if (buffer[0] == 0x5F && buffer[1] == 0xF5 && buffer[2] == 0xAF && buffer[3] == 0xFA)
            {
                return new MtkDecodedPacket
                {
                    Stage = "BROM",
                    OpCode = 0x5F,
                    CommandName = "BROM_HANDSHAKE_ACK",
                    Summary = "Device acknowledged BROM synchronization (0x5F 0xF5 0xAF 0xFA - Connected)"
                };
            }
        }

        byte op = buffer[0];

        // 1. Check BROM Commands
        if (BromCommands.TryGetValue(op, out var bCmd))
        {
            var packet = new MtkDecodedPacket
            {
                Stage = "BROM",
                OpCode = op,
                CommandName = bCmd
            };

            switch (op)
            {
                case 0xA0:
                    packet.Summary = direction == PacketDirection.HOST_TO_DEVICE
                        ? "BROM Handshake Sync Step 1 (Ping 0xA0)"
                        : "BROM Handshake Sync Step 1 Echo";
                    break;

                case 0x5F:
                    packet.Summary = "Device acknowledged BROM Handshake Sync Step 1 (0x5F)";
                    break;

                case 0x0A:
                    packet.Summary = "BROM Handshake Sync Step 2 (0x0A)";
                    break;

                case 0xF5:
                    packet.Summary = "Device acknowledged BROM Handshake Sync Step 2 (0xF5)";
                    break;

                case 0x50:
                    packet.Summary = "BROM Handshake Sync Step 3 (0x50)";
                    break;

                case 0xAF:
                    packet.Summary = "Device acknowledged BROM Handshake Sync Step 3 (0xAF)";
                    break;

                case 0x05:
                    packet.Summary = "BROM Handshake Sync Step 4 (0x05)";
                    break;

                case 0xFA:
                    packet.Summary = "Device acknowledged BROM Handshake Sync Step 4 (0xFA - Connected!)";
                    break;

                case 0xD4: // GET_HW_CODE
                    packet.Summary = direction == PacketDirection.HOST_TO_DEVICE
                        ? "Querying Target Chipset Hardware Code"
                        : ParseHwCodeResponse(buffer, packet);
                    break;

                case 0xDC: // SLA / DAA Challenge
                    packet.Summary = direction == PacketDirection.HOST_TO_DEVICE
                        ? "Initiating SLA/DAA Security Authentication / Auth Bypass handshake"
                        : "Device returned SLA/DAA Challenge token";
                    break;

                case 0xD1: // SEND_DA
                    packet.Summary = direction == PacketDirection.HOST_TO_DEVICE
                        ? "Transmitting Download Agent (DA) binary into device SRAM"
                        : "Device acknowledged DA binary staging";
                    break;

                case 0xD2: // JUMP_DA
                    packet.Summary = "Executing DA entry point in SRAM/DRAM";
                    break;

                case 0xD0: // GET_TARGET_CONFIG
                    packet.Summary = "Reading target hardware configuration & security flags";
                    break;

                case 0xD3: // GET_HW_SW_VER
                    packet.Summary = "Reading hardware and BROM software sub-version";
                    break;

                default:
                    packet.Summary = $"BROM Opcode 0x{op:X2} ({bCmd})";
                    break;
            }

            packet.Details["OpCode"] = $"0x{op:X2}";
            packet.Details["Command"] = bCmd;
            return packet;
        }

        // 2. Check DA Commands
        if (DaCommands.TryGetValue(op, out var daCmd))
        {
            var packet = new MtkDecodedPacket
            {
                Stage = "DA",
                OpCode = op,
                CommandName = daCmd,
                Summary = $"DA Command: {daCmd}"
            };

            // Scan for partition text in buffer
            string ascii = Encoding.ASCII.GetString(buffer[..Math.Min(buffer.Length, 64)]);
            foreach (var part in new[] { "boot", "recovery", "nvram", "nvdata", "protect1", "protect2", "frp", "md1img", "super", "userdata", "system" })
            {
                if (ascii.Contains(part, StringComparison.OrdinalIgnoreCase))
                {
                    packet.Summary += $" (Partition: {part})";
                    packet.Details["TargetPartition"] = part;
                    break;
                }
            }

            packet.Details["OpCode"] = $"0x{op:X2}";
            packet.Details["Command"] = daCmd;
            return packet;
        }

        // 3. Fallback: Generic MTK Packet
        return new MtkDecodedPacket
        {
            Stage = "MTK",
            OpCode = op,
            CommandName = $"RAW_0x{op:X2}",
            Summary = $"MediaTek frame ({buffer.Length} bytes)"
        };
    }

    private static string ParseHwCodeResponse(ReadOnlySpan<byte> buf, MtkDecodedPacket packet)
    {
        if (buf.Length >= 4)
        {
            // Response typically 2-byte HW code + status
            ushort hwCode = (ushort)((buf[1] << 8) | buf[2]);
            if (hwCode == 0 && buf.Length >= 5) hwCode = (ushort)((buf[2] << 8) | buf[3]);

            if (hwCode != 0)
            {
                packet.HardwareCode = hwCode;
                string name = KnownChipsets.TryGetValue(hwCode, out var cName) ? cName : $"MT0x{hwCode:X4}";
                packet.ChipName = name;
                packet.Details["HardwareCode"] = $"0x{hwCode:X4}";
                packet.Details["Chipset"] = name;
                return $"Chipset Identified: {name} (HW Code: 0x{hwCode:X4})";
            }
        }
        return "Target Chipset Hardware Code response";
    }
}
