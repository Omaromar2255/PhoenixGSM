using System;
using System.Text;

namespace PhoenixGSM.MonitoringStudio.Models;

public enum EventSourceCategory
{
    All,
    PhoneCommands, // Dedicated Pipeline for Host-to-Device commands only
    UsbDriver,
    AdbProxy,
    SerialPort,
    Process,
    NetworkUrl,
    TempFileAt,
    Mtp,
    MediaTek,
    UnisocSpd,
    QualcommEdl,
    InProcess,
    AppleIos,
    ArtifactVault,
    Cmd,
    Shell,
    ToolSource
}

public class LiveEventItem
{
    public int Id { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string TimeFormatted => Timestamp.ToLocalTime().ToString("HH:mm:ss.fff");

    public EventSourceCategory Category { get; set; }
    public string SourceTag { get; set; } = "SYS";
    public string Direction { get; set; } = "--";
    public string EndpointOrTarget { get; set; } = "";
    public string Protocol { get; set; } = "UNKNOWN";
    public string Command { get; set; } = "";
    public string Summary { get; set; } = "";
    public byte[]? RawPayload { get; set; }
    public string PayloadAscii { get; set; } = "";
    public string PayloadHex { get; set; } = "";
    public string AdditionalDetails { get; set; } = "";

    // Badge styling colors
    public string BadgeBackground => Category switch
    {
        EventSourceCategory.PhoneCommands => "#0D3326", // Deep Emerald
        EventSourceCategory.UsbDriver => "#003B5C",
        EventSourceCategory.AdbProxy => "#004D36",
        EventSourceCategory.SerialPort => "#4D3B00",
        EventSourceCategory.Process => "#3B004D",
        EventSourceCategory.NetworkUrl => "#4A154B", // Deep Magenta
        EventSourceCategory.TempFileAt => "#4A2800", // Dark Amber / Ochre
        EventSourceCategory.Mtp => "#002B4D",        // Deep Sapphire Blue
        EventSourceCategory.MediaTek => "#4A1C00",   // Dark Amber/Rust
        EventSourceCategory.UnisocSpd => "#38004A",  // Deep Violet
        EventSourceCategory.QualcommEdl => "#4A000A",// Deep Crimson
        EventSourceCategory.InProcess => "#00363A",  // Deep Cyan/Teal
        EventSourceCategory.Cmd => "#212121",        // Dark Grey / CMD
        EventSourceCategory.Shell => "#1B2A10",      // Dark Olive / Shell
        EventSourceCategory.ToolSource => "#003D3D", // Deep Teal / Tool Source
        _ => "#2B303C"
    };

    public string BadgeForeground => Category switch
    {
        EventSourceCategory.PhoneCommands => "#00FFC2", // Vivid Neon Aqua / Emerald
        EventSourceCategory.UsbDriver => "#00E5FF",  // Neon Cyan
        EventSourceCategory.AdbProxy => "#00FF9D",   // Neon Emerald
        EventSourceCategory.SerialPort => "#FFC800", // Amber Gold
        EventSourceCategory.Process => "#E066FF",    // Bright Violet
        EventSourceCategory.NetworkUrl => "#FF007F", // Neon Rose / Hot Pink
        EventSourceCategory.TempFileAt => "#FF9100", // Vibrant Tangerine / Amber
        EventSourceCategory.Mtp => "#00B0FF",        // Electric Blue / MTP
        EventSourceCategory.MediaTek => "#FF6D00",   // Vivid Orange / MTK
        EventSourceCategory.UnisocSpd => "#E040FB",  // Electric Neon Purple / SPD
        EventSourceCategory.QualcommEdl => "#FF1744",// Electric Crimson / EDL
        EventSourceCategory.InProcess => "#00E5FF",  // Bright Cyan / In-Process
        EventSourceCategory.Cmd => "#FFFFFF",        // White / CMD
        EventSourceCategory.Shell => "#A5D6A7",      // Light Green / Shell
        EventSourceCategory.ToolSource => "#00FFE5", // Vivid Neon Teal / Cyan
        _ => "#A0AAB8"
    };

    public string DirectionForeground => Direction.Trim().ToUpper() switch
    {
        "OUT" or "HOST->DEV" or ">>" => "#00E5FF", // Neon Cyan for host commands / stdin
        "IN" or "DEV->HOST" or "<<" => "#00FF9D",  // Neon Emerald for device responses / stdout
        "WEB" or "URL" => "#FF007F",                // Neon Rose for web/URL downloads
        "FILE >>" or "FILE" => "#FF9100",           // Vibrant Tangerine for File AT staging
        "INTERNAL" or "IN-PROC" => "#00E5FF",       // Bright Cyan for internal in-process calls
        _ => "#A0AAB8"
    };

    public static string FormatHexDump(byte[] data)
    {
        if (data == null || data.Length == 0) return "(Empty Payload)";

        var sb = new StringBuilder();
        int length = Math.Min(data.Length, 65536); // Cap at 64KB for high-fidelity un-truncated preview

        for (int i = 0; i < length; i += 16)
        {
            sb.Append($"{i:X4}  ");

            // Hex bytes
            for (int j = 0; j < 16; j++)
            {
                if (i + j < length)
                    sb.Append($"{data[i + j]:X2} ");
                else
                    sb.Append("   ");

                if (j == 7) sb.Append(" ");
            }

            sb.Append(" |");

            // ASCII characters
            for (int j = 0; j < 16 && (i + j) < length; j++)
            {
                byte b = data[i + j];
                char c = (b >= 32 && b <= 126) ? (char)b : '.';
                sb.Append(c);
            }

            sb.Append("|\n");
        }

        if (data.Length > length)
        {
            sb.Append($"\n... [{data.Length - length:N0} more bytes truncated for preview - Total size: {data.Length:N0} bytes]");
        }

        return sb.ToString();
    }
}
