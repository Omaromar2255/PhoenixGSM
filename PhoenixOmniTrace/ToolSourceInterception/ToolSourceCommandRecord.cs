using System;
using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;

namespace PhoenixGSM.OmniTrace.ToolSourceInterception;

/// <summary>
/// Forensic record of a command captured directly from the tool/program source
/// across MTP, MTK, Odin, and Port modes before channel encapsulation.
/// سجل جنائي لأمر تم التقاطه من مصدر الأداة مباشرة
/// </summary>
public sealed class ToolSourceCommandRecord : INotifyPropertyChanged
{
    public long Id { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string TimeFormatted => Timestamp.ToLocalTime().ToString("HH:mm:ss.fff");

    /// <summary>
    /// Target operating mode (MTP, MTK BROM, Odin, Serial Port, etc.)
    /// </summary>
    public ToolSourceMode Mode { get; set; } = ToolSourceMode.Universal;
    public string ModeName => Mode switch
    {
        ToolSourceMode.Mtp => "MTP",
        ToolSourceMode.MtkBrom => "MTK BROM",
        ToolSourceMode.SamsungOdin => "ODIN",
        ToolSourceMode.SerialPort => "PORT/COM",
        ToolSourceMode.QualcommEdl => "QCOM EDL",
        ToolSourceMode.UnisocSpd => "SPD FDL",
        _ => "TOOL-SRC"
    };

    /// <summary>
    /// Executable name of the originating tool (e.g. UnlockTool.exe, Odin3.exe, Chimera.exe)
    /// </summary>
    public string ToolName { get; set; } = "UnknownTool";

    /// <summary>
    /// Process ID (PID) of the tool.
    /// </summary>
    public int ProcessId { get; set; }

    /// <summary>
    /// Parent Process ID (PPID) of the tool.
    /// </summary>
    public int ParentProcessId { get; set; }

    /// <summary>
    /// Cleaned, parsed command or action name directed to the device.
    /// </summary>
    public string PureCommand { get; set; } = string.Empty;

    /// <summary>
    /// Raw unparsed command or packet summary.
    /// </summary>
    public string RawCommand { get; set; } = string.Empty;

    /// <summary>
    /// API interception mechanism (e.g. DeviceIoControl, libusb_bulk_transfer, WriteFile_COM, WinUsb_WritePipe)
    /// </summary>
    public string InterceptMechanism { get; set; } = "API-HOOK";

    /// <summary>
    /// Target port, handle, or USB endpoint (e.g. \\.\COM5, USB\VID_0E8D&PID_0003, LokePort)
    /// </summary>
    public string TargetEndpoint { get; set; } = string.Empty;

    /// <summary>
    /// Raw payload bytes of the command.
    /// </summary>
    public byte[]? RawPayload { get; set; }

    /// <summary>
    /// Formatted Hex Dump representation of payload.
    /// </summary>
    public string PayloadHex { get; set; } = string.Empty;

    /// <summary>
    /// Printable ASCII representation of payload.
    /// </summary>
    public string PayloadAscii { get; set; } = string.Empty;

    /// <summary>
    /// Comprehensive forensic and technical context.
    /// </summary>
    public string TechnicalDetails { get; set; } = string.Empty;

    /// <summary>
    /// Evaluated security / operational risk level (INFO, WARNING, CRITICAL)
    /// </summary>
    public string RiskLevel { get; set; } = "INFO";

    /// <summary>
    /// Current capture status (e.g. CAPTURED_AT_SOURCE)
    /// </summary>
    public string Status { get; set; } = "CAPTURED_AT_SOURCE";

    /// <summary>
    /// Size of payload in bytes.
    /// </summary>
    public int PayloadSize => RawPayload?.Length ?? 0;

    // ══════════════════════════════════════════════════════════════
    // UI BADGE COLORS & STYLING (WPF Binding)
    // ══════════════════════════════════════════════════════════════

    public string ModeBadgeBackground => Mode switch
    {
        ToolSourceMode.Mtp => "#002B4D",        // Deep Sapphire Blue
        ToolSourceMode.MtkBrom => "#4A1C00",    // Dark Amber / Rust
        ToolSourceMode.SamsungOdin => "#0D2E1C",// Deep Forest Emerald
        ToolSourceMode.SerialPort => "#4D3B00", // Dark Amber Gold
        ToolSourceMode.QualcommEdl => "#4A000A",// Deep Crimson
        ToolSourceMode.UnisocSpd => "#38004A",  // Deep Violet
        _ => "#171C28"
    };

    public string ModeBadgeForeground => Mode switch
    {
        ToolSourceMode.Mtp => "#00B0FF",        // Electric Cyan Blue
        ToolSourceMode.MtkBrom => "#FF6D00",    // Vivid Orange MTK
        ToolSourceMode.SamsungOdin => "#00FF9D",// Neon Emerald Odin
        ToolSourceMode.SerialPort => "#FFC800", // Gold Serial/COM
        ToolSourceMode.QualcommEdl => "#FF1744",// Electric Crimson
        ToolSourceMode.UnisocSpd => "#E040FB",  // Electric Violet
        _ => "#00E5FF"
    };

    public string RiskColor => RiskLevel switch
    {
        "CRITICAL" => "#FF1744", // Bright Red
        "WARNING" => "#FFC800",  // Amber Gold
        _ => "#00FF9D"           // Neon Green
    };

    public string RiskBackground => RiskLevel switch
    {
        "CRITICAL" => "#3D0A12",
        "WARNING" => "#362705",
        _ => "#082618"
    };

    public string InterceptBadgeForeground => InterceptMechanism switch
    {
        "DeviceIoControl" => "#00E5FF",
        "libusb_bulk_transfer" => "#FF6D00",
        "WinUsb_WritePipe" => "#E040FB",
        "WriteFile_COM" => "#FFC800",
        "ETW_KernelIo" => "#00FF9D",
        _ => "#A0AAB8"
    };

    public static string ComputeSha256(byte[] data)
    {
        if (data == null || data.Length == 0) return string.Empty;
        using var sha = SHA256.Create();
        return Convert.ToHexString(sha.ComputeHash(data));
    }

    public static string FormatHexDump(byte[]? data)
    {
        if (data == null || data.Length == 0) return "(Empty Payload)";

        var sb = new StringBuilder();
        int length = Math.Min(data.Length, 65536);

        for (int i = 0; i < length; i += 16)
        {
            sb.Append($"{i:X4}  ");
            for (int j = 0; j < 16; j++)
            {
                if (i + j < length)
                    sb.Append($"{data[i + j]:X2} ");
                else
                    sb.Append("   ");

                if (j == 7) sb.Append(" ");
            }

            sb.Append(" |");
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
            sb.Append($"\n... [{data.Length - length:N0} more bytes truncated for preview - Total: {data.Length:N0} bytes]");
        }

        return sb.ToString();
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged(string propertyName) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}
