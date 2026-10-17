using System;
using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;

namespace PhoenixGSM.OmniTrace.TechnicianAudit;

/// <summary>
/// Immutable forensic record of an intercepted command sent from the technician's PC to the client's phone.
/// </summary>
public sealed class TechnicianAuditRecord : INotifyPropertyChanged
{
    public long Id { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string TimeFormatted => Timestamp.ToLocalTime().ToString("HH:mm:ss.fff");

    /// <summary>
    /// Protocol of communication (e.g. ADB-SHELL, AT-MODEM, MTK-BROM, MTK-DA, QCOM-EDL, SPD-FDL, APPLE-IOS, FASTBOOT, SERIAL-RAW, USB-URB).
    /// </summary>
    public string Protocol { get; set; } = "UNKNOWN";

    /// <summary>
    /// Physical or logical operating mode of the client's mobile device
    /// (e.g. Normal / ADB, Recovery, Fastboot, Bootloader, MTK BROM, Preloader, Qualcomm 9008 EDL, Unisoc FDL, Apple DFU, Apple Recovery, Modem / Diag).
    /// </summary>
    public string Mode { get; set; } = "Normal";

    /// <summary>
    /// Pure, cleaned executable command or payload directed to the phone without framing, tokens, or noise.
    /// </summary>
    public string PureCommand { get; set; } = string.Empty;

    /// <summary>
    /// Original raw command string or representation before parsing.
    /// </summary>
    public string RawCommand { get; set; } = string.Empty;

    /// <summary>
    /// Target phone interface, port, or connection identifier (e.g. COM15, USB#VID_0E8D&PID_0003, ADB:R58M..., /dev/ttyUSB0).
    /// </summary>
    public string TargetDeviceOrPort { get; set; } = string.Empty;

    /// <summary>
    /// Name of the technician's servicing tool or process that sent the command (e.g. UnlockTool.exe, Chimera.exe, TFTUnlock.exe, adb.exe).
    /// </summary>
    public string TechnicianTool { get; set; } = "Unknown";

    /// <summary>
    /// Process ID (PID) of the technician's tool.
    /// </summary>
    public int TechnicianProcessId { get; set; }

    /// <summary>
    /// Direction of packet: HOST ➔ DEVICE (Command) or DEVICE ➔ HOST (Phone Response).
    /// </summary>
    public string Direction { get; set; } = "HOST ➔ DEVICE";

    /// <summary>
    /// Indicates whether this record is an incoming response from the phone (DEVICE ➔ HOST).
    /// </summary>
    public bool IsResponse { get; set; } = false;

    /// <summary>
    /// If this record is a response, the ID of the command that prompted it.
    /// </summary>
    public long? RelatedCommandId { get; set; }

    private string? _relatedCommandText;
    /// <summary>
    /// If this record is a response, the clean text of the command that prompted it.
    /// </summary>
    public string? RelatedCommandText
    {
        get => _relatedCommandText;
        set
        {
            if (_relatedCommandText != value)
            {
                _relatedCommandText = value;
                OnPropertyChanged(nameof(RelatedCommandText));
                OnPropertyChanged(nameof(HasPairedData));
                OnPropertyChanged(nameof(PairedPayload));
            }
        }
    }

    private string? _deviceResponse;
    /// <summary>
    /// If this record is a command and a response was captured from the phone, the response text.
    /// </summary>
    public string? DeviceResponse
    {
        get => _deviceResponse;
        set
        {
            if (_deviceResponse != value)
            {
                _deviceResponse = value;
                OnPropertyChanged(nameof(DeviceResponse));
                OnPropertyChanged(nameof(HasPairedData));
                OnPropertyChanged(nameof(PairedPayload));
            }
        }
    }

    /// <summary>
    /// Timestamp when the phone response was received (if paired with this command).
    /// </summary>
    public DateTime? ResponseTimestamp { get; set; }

    /// <summary>
    /// Raw payload bytes of the command or response (if available).
    /// </summary>
    public byte[]? RawBytes { get; set; }

    /// <summary>
    /// Formatted Hex Dump for detailed forensic analysis.
    /// </summary>
    public string HexPayload { get; set; } = string.Empty;

    /// <summary>
    /// SHA-256 cryptographic hash of the command payload for tamper-evident chain of custody.
    /// </summary>
    public string Sha256Hash { get; set; } = string.Empty;

    /// <summary>
    /// Estimated operational risk/intent or response status
    /// (e.g. "INFO / READ", "FRP / BYPASS", "PARTITION WRITE", "BOOTLOADER", "REBOOT", "SHELL EXEC", "ROOT / EXPLOIT", "SUCCESS / OK", "ERROR / FAIL", "DEVICE INFO").
    /// </summary>
    public string RiskLevel { get; set; } = "INFO";

    /// <summary>
    /// Extended technical details, caller lineage, or protocol parameters.
    /// </summary>
    public string TechnicalDetails { get; set; } = string.Empty;

    // Badging and UI Styling
    public string DirectionSymbol => IsResponse ? "<<" : ">>";
    public string DirectionShort => IsResponse ? "DEV ➔ HOST" : "HOST ➔ DEV";
    public string DirectionBadgeColor => IsResponse ? "#00FF9D" : "#00E5FF";
    public string DirectionBadgeBackground => IsResponse ? "#0B2B20" : "#0A2838";

    public string ProtocolBadgeColor => Protocol.ToUpperInvariant() switch
    {
        var p when p.Contains("ADB") => "#00FF9D",      // Emerald
        var p when p.Contains("AT") => "#FFC800",       // Amber Gold
        var p when p.Contains("MTK") => "#FF6D00",      // Vivid Orange
        var p when p.Contains("EDL") || p.Contains("QCOM") => "#FF1744", // Crimson
        var p when p.Contains("SPD") || p.Contains("FDL") => "#E040FB",  // Electric Purple
        var p when p.Contains("APPLE") => "#E0E6ED",    // Silver White
        var p when p.Contains("FASTBOOT") => "#00E5FF", // Cyan
        var p when p.Contains("SHELL") => "#A5D6A7",    // Mint
        _ => "#8E9AA8"
    };

    public string RiskBadgeColor => RiskLevel.ToUpperInvariant() switch
    {
        var r when r.Contains("BYPASS") || r.Contains("EXPLOIT") => "#FF1744",
        var r when r.Contains("WRITE") || r.Contains("FLASH") => "#FF9100",
        var r when r.Contains("ROOT") || r.Contains("BOOTLOADER") || r.Contains("PRIVILEGED") => "#E040FB",
        var r when r.Contains("SHELL") => "#00E5FF",
        var r when r.Contains("ERROR") || r.Contains("FAIL") => "#FF1744",
        var r when r.Contains("SUCCESS") || r.Contains("OK") => "#00FF9D",
        var r when r.Contains("DEVICE INFO") => "#00E5FF",
        var r when r.Contains("DATA") || r.Contains("RESP") => "#80D8FF",
        _ => "#00FF9D"
    };

    // Paired Inspection UI Helpers
    public bool HasPairedData => IsResponse ? !string.IsNullOrWhiteSpace(RelatedCommandText) : !string.IsNullOrWhiteSpace(DeviceResponse);
    public string PairedHeaderTitle => IsResponse ? "ORIGINAL ISSUED COMMAND (HOST ➔ DEV):" : "PHONE RESPONSE RECEIVED (DEV ➔ HOST):";
    public string PairedPayload => IsResponse ? (RelatedCommandText ?? string.Empty) : (DeviceResponse ?? string.Empty);
    public string PairedBadgeColor => IsResponse ? "#00E5FF" : "#00FF9D";
    public string PrimaryHeaderTitle => IsResponse ? "INTERCEPTED PHONE RESPONSE (DEV ➔ HOST):" : "CLEAN EXECUTABLE COMMAND (HOST ➔ DEV):";
    public string PrimaryHeaderIcon => IsResponse ? "📥" : "⚡";

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged(string propertyName) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

    public static string ComputeSha256(byte[]? data)
    {
        if (data == null || data.Length == 0) return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        using var sha = SHA256.Create();
        byte[] hash = sha.ComputeHash(data);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    public static string ComputeSha256(string text)
    {
        return ComputeSha256(Encoding.UTF8.GetBytes(text ?? string.Empty));
    }
}
