namespace PhoenixGSM.SerialSniffer.Models;

using System.Text.Json.Serialization;

/// <summary>
/// نموذج بيانات حزمة تسلسلية ملتقطة
/// Data model for a captured serial packet
/// </summary>
public class SerialPacket
{
    [JsonPropertyName("timestamp")]
    public DateTime Timestamp { get; set; } = DateTime.Now;

    /// <summary>اتجاه البيانات / Data direction</summary>
    [JsonPropertyName("direction")]
    public string Direction { get; set; } = "RX"; // RX = مستقبل, TX = مرسل

    /// <summary>اسم المنفذ / Port name</summary>
    [JsonPropertyName("port")]
    public string Port { get; set; } = "";

    /// <summary>البيانات بصيغة Hex / Data as hex string</summary>
    [JsonPropertyName("hex_data")]
    public string HexData { get; set; } = "";

    /// <summary>البيانات كنص ASCII / Data as ASCII text</summary>
    [JsonPropertyName("ascii_data")]
    public string AsciiData { get; set; } = "";

    /// <summary>حجم البيانات بالبايت / Data size in bytes</summary>
    [JsonPropertyName("size")]
    public int Size { get; set; }

    /// <summary>سرعة الاتصال / Baud rate</summary>
    [JsonPropertyName("baud_rate")]
    public int BaudRate { get; set; }

    /// <summary>هل هو أمر AT؟ / Is it an AT command?</summary>
    [JsonPropertyName("is_at_command")]
    public bool IsAtCommand { get; set; }

    /// <summary>نوع البروتوكول المكتشف / Detected protocol type</summary>
    [JsonPropertyName("protocol")]
    public string Protocol { get; set; } = "UNKNOWN";
}

/// <summary>
/// أنواع البروتوكولات المكتشفة
/// Detected protocol types
/// </summary>
public static class ProtocolTypes
{
    public const string AtCommand = "AT_COMMAND";
    public const string Odin = "ODIN";
    public const string Qualcomm = "QUALCOMM_DIAG";
    public const string MediaTek = "MTK_BROM";
    public const string Samsung = "SAMSUNG_UART";
    public const string Unknown = "UNKNOWN";

    /// <summary>
    /// كشف البروتوكول من البيانات
    /// Detect protocol from data
    /// </summary>
    public static string Detect(byte[] data)
    {
        if (data == null || data.Length == 0) return Unknown;

        // Skip leading whitespace / CR / LF / null bytes
        int start = 0;
        while (start < data.Length && (data[start] == '\r' || data[start] == '\n' || data[start] == ' ' || data[start] == '\t' || data[start] == 0))
        {
            start++;
        }
        if (start >= data.Length) return Unknown;

        var text = System.Text.Encoding.ASCII.GetString(data, start, data.Length - start).Trim();
        var upper = text.ToUpperInvariant();

        // أوامر وردود AT / AT commands & responses
        if (upper.StartsWith("AT") || upper.StartsWith("A/") ||
            upper.StartsWith("+") ||
            upper.StartsWith("OK") ||
            upper.StartsWith("ERROR") ||
            upper.Contains("+CME") ||
            upper.Contains("+CMS") ||
            upper.StartsWith("^") ||
            upper.StartsWith("RING") ||
            upper.StartsWith("CONNECT") ||
            upper.StartsWith("NO CARRIER") ||
            upper.StartsWith("BUSY") ||
            upper.StartsWith("NO DIALTONE") ||
            (text.Length == 1 && "01234678".Contains(text[0])) ||
            upper.StartsWith(">") ||
            (text.Length >= 14 && text.Length <= 16 && text.All(char.IsDigit)) ||
            (text.Length >= 2 && (text[0] == '%' || text[0] == '$' || text[0] == '#' || text[0] == '*' || text[0] == '@')) ||
            upper.StartsWith("SAMSUNG") || upper.StartsWith("QUALCOMM") || upper.StartsWith("MEDIATEK"))
        {
            return AtCommand;
        }

        // بروتوكول Odin (Samsung download mode)
        if (data.Length >= 4)
        {
            // ODIN magic bytes
            if (data[0] == 0x4F && data[1] == 0x44 && data[2] == 0x49 && data[3] == 0x4E)
                return Odin;
            // Samsung LOKE protocol
            if (data[0] == 0x00 && data[1] == 0x00 && data[2] == 0x00 && data[3] == 0x04)
                return Odin;
        }

        // Qualcomm Diagnostic (DIAG)
        if (data[0] == 0x7E || data[^1] == 0x7E)
            return Qualcomm;

        // MediaTek BROM
        if (data[0] == 0xA0 || (data.Length > 1 && data[0] == 0x5A && data[1] == 0xA5))
            return MediaTek;

        return Unknown;
    }
}
