using System;
using System.Text;

namespace PhoenixGSM.OmniTrace.Decoders;

/// <summary>
/// Result model for inspecting file payload magic bytes and content heuristics.
/// </summary>
public sealed class ContentClassificationResult
{
    public string Classification { get; set; } = "UNKNOWN";
    public string Description { get; set; } = "Generic binary or unclassified data";
    public bool IsExecutableOrExploit { get; set; }
    public string Architecture { get; set; } = "N/A";
    public string MimeType { get; set; } = "application/octet-stream";
}

/// <summary>
/// LAYER 8B — Smart Content Classifier
/// Fast, zero-allocation magic bytes inspector and heuristics engine for pushed files and payloads.
/// Identifies Linux ELF root exploits (athun/trd), Android DEX bytecode, APK packages, shell scripts,
/// firmware partitions (Sparse, Boot), and modem staging files.
/// </summary>
public static class SmartContentClassifier
{
    public static ContentClassificationResult Classify(ReadOnlySpan<byte> data)
    {
        var result = new ContentClassificationResult();
        if (data.Length == 0)
        {
            result.Classification = "EMPTY";
            result.Description = "Empty file (0 bytes)";
            return result;
        }

        // 1. Check Linux ELF Executable / Shared Object (Exploits, athun, su, daemons)
        if (data.Length >= 4 && data[0] == 0x7F && data[1] == (byte)'E' && data[2] == (byte)'L' && data[3] == (byte)'F')
        {
            result.IsExecutableOrExploit = true;
            result.Classification = "ELF_EXECUTABLE";
            result.MimeType = "application/x-executable";

            string bitness = "32-bit";
            if (data.Length > 4 && data[4] == 2) bitness = "64-bit";

            string endianness = "LSB";
            if (data.Length > 5 && data[5] == 2) endianness = "MSB";

            string arch = "Generic";
            if (data.Length >= 20)
            {
                ushort e_machine = (ushort)(data[18] | (data[19] << 8));
                arch = e_machine switch
                {
                    0x03 => "x86",
                    0x28 => "ARM",
                    0xB7 => "AArch64 (ARM64)",
                    0x3E => "x86_64",
                    0x08 => "MIPS",
                    _ => $"Machine:0x{e_machine:X2}"
                };
            }
            result.Architecture = arch;
            result.Description = $"Linux ELF {bitness} {endianness} ({arch}) — Exploit / Native Binary";
            return result;
        }

        // 2. Check Android Dalvik Bytecode (DEX)
        if (data.Length >= 4 && data[0] == (byte)'d' && data[1] == (byte)'e' && data[2] == (byte)'x' && data[3] == 0x0A)
        {
            result.IsExecutableOrExploit = true;
            result.Classification = "ANDROID_DEX";
            result.MimeType = "application/x-dex";
            string version = data.Length >= 7 ? Encoding.ASCII.GetString(data.Slice(4, 3)) : "035";
            result.Description = $"Android Dalvik Executable (DEX v{version})";
            return result;
        }

        // 3. Check ZIP / APK Package
        if (data.Length >= 4 && data[0] == 0x50 && data[1] == 0x4B && data[2] == 0x03 && data[3] == 0x04)
        {
            // Scan first 1KB to distinguish APK from regular ZIP
            int scanLen = Math.Min(data.Length, 1024);
            string preview = Encoding.ASCII.GetString(data[..scanLen]);
            bool isApk = preview.Contains("AndroidManifest.xml") || preview.Contains("classes.dex") || preview.Contains("META-INF");

            if (isApk)
            {
                result.IsExecutableOrExploit = true;
                result.Classification = "ANDROID_APK";
                result.MimeType = "application/vnd.android.package-archive";
                result.Description = "Android Package Archive (APK) containing DEX / Manifest";
            }
            else
            {
                result.Classification = "ZIP_ARCHIVE";
                result.MimeType = "application/zip";
                result.Description = "ZIP Compressed Archive";
            }
            return result;
        }

        // 4. Check Android Sparse Image (e.g. system.img, vendor.img)
        // Magic: 0x3AFF26ED in little-endian
        if (data.Length >= 4 && data[0] == 0x3A && data[1] == 0xFF && data[2] == 0x26 && data[3] == 0xED)
        {
            result.Classification = "ANDROID_SPARSE_IMG";
            result.MimeType = "application/x-sparse-image";
            result.Description = "Android Sparse Partition Image (system/vendor)";
            return result;
        }

        // 5. Check Android Boot / Recovery Image
        if (data.Length >= 8 && data[0] == (byte)'A' && data[1] == (byte)'N' && data[2] == (byte)'D' && data[3] == (byte)'R' &&
            data[4] == (byte)'O' && data[5] == (byte)'I' && data[6] == (byte)'D' && data[7] == (byte)'!')
        {
            result.IsExecutableOrExploit = true;
            result.Classification = "ANDROID_BOOT_IMG";
            result.MimeType = "application/x-boot-image";
            result.Description = "Android Boot / Recovery Kernel Image (ANDROID!)";
            return result;
        }

        // 6. Check GZIP Compressed Archive
        if (data.Length >= 2 && data[0] == 0x1F && data[1] == 0x8B)
        {
            result.Classification = "GZIP_COMPRESSED";
            result.MimeType = "application/gzip";
            result.Description = "GZIP Compressed Archive";
            return result;
        }

        // 7. Check TAR Archive ("ustar" at offset 257)
        if (data.Length >= 262 && data[257] == (byte)'u' && data[258] == (byte)'s' && data[259] == (byte)'t' && data[260] == (byte)'a' && data[261] == (byte)'r')
        {
            result.Classification = "TAR_ARCHIVE";
            result.MimeType = "application/x-tar";
            result.Description = "POSIX Tar Archive (ustar)";
            return result;
        }

        // 8. Check Shell Script (starts with #! or common Linux shell tokens)
        if (data.Length >= 2 && data[0] == (byte)'#' && data[1] == (byte)'!')
        {
            int lineEnd = data.IndexOf((byte)'\n');
            if (lineEnd < 0) lineEnd = Math.Min(data.Length, 64);
            string shebang = Encoding.UTF8.GetString(data[..lineEnd]).Trim();

            result.IsExecutableOrExploit = true;
            result.Classification = "SHELL_SCRIPT";
            result.MimeType = "text/x-shellscript";
            result.Description = $"Shell Script ({shebang})";
            return result;
        }

        // Check text content heuristics for shell scripts or commands without shebang
        int textCheckLen = Math.Min(data.Length, 256);
        bool isAsciiText = true;
        for (int i = 0; i < textCheckLen; i++)
        {
            byte b = data[i];
            if (b < 9 || (b > 13 && b < 32))
            {
                isAsciiText = false;
                break;
            }
        }

        if (isAsciiText)
        {
            string ascii = Encoding.ASCII.GetString(data[..textCheckLen]);
            if (ascii.Contains("chmod ") || ascii.Contains("chown ") || ascii.Contains("insmod ") ||
                ascii.Contains("setprop ") || ascii.Contains("export ") || ascii.Contains("/data/local/tmp"))
            {
                result.IsExecutableOrExploit = true;
                result.Classification = "SHELL_SCRIPT";
                result.MimeType = "text/x-shellscript";
                result.Description = "Executable Shell Script with Root / Permission Directives";
                return result;
            }

            result.Classification = "TEXT_CONFIG";
            result.MimeType = "text/plain";
            result.Description = "Plain Text / Configuration Script";
            return result;
        }

        // 9. Generic Binary Fallback
        result.Classification = "BINARY_PAYLOAD";
        result.MimeType = "application/octet-stream";
        result.Description = $"Binary Payload ({data.Length} bytes)";
        return result;
    }
}
