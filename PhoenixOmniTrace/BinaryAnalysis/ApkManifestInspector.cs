using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace PhoenixGSM.OmniTrace.BinaryAnalysis;

public class ApkInspectionResult
{
    public bool IsValidApkOrZip { get; set; }
    public bool HasDangerousPermissions { get; set; }
    public List<string> DangerousPermissions { get; set; } = new();
    public bool HasDeviceAdmin { get; set; }
    public bool HasExportedPersistentServices { get; set; }
    public bool HasNativeRilLibrary { get; set; }
    public bool HasRetailModeSignature { get; set; }
    public string ForensicDescription { get; set; } = string.Empty;
    public List<string> MatchedSignatures { get; set; } = new();
}

/// <summary>
/// Inspects Android APKs, binary AndroidManifest.xml, and embedded native libraries.
/// يفحص حزم APK و AndroidManifest.xml والمكتبات الأصلية المضمنة.
/// </summary>
public class ApkManifestInspector : IDisposable
{
    private static ReadOnlySpan<byte> ZipMagic => new byte[] { 0x50, 0x4B, 0x03, 0x04 }; // PK\x03\x04

    private readonly string[] _dangerousPermissions = {
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.READ_CONTACTS",
        "android.permission.INSTALL_PACKAGES"
    };

    private readonly string[] _nativeRilSignatures = {
        "lib/arm64-v8a/libril.so",
        "libril.so",
        "libsec-ril.so"
    };

    private readonly string[] _retailModeSignatures = {
        "retailmode",
        "com.samsung.retailmode",
        "SRV4_64",
        "RetailAgent",
        "APK Sig Block 42"
    };

    /// <summary>
    /// Inspects raw bytes of an APK or ZIP archive for malicious native libraries and privilege bridge artifacts.
    /// </summary>
    public ApkInspectionResult InspectApk(ReadOnlySpan<byte> apkData)
    {
        var result = new ApkInspectionResult();
        if (apkData.Length < 4) return result;

        try
        {
            bool hasZipHeader = apkData.Slice(0, 4).SequenceEqual(ZipMagic);
            string content = Encoding.Latin1.GetString(apkData.ToArray());

            bool hasManifest = content.Contains("AndroidManifest.xml", StringComparison.OrdinalIgnoreCase);
            bool hasDex = content.Contains("classes.dex", StringComparison.OrdinalIgnoreCase);

            if (hasZipHeader || (hasManifest && hasDex))
            {
                result.IsValidApkOrZip = true;
            }

            // 1. Detect Native RIL Libraries (libril.so, libsec-ril.so)
            foreach (var rilSig in _nativeRilSignatures)
            {
                if (content.Contains(rilSig, StringComparison.OrdinalIgnoreCase))
                {
                    result.HasNativeRilLibrary = true;
                    result.MatchedSignatures.Add(rilSig);
                }
            }

            if (result.HasNativeRilLibrary)
            {
                result.ForensicDescription = "Privilege Bridge APK containing Native RIL Library (lib/arm64-v8a/libril.so)";
            }

            // 2. Detect Retail Mode / SRV4 signatures
            foreach (var retSig in _retailModeSignatures)
            {
                if (content.Contains(retSig, StringComparison.OrdinalIgnoreCase))
                {
                    result.HasRetailModeSignature = true;
                    result.MatchedSignatures.Add(retSig);
                }
            }

            if (string.IsNullOrEmpty(result.ForensicDescription) && result.HasRetailModeSignature)
            {
                result.ForensicDescription = "Samsung Retail Mode / Service Mode Privilege Bridge Package";
            }

            // 3. Detect dangerous permissions
            foreach (var perm in _dangerousPermissions)
            {
                if (content.Contains(perm, StringComparison.OrdinalIgnoreCase))
                {
                    result.DangerousPermissions.Add(perm);
                    result.HasDangerousPermissions = true;
                }
            }

            // 4. Detect DeviceAdminReceiver
            if (content.Contains("DeviceAdminReceiver", StringComparison.OrdinalIgnoreCase))
            {
                result.HasDeviceAdmin = true;
            }

            // 5. Detect exported persistent services
            if (content.Contains("android:exported=\"true\"", StringComparison.OrdinalIgnoreCase) && 
                content.Contains("android:persistent=\"true\"", StringComparison.OrdinalIgnoreCase))
            {
                result.HasExportedPersistentServices = true;
            }

            return result;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ApkManifestInspector Error]: {ex.Message}");
            return result;
        }
    }

    public ApkInspectionResult InspectApk(byte[] apkData)
    {
        if (apkData == null || apkData.Length == 0) return new ApkInspectionResult();
        return InspectApk(new ReadOnlySpan<byte>(apkData));
    }

    /// <summary>
    /// Inspects the APK for suspicious configurations from file path or manifest string.
    /// </summary>
    public ApkInspectionResult InspectApk(string apkPathOrContent)
    {
        if (string.IsNullOrWhiteSpace(apkPathOrContent)) return new ApkInspectionResult();

        try
        {
            if (File.Exists(apkPathOrContent))
            {
                byte[] bytes = File.ReadAllBytes(apkPathOrContent);
                return InspectApk(bytes);
            }

            byte[] textBytes = Encoding.UTF8.GetBytes(apkPathOrContent);
            return InspectApk(textBytes);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ApkManifestInspector Error]: {ex.Message}");
            return new ApkInspectionResult();
        }
    }

    public void Dispose()
    {
    }
}
