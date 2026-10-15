using System;
using System.IO;
using System.Security.Cryptography;

namespace PhoenixGSM.OmniTrace.NetworkInterception;

public class InterceptedNetworkPayload
{
    public string FilePath { get; set; } = string.Empty;
    public string Sha256 { get; set; } = string.Empty;
    public string Md5 { get; set; } = string.Empty;
    public string FileType { get; set; } = string.Empty;
    public long Size { get; set; }
}

/// <summary>
/// Dumps binary payloads downloaded in-flight directly to the artifact vault.
/// يقوم بتفريغ الحمولات الثنائية التي تم تنزيلها أثناء الطيران مباشرة إلى قبو القطع الأثرية.
/// </summary>
public class NetworkStreamPayloadDumper : IDisposable
{
    private readonly SocketBufferReassembler _reassembler = new();
    private readonly string _artifactVaultPath;
    private bool _isRunning;

    public event EventHandler<InterceptedNetworkPayload>? OnNetworkPayloadCaptured;

    public NetworkStreamPayloadDumper(string baseDirectory = @"c:\Users\pc5\softwer\PhoenixGSM\tools\MonitoringToolkit\PhoenixOmniTrace")
    {
        _artifactVaultPath = Path.Combine(baseDirectory, "AdbPushArtifactVault");
        if (!Directory.Exists(_artifactVaultPath))
        {
            Directory.CreateDirectory(_artifactVaultPath);
        }
    }

    public void Start()
    {
        _isRunning = true;
        Console.WriteLine("[PayloadDumper] Started monitoring network streams.");
    }

    public void Stop()
    {
        _isRunning = false;
        Console.WriteLine("[PayloadDumper] Stopped monitoring network streams.");
    }

    /// <summary>
    /// Feeds raw captured network data into the reassembler.
    /// يغذي البيانات الشبكية الخام الملتقطة في معيد التجميع.
    /// </summary>
    public void ProcessRawPacket(string sourceIp, int sourcePort, string destIp, int destPort, byte[] payloadData)
    {
        if (!_isRunning) return;

        try
        {
            string connectionKey = $"{sourceIp}:{sourcePort}->{destIp}:{destPort}";
            var completedPayload = _reassembler.AddChunkAndCheckCompletion(connectionKey, payloadData);

            if (completedPayload != null && completedPayload.Length > 0)
            {
                AnalyzeAndDumpPayload(completedPayload);
            }
        }
        catch (Exception ex)
        {
            // Fail-open: prevent crash on processing error / تجاوز الفشل: منع الانهيار عند خطأ المعالجة
            Console.WriteLine($"[PayloadDumper] Error processing packet: {ex.Message}");
        }
    }

    private void AnalyzeAndDumpPayload(byte[] payload)
    {
        try
        {
            string magicType = IdentifyMagicBytes(payload);
            
            // Only dump interesting binary types / قم بتفريغ الأنواع الثنائية المثيرة للاهتمام فقط
            if (string.IsNullOrEmpty(magicType)) return;

            string sha256 = ComputeHash(payload, SHA256.Create());
            string md5 = ComputeHash(payload, MD5.Create());
            
            string fileName = $"intercept_{DateTime.UtcNow:yyyyMMdd_HHmmss}_{sha256.Substring(0, 8)}.{magicType.ToLower()}";
            string filePath = Path.Combine(_artifactVaultPath, fileName);

            File.WriteAllBytes(filePath, payload);

            var interceptedInfo = new InterceptedNetworkPayload
            {
                FilePath = filePath,
                Sha256 = sha256,
                Md5 = md5,
                FileType = magicType,
                Size = payload.Length
            };

            OnNetworkPayloadCaptured?.Invoke(this, interceptedInfo);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[PayloadDumper] Error analyzing payload: {ex.Message}");
        }
    }

    private string IdentifyMagicBytes(byte[] payload)
    {
        if (payload.Length < 4) return string.Empty;

        // MZ (EXE)
        if (payload[0] == 0x4D && payload[1] == 0x5A) return "EXE";
        // PK (ZIP, APK)
        if (payload[0] == 0x50 && payload[1] == 0x4B && payload[2] == 0x03 && payload[3] == 0x04) return "ZIP";
        // ELF
        if (payload[0] == 0x7F && payload[1] == 0x45 && payload[2] == 0x4C && payload[3] == 0x46) return "ELF";
        // DEX
        if (payload[0] == 0x64 && payload[1] == 0x65 && payload[2] == 0x78 && payload[3] == 0x0A) return "DEX";
        // GZ
        if (payload[0] == 0x1F && payload[1] == 0x8B) return "GZ";

        return string.Empty;
    }

    private string ComputeHash(byte[] data, HashAlgorithm algorithm)
    {
        using (algorithm)
        {
            byte[] hash = algorithm.ComputeHash(data);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }
    }

    public void Dispose()
    {
        Stop();
        _reassembler.Dispose();
    }
}
