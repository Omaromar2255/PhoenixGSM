using System;
using System.Collections.Generic;

namespace PhoenixGSM.OmniTrace.PayloadAnalysis;

// Assuming there's a sensor or vault we connect to. We'll simulate the bridge.
public class PayloadVaultBridge : IDisposable
{
    private readonly YaraPatternScanner _scanner;
    
    // حدث عند اكتشاف تهديد / Event when threat detected
    public event EventHandler<YaraScanMatch>? OnThreatDetected;

    public PayloadVaultBridge(YaraPatternScanner scanner)
    {
        _scanner = scanner;
    }

    /// <summary>
    /// استدعاء عند التقاط ملف جديد / Triggered when new artifact captured
    /// </summary>
    public void ProcessArtifact(string filePath)
    {
        try
        {
            var matches = _scanner.ScanFile(filePath);
            foreach (var match in matches)
            {
                OnThreatDetected?.Invoke(this, match);
            }
        }
        catch (Exception ex)
        {
            // Fail-open
            Console.WriteLine($"[PayloadVaultBridge] ProcessArtifact Error: {ex.Message}");
        }
    }

    /// <summary>
    /// استدعاء عند التقاط بايتات جديدة / Triggered when new buffer captured
    /// </summary>
    public void ProcessBuffer(ReadOnlySpan<byte> buffer)
    {
        try
        {
            var matches = _scanner.ScanBuffer(buffer);
            foreach (var match in matches)
            {
                OnThreatDetected?.Invoke(this, match);
            }
        }
        catch (Exception ex)
        {
            // Fail-open
            Console.WriteLine($"[PayloadVaultBridge] ProcessBuffer Error: {ex.Message}");
        }
    }

    public void Dispose()
    {
        // تنظيف / Cleanup
        _scanner.Dispose();
    }
}
