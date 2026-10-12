using System;
using System.Collections.Generic;

namespace PhoenixGSM.OmniTrace.IndirectChannels;

public class SecretCodeDetector : IDisposable
{
    private readonly Dictionary<string, string> _knownCodes = new(StringComparer.OrdinalIgnoreCase)
    {
        { "*#0808#", "USB Settings Menu" },
        { "*#9900#", "SysDump Menu" },
        { "*#06#", "IMEI Display" },
        { "*#*#4636#*#*", "Testing Menu" },
        { "*#272*", "CSC Change Menu" },
        { "*#0*#", "Hardware Test Menu" }
    };

    // اكتشاف الأكواد السرية في الأوامر أو النوايا
    public bool CheckSecretCode(string commandOrIntent, out string detectedCode, out string explanation)
    {
        detectedCode = string.Empty;
        explanation = string.Empty;

        try
        {
            if (string.IsNullOrWhiteSpace(commandOrIntent)) return false;

            // Simple substring search for known codes
            // البحث المباشر عن الأكواد في النص
            foreach (var kvp in _knownCodes)
            {
                if (commandOrIntent.Contains(kvp.Key))
                {
                    detectedCode = kvp.Key;
                    explanation = $"Detected activation of {kvp.Value} ({kvp.Key})";
                    return true;
                }
            }

            return false;
        }
        catch (Exception ex)
        {
            // Fail-open
            Console.WriteLine($"[Error] CheckSecretCode failed: {ex.Message}");
            return false;
        }
    }

    public void Dispose()
    {
        _knownCodes.Clear();
    }
}
