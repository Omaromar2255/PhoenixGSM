using System;
using System.Collections.Concurrent;

namespace PhoenixGSM.OmniTrace.UsbSecurity;

/// <summary>
/// Detects automated keystroke injection (Rubber Ducky / BadUSB behavior).
/// يكتشف حقن ضغطات المفاتيح التلقائي (سلوك Rubber Ducky / BadUSB).
/// </summary>
public class HidInjectionDetector : IDisposable
{
    private DateTimeOffset _lastKeystrokeTime = DateTimeOffset.MinValue;
    private int _rapidKeyCount = 0;
    
    // Threshold: > 50 keystrokes per second is considered inhuman
    // الحد الأدنى: أكثر من 50 ضغطة في الثانية يعتبر غير بشري
    private const double InhumanSpeedThresholdMs = 20.0; // 1000ms / 50 keys = 20ms per key avg

    /// <summary>
    /// Calculates keystroke inter-arrival timing.
    /// يحسب التوقيت بين وصول ضغطات المفاتيح.
    /// </summary>
    public bool AnalyzeKeystrokeTiming(DateTimeOffset timestamp, int keyCount, out string detectionReason)
    {
        detectionReason = string.Empty;

        try
        {
            if (_lastKeystrokeTime == DateTimeOffset.MinValue)
            {
                _lastKeystrokeTime = timestamp;
                return false;
            }

            double timeDiffMs = (timestamp - _lastKeystrokeTime).TotalMilliseconds;
            _lastKeystrokeTime = timestamp;

            if (timeDiffMs > 0 && timeDiffMs < InhumanSpeedThresholdMs)
            {
                _rapidKeyCount += keyCount;
            }
            else
            {
                // Reset if human speed resumes
                // إعادة الضبط إذا عادت السرعة البشرية
                _rapidKeyCount = 0;
            }

            // If we see more than 50 rapid keys, flag it
            // إذا رأينا أكثر من 50 مفتاحاً سريعاً، أبلغ عنه
            if (_rapidKeyCount >= 50)
            {
                detectionReason = $"BadUSB / HID Injection detected: {_rapidKeyCount} keystrokes received at superhuman speed.";
                _rapidKeyCount = 0; // reset after detection
                return true;
            }

            return false;
        }
        catch (Exception ex)
        {
            // Fail-open
            // نمط تجاوز الفشل
            Console.WriteLine($"[HidInjectionDetector Error]: {ex.Message}");
            return false;
        }
    }

    public void Dispose()
    {
        // Cleanup
        // تنظيف
    }
}
