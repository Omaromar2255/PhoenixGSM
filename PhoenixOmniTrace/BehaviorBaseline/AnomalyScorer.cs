using System;

namespace PhoenixGSM.OmniTrace.BehaviorBaseline;

public class AnomalyEvaluation
{
    public double DeviationScore { get; set; }
    public bool IsAnomalous { get; set; }
    public string Reason { get; set; } = string.Empty;
}

public class AnomalyScorer
{
    private readonly ToolBehaviorProfiler _profiler;

    public AnomalyScorer(ToolBehaviorProfiler profiler)
    {
        _profiler = profiler ?? throw new ArgumentNullException(nameof(profiler));
    }

    /// <summary>
    /// يحسب درجة الانحراف (Z-score) للقياسات الحالية / Calculates deviation score of current session metrics
    /// </summary>
    public AnomalyEvaluation ScoreSession(double currentRate, int currentSize, bool isWrite)
    {
        var result = new AnomalyEvaluation { IsAnomalous = false, DeviationScore = 0.0 };

        try
        {
            var baseline = _profiler.GetProfile();

            // Thresholds for anomaly detection (heuristics for demonstration)
            // عتبات كشف الشذوذ (استدلال للتوضيح)
            double score = 0;

            if (baseline.AverageCommandRate > 0 && currentRate > baseline.AverageCommandRate * 3)
            {
                score += 3.0; // Spikes in burst frequencies
                result.Reason += "Abnormal burst frequency. ";
            }

            if (baseline.AveragePayloadSize > 0 && currentSize > baseline.AveragePayloadSize * 5)
            {
                score += 4.0; // Large unexpected payload
                result.Reason += "Unexpected large payload. ";
            }

            // Write activity anomaly
            if (isWrite && baseline.WriteRatio < 0.1 && _profiler.GetProfile().AverageCommandRate > 0) // If writes are rare
            {
                score += 2.0;
                result.Reason += "Anomalous write spike. ";
            }

            result.DeviationScore = score;
            result.IsAnomalous = score >= 4.0;
        }
        catch (Exception ex)
        {
            // Fail-open
            Console.WriteLine($"[Scorer Error] {ex.Message}");
        }

        return result;
    }
}
