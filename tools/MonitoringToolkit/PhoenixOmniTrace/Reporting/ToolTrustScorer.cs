using System;

namespace PhoenixGSM.OmniTrace.Reporting
{
    public enum RiskVerdict
    {
        Trusted,
        Suspicious,
        MaliciousHostile
    }

    public record ToolTrustEvaluation(int Score, RiskVerdict Verdict);

    public class ToolTrustScorer
    {
        // تقييم مستوى الثقة في الأداة - Evaluate the trust level of the tool
        public ToolTrustEvaluation EvaluateTrust(int criticalCount, int highCount, int mediumCount, int darkChannelCount)
        {
            try
            {
                int score = 100;
                
                score -= criticalCount * 25;
                score -= highCount * 10;
                score -= mediumCount * 4;
                score -= darkChannelCount * 30;

                score = Math.Max(0, score); // لا يمكن أن تكون النتيجة أقل من صفر - Score cannot be less than zero

                RiskVerdict verdict;
                if (score >= 85)
                {
                    verdict = RiskVerdict.Trusted;
                }
                else if (score >= 50)
                {
                    verdict = RiskVerdict.Suspicious;
                }
                else
                {
                    verdict = RiskVerdict.MaliciousHostile;
                }

                return new ToolTrustEvaluation(score, verdict);
            }
            catch (Exception ex)
            {
                // منع التوقف المفاجئ - Prevent crash
                Console.WriteLine($"[ToolTrustScorer] Error: {ex.Message}");
                return new ToolTrustEvaluation(50, RiskVerdict.Suspicious); // Default safe value
            }
        }
    }
}
