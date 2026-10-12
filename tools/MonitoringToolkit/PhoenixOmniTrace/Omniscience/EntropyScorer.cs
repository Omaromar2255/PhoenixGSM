using System;

namespace PhoenixGSM.OmniTrace.Omniscience
{
    /// <summary>
    /// Computes Shannon entropy of byte buffers.
    /// حساب إنتروبيا شانون لاكتشاف التشفير أو الضغط
    /// </summary>
    public static class EntropyScorer
    {
        public static double CalculateEntropy(ReadOnlySpan<byte> data)
        {
            try
            {
                if (data.IsEmpty) return 0.0;

                int[] counts = new int[256];
                int total = data.Length;

                foreach (byte b in data)
                {
                    counts[b]++;
                }

                double entropy = 0.0;
                foreach (int count in counts)
                {
                    if (count > 0)
                    {
                        double p = (double)count / total;
                        entropy -= p * Math.Log(p, 2);
                    }
                }

                return entropy; // قيمة بين 0 و 8
            }
            catch
            {
                // Fail-open
                return 0.0;
            }
        }

        public static bool IsHighEntropy(ReadOnlySpan<byte> data, double threshold = 7.2)
        {
            try
            {
                double entropy = CalculateEntropy(data);
                return entropy > threshold;
            }
            catch
            {
                return false;
            }
        }
    }
}
