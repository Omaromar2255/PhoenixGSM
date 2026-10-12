using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Text;

namespace PhoenixGSM.OmniTrace.Omniscience
{
    /// <summary>
    /// Honeytoken / Canary detector for finding leaks.
    /// مدير الكناري لاكتشاف التسريبات
    /// </summary>
    public class CanaryManager : IDisposable
    {
        private readonly ConcurrentDictionary<string, string> _canaries = new();
        private bool _disposed = false;

        public CanaryManager()
        {
            // إعداد القيم الافتراضية
            PlantCanary("CANARY_JOHN_DOE", "Fake Contact Name");
            PlantCanary("990000862471854", "Fake IMEI");
            PlantCanary("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", "Fake BTC Wallet");
        }

        public void PlantCanary(string token, string description)
        {
            try
            {
                if (_disposed) return;
                _canaries[token] = description;
            }
            catch (Exception ex)
            {
                // Fail-open
                Console.WriteLine($"[CanaryManager] Error planting canary: {ex.Message}");
            }
        }

        public bool CheckForCanaryLeak(ReadOnlySpan<byte> data, out string detectedCanary)
        {
            detectedCanary = string.Empty;
            try
            {
                if (data.IsEmpty || _disposed) return false;

                // تحويل البيانات إلى نص والبحث عن الكناري
                string text = Encoding.UTF8.GetString(data);
                return CheckForCanaryLeakText(text, out detectedCanary);
            }
            catch
            {
                return false; // Fail-open
            }
        }

        public bool CheckForCanaryLeakText(string text, out string detectedCanary)
        {
            detectedCanary = string.Empty;
            try
            {
                if (string.IsNullOrEmpty(text) || _disposed) return false;

                foreach (var token in _canaries.Keys)
                {
                    if (text.Contains(token))
                    {
                        detectedCanary = token;
                        // تم اكتشاف تسريب!
                        return true;
                    }
                }
            }
            catch
            {
                // Ignore exception
            }

            return false;
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _canaries.Clear();
                _disposed = true;
            }
            GC.SuppressFinalize(this);
        }
    }
}
