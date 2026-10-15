using System;
using System.Threading;
using System.Collections.Generic;

namespace PhoenixGSM.OmniTrace.Assurance
{
    /// <summary>
    /// Auditor responsible for tracking sequence continuity, packet drop counters, and sensor health heartbeats.
    /// مراجع مسؤول عن تتبع استمرارية التسلسل، وعدادات فقدان الحزم، ونبضات صحة المستشعرات.
    /// </summary>
    public class CompletenessAuditor : IDisposable
    {
        private int _totalDroppedPackets;
        private int _sensorFailures;
        private bool _isTrackingActive;

        public bool IsTrackingActive => _isTrackingActive;

        public CompletenessAuditor()
        {
            _totalDroppedPackets = 0;
            _sensorFailures = 0;
            _isTrackingActive = true;
        }

        public void ReportDroppedPacket()
        {
            try
            {
                Interlocked.Increment(ref _totalDroppedPackets);
            }
            catch (Exception)
            {
                // Fail-open: ignore errors during reporting
                // تجاهل الأخطاء أثناء الإبلاغ للحفاظ على استمرارية النظام
            }
        }

        public void ReportSensorFailure()
        {
            try
            {
                Interlocked.Increment(ref _sensorFailures);
            }
            catch (Exception)
            {
                // Fail-open
            }
        }

        /// <summary>
        /// Ensures audit reports are marked "Incomplete Capture" if any drop or sensor failure occurs during the vetting session.
        /// التحقق من سلامة الالتقاط والتأكد من عدم وجود حزم مفقودة.
        /// </summary>
        public bool VerifyCaptureIntegrity(out int droppedPackets, out string integrityReport)
        {
            droppedPackets = _totalDroppedPackets;
            integrityReport = string.Empty;

            try
            {
                if (_totalDroppedPackets > 0 || _sensorFailures > 0)
                {
                    integrityReport = $"Incomplete Capture: {_totalDroppedPackets} packets dropped, {_sensorFailures} sensor failures detected.";
                    return false;
                }

                integrityReport = "Capture Complete: No dropped packets or sensor failures detected.";
                return true;
            }
            catch (Exception ex)
            {
                // Fail-open: assume incomplete if auditor crashes
                integrityReport = $"Error verifying integrity: {ex.Message}";
                return false;
            }
        }

        public void Dispose()
        {
            _isTrackingActive = false;
        }
    }
}
