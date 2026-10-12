using System;
using System.Collections.Generic;

namespace PhoenixGSM.OmniTrace.Assurance
{
    /// <summary>
    /// Enum representing the three-state verdict for security behavior detection.
    /// حالة الحكم الثلاثية لاكتشاف السلوك الأمني.
    /// </summary>
    public enum VerdictStatus
    {
        /// <summary>
        /// Behavior explicitly observed and recorded.
        /// تم رصد السلوك بوضوح وتسجيله.
        /// </summary>
        Detected,

        /// <summary>
        /// Behavior was NOT observed, AND monitoring sensors were proven healthy & actively covering the path.
        /// لم يتم رصد السلوك، وتم إثبات أن أجهزة الاستشعار تعمل بشكل سليم وتغطي المسار.
        /// </summary>
        NotDetectedWithProvenCoverage,

        /// <summary>
        /// Behavior cannot be definitively confirmed or denied due to known blind spot.
        /// لا يمكن تأكيد أو نفي السلوك بسبب وجود نقطة عمياء (مثلاً تشفير VMProtect).
        /// </summary>
        UnobservableBlindSpot
    }

    /// <summary>
    /// Record representing a security finding with a specific verdict.
    /// سجل يمثل نتيجة أمنية مع حكم محدد.
    /// </summary>
    public record SecurityFinding(
        string FindingId,
        string Category,
        string Description,
        VerdictStatus Verdict,
        float ConfidenceScore,
        List<string> SensorEvidenceSources,
        string AuditNotes)
    {
        public bool IsActionable => Verdict == VerdictStatus.Detected && ConfidenceScore >= 0.8f;
    }
}
