using System;
using PhoenixGSM.OmniTrace;

namespace PhoenixGSM.OmniTrace.SecurityEngine;

/// <summary>
/// واجهة قواعد الكشف عن التهديدات
/// Interface for threat detection rules
/// </summary>
public interface IDetectionRule
{
    // معرف القاعدة - Rule ID
    string RuleId { get; }
    
    // اسم القاعدة - Rule Name
    string RuleName { get; }
    
    // فئة التهديد - Threat Category
    ThreatCategory Category { get; }
    
    // الخطورة الافتراضية - Default Severity
    ThreatSeverity DefaultSeverity { get; }
    
    /// <summary>
    /// تقييم الأمر وتحديد ما إذا كان يمثل تهديداً
    /// Evaluate the command and determine if it represents a threat
    /// </summary>
    ThreatAlert? Evaluate(dynamic commandEvent);
    // Note: Using dynamic or assuming LogicalCommandEvent is passed via dynamic/duck-typing if not strictly referenced, 
    // but assuming LogicalCommandEvent is available in PhoenixGSM.OmniTrace namespace.
}
