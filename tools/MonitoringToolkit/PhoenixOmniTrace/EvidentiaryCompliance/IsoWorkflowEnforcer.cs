using System;

namespace PhoenixGSM.OmniTrace.EvidentiaryCompliance;

public enum EvidencePhase
{
    Identification,
    Collection,
    Acquisition,
    Preservation
}

public class IsoWorkflowEnforcer
{
    private EvidencePhase _currentPhase = EvidencePhase.Identification;
    private readonly object _lockObj = new object();

    /// <summary>
    /// يطبق سير عمل إدارة الأدلة الرقمية وفقاً لمعيار ISO/IEC 27037 / Enforces digital evidence management workflow
    /// </summary>
    public bool ValidateWorkflowPhase(EvidencePhase targetPhase, out string complianceMessage)
    {
        complianceMessage = string.Empty;

        try
        {
            lock (_lockObj)
            {
                // التحقق من التسلسل المنطقي للمراحل / Validate logical sequence of phases
                if (targetPhase == _currentPhase)
                {
                    complianceMessage = $"المرحلة الحالية صالحة / Current phase is valid: {targetPhase}";
                    return true;
                }

                if (targetPhase == _currentPhase + 1)
                {
                    _currentPhase = targetPhase;
                    complianceMessage = $"تم الانتقال إلى المرحلة / Transitioned to phase: {targetPhase}";
                    return true;
                }

                complianceMessage = $"انتهاك سير العمل: لا يمكن الانتقال من {_currentPhase} إلى {targetPhase} / Workflow violation: Cannot transition directly.";
                return false;
            }
        }
        catch (Exception ex)
        {
            // Fail-open
            complianceMessage = $"خطأ في التحقق من الامتثال / Compliance error: {ex.Message}";
            return false; 
        }
    }
    
    public EvidencePhase GetCurrentPhase()
    {
        lock (_lockObj)
        {
            return _currentPhase;
        }
    }
}
