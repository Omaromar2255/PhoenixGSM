using System;
using System.Collections.Generic;

namespace PhoenixGSM.OmniTrace.SecurityEngine;

public enum ThreatSeverity
{
    Info,
    Low,
    Medium,
    High,
    Critical
}

public enum ThreatCategory
{
    SpywareImplant,
    DataExfiltration,
    BackdoorInstall,
    UnauthorizedRoot,
    ImeiTampering,
    FrpBypass,
    BootloaderExploit,
    SilentApkInstall,
    CovertChannel,
    CameraAccess,
    LocationQuery,
    ScreenCapture,
    PrivilegeEscalation,
    AntiForensic,
    Unknown
}

public class ThreatAlert
{
    // معرف التنبيه - Alert ID
    public Guid AlertId { get; set; } = Guid.NewGuid();
    
    // وقت وتاريخ الحدث - Timestamp of the event
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    
    // خطورة التهديد - Threat Severity
    public ThreatSeverity Severity { get; set; }
    
    // فئة التهديد - Threat Category
    public ThreatCategory Category { get; set; }
    
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    
    // معرف الأمر المرتبط - Associated Command ID
    public string? CommandId { get; set; }
    
    public string? ProcessName { get; set; }
    public string? DeviceId { get; set; }
    
    // درجة الموثوقية (0-100) - Confidence Score (0-100)
    public int ConfidenceScore { get; set; }
    
    public Dictionary<string, string> Metadata { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public List<string> RawEvidence { get; set; } = new();
}
