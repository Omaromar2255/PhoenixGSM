using System;
using System.Collections.Generic;

namespace PhoenixGSM.OmniTrace.KernelTelemetry;

/// <summary>
/// نموذج أحداث الأمان على مستوى النواة
/// Model for kernel-level security events
/// </summary>
public enum SecurityEventType
{
    ProcessCreated,
    ProcessTerminated,
    ThreadCreated,
    ImageLoaded,
    RegistryModified,
    FileModified,
    NetworkConnection,
    MemoryOperation,
    DriverLoaded,
    TokenManipulated
}

/// <summary>
/// خطورة حدث الأمان
/// Severity of the security event
/// </summary>
public enum SecurityEventSeverity
{
    Info,
    Low,
    Medium,
    High,
    Critical
}

/// <summary>
/// يمثل حدث أمان يتم رصده في طبقة الكيرنل
/// Represents a security event monitored in the kernel layer
/// </summary>
public record SecurityEvent(
    SecurityEventType Type,
    SecurityEventSeverity Severity,
    DateTime Timestamp,
    int ProcessId,
    string ProcessName,
    int ParentProcessId,
    string Description,
    Dictionary<string, string> Details,
    byte[] RawData
);
