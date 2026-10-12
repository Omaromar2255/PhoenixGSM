using System;

namespace PhoenixGSM.OmniTrace.AdbForensics;

public enum AdbRiskLevel
{
    Safe,
    Low,
    Medium,
    High,
    Critical,
    Unknown
}

public enum AdbCommandCategory
{
    DeviceQuery,
    FileTransfer,
    ShellExecution,
    PackageManagement,
    SystemSettings,
    NetworkConfig,
    PermissionGrant,
    DebugControl,
    SecuritySensitive,
    Unknown
}

public record AdbCommandRisk(string Command, AdbRiskLevel RiskLevel, AdbCommandCategory Category, string Explanation)
{
    // Record already provides properties and constructor
    // التعليقات باللغة العربية والإنجليزية
    // Arabic and English comments
}
