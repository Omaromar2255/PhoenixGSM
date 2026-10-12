using System;
using System.Collections.Generic;
using PhoenixGSM.OmniTrace.HardwareDiff;
using PhoenixGSM.OmniTrace.SyscallDefense;
using PhoenixGSM.OmniTrace.ValidationSuite;

namespace PhoenixGSM.OmniTrace.Tests;

public static partial class Program
{
    private static bool Test54_DiagnosticHealthCheckSuite100PercentReadiness()
    {
        using var suite = new DiagnosticHealthCheckSuite();
        var report = suite.RunSensorReadinessAudit();
        return report.AllSensorsOperational && report.OperationalCount >= 12;
    }

    private static bool Test55_NtdllIntegrityCheckerTamperDetection()
    {
        using var checker = new NtdllIntegrityChecker();
        bool isClean = checker.AuditNtdllIntegrity(Environment.ProcessId, out var tampered);
        return isClean && tampered.Count == 0;
    }

    private static bool Test56_RawSectorDiffAuditorHardwareModifications()
    {
        using var auditor = new RawSectorDiffAuditor();
        var before = new Dictionary<string, string>
        {
            ["boot"] = "HASH_BOOT_V1",
            ["recovery"] = "HASH_RECOVERY_V1",
            ["modem"] = "HASH_MODEM_V1"
        };
        var after = new Dictionary<string, string>
        {
            ["boot"] = "HASH_BOOT_TAMPERED", // Tampered
            ["recovery"] = "HASH_RECOVERY_V1",
            // modem removed
            ["userdata"] = "HASH_USERDATA_NEW" // Added
        };

        var result = auditor.ComparePartitionHashes(before, after);
        return result.HasModifications &&
               result.ModifiedPartitions.Contains("boot") &&
               result.RemovedPartitions.Contains("modem") &&
               result.AddedPartitions.Contains("userdata");
    }
}
