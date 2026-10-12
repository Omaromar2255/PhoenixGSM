using System;
using System.Diagnostics;
using System.Runtime.Versioning;

namespace PhoenixGSM.OmniTrace.Rollback;

/// <summary>
/// Tracks an ETW session creation.
/// يتتبع إنشاء جلسات ETW.
/// </summary>
[SupportedOSPlatform("windows")]
public class EtwSessionChange : ISystemChange
{
    public string ChangeId { get; } = Guid.NewGuid().ToString();
    public string Description { get; }
    public DateTimeOffset Timestamp { get; } = DateTimeOffset.UtcNow;
    public bool IsApplied { get; private set; }

    private readonly string _sessionName;
    private bool _wasExisting;

    public EtwSessionChange(string sessionName, string description)
    {
        _sessionName = sessionName;
        Description = description;
    }

    public bool Apply()
    {
        try
        {
            // Simple check using logman. التحقق باستخدام logman
            var checkInfo = new ProcessStartInfo("logman", $"query \"{_sessionName}\" -ets")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true
            };
            using var checkProc = Process.Start(checkInfo);
            checkProc?.WaitForExit();
            _wasExisting = checkProc?.ExitCode == 0;

            if (!_wasExisting)
            {
                // Start a basic ETW session. بدء الجلسة
                var startInfo = new ProcessStartInfo("logman", $"start \"{_sessionName}\" -p {{00000000-0000-0000-0000-000000000000}} -ets")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false
                };
                using var startProc = Process.Start(startInfo);
                startProc?.WaitForExit();
            }

            IsApplied = true;
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[EtwSessionChange] Apply failed: {ex.Message}");
            return false;
        }
    }

    public bool Revert()
    {
        if (!IsApplied) return true;

        try
        {
            if (!_wasExisting)
            {
                // Stop the ETW session. إيقاف الجلسة
                var stopInfo = new ProcessStartInfo("logman", $"stop \"{_sessionName}\" -ets")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false
                };
                using var stopProc = Process.Start(stopInfo);
                stopProc?.WaitForExit();
            }

            IsApplied = false;
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[EtwSessionChange] Revert failed: {ex.Message}");
            return false;
        }
    }
}
