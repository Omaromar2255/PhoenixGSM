using System;
using System.Diagnostics;
using System.Runtime.Versioning;

namespace PhoenixGSM.OmniTrace.Rollback;

/// <summary>
/// Tracks a Windows service registration using native sc.exe utility.
/// يتتبع تسجيل خدمات الويندوز والتحكم بها عبر sc.exe لضمان التراجع التام بدون تبعيات إضافية.
/// </summary>
[SupportedOSPlatform("windows")]
public class ServiceChange : ISystemChange
{
    public string ChangeId { get; } = Guid.NewGuid().ToString();
    public string Description { get; }
    public DateTimeOffset Timestamp { get; } = DateTimeOffset.UtcNow;
    public bool IsApplied { get; private set; }

    private readonly string _serviceName;
    private readonly string _binPath;
    private bool _wasInstalled;
    private bool _wasRunning;

    public ServiceChange(string serviceName, string binPath, string description)
    {
        _serviceName = serviceName;
        _binPath = binPath;
        Description = description;
    }

    private static (bool Exists, bool Running) QueryServiceStatus(string name)
    {
        try
        {
            var psi = new ProcessStartInfo("sc.exe", $"query \"{name}\"")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true
            };
            using var p = Process.Start(psi);
            if (p == null) return (false, false);
            string output = p.StandardOutput.ReadToEnd();
            p.WaitForExit();

            if (p.ExitCode != 0 || output.Contains("1060")) // ERROR_SERVICE_DOES_NOT_EXIST
            {
                return (false, false);
            }

            bool isRunning = output.Contains("STATE") && output.Contains("RUNNING");
            return (true, isRunning);
        }
        catch
        {
            return (false, false);
        }
    }

    private static void RunScCommand(string args)
    {
        try
        {
            var psi = new ProcessStartInfo("sc.exe", args)
            {
                CreateNoWindow = true,
                UseShellExecute = false
            };
            using var p = Process.Start(psi);
            p?.WaitForExit(5000);
        }
        catch { }
    }

    public bool Apply()
    {
        try
        {
            var status = QueryServiceStatus(_serviceName);
            _wasInstalled = status.Exists;
            _wasRunning = status.Running;

            if (!_wasInstalled)
            {
                // Install via sc.exe create
                RunScCommand($"create \"{_serviceName}\" binPath= \"{_binPath}\" start= demand");
            }

            // Start service if not running
            var currentStatus = QueryServiceStatus(_serviceName);
            if (currentStatus.Exists && !currentStatus.Running)
            {
                RunScCommand($"start \"{_serviceName}\"");
            }

            IsApplied = true;
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ServiceChange] Apply failed: {ex.Message}");
            return false;
        }
    }

    public bool Revert()
    {
        if (!IsApplied) return true;

        try
        {
            var status = QueryServiceStatus(_serviceName);
            if (status.Exists)
            {
                if (!_wasRunning && status.Running)
                {
                    RunScCommand($"stop \"{_serviceName}\"");
                }

                if (!_wasInstalled)
                {
                    RunScCommand($"delete \"{_serviceName}\"");
                }
            }

            IsApplied = false;
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ServiceChange] Revert failed: {ex.Message}");
            return false;
        }
    }
}

