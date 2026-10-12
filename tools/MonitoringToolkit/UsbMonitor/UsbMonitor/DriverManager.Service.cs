using System;
using System.Diagnostics;
using System.IO;

namespace PhoenixGSM.UsbMonitor;

public static partial class DriverManager
{
    public static bool InstallService(string? customSysPath = null)
    {
        string sysPath = customSysPath ?? GetDriverSysPath();
        if (!File.Exists(sysPath))
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  [-] Error: Driver binary not found at '{sysPath}'.");
            Console.ResetColor();
            return false;
        }

        if (IsServiceInstalled())
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"  [*] Service '{ServiceName}' is already registered.");
            Console.ResetColor();
            return true;
        }

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = $"create {ServiceName} type= kernel binPath= \"{sysPath}\" start= demand",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            p?.WaitForExit();
            string stdout = p?.StandardOutput.ReadToEnd() ?? "";
            string stderr = p?.StandardError.ReadToEnd() ?? "";

            if (p?.ExitCode == 0)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"  [+] Successfully registered service '{ServiceName}'.");
                Console.WriteLine($"      Binary: {sysPath}");
                Console.ResetColor();
                return true;
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"  [-] Failed to register service. Error: {stdout} {stderr}");
                Console.ResetColor();
                return false;
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  [-] Exception while creating service: {ex.Message}");
            Console.ResetColor();
            return false;
        }
    }

    public static bool StartService()
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = $"start {ServiceName}",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            p?.WaitForExit();
            string stdout = p?.StandardOutput.ReadToEnd() ?? "";

            if (p?.ExitCode == 0)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"  [+] Driver service '{ServiceName}' started successfully.");
                Console.ResetColor();
                return true;
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"  [!] Service start response: {stdout.Trim()}");
                if (stdout.Contains("577"))
                {
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine("      Note: Windows requires a reboot for 'bcdedit /set testsigning on' to take effect before unsigned/test-signed drivers can load.");
                    Console.ResetColor();
                }
                return false;
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  [-] Error starting service: {ex.Message}");
            Console.ResetColor();
            return false;
        }
    }

    public static bool StopService()
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = $"stop {ServiceName}",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            p?.WaitForExit();
            return p?.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    public static bool UninstallService()
    {
        StopService();

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = $"delete {ServiceName}",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            p?.WaitForExit();
            if (p?.ExitCode == 0)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"  [+] Driver service '{ServiceName}' uninstalled successfully.");
                Console.ResetColor();
                return true;
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"  [*] Service delete returned code {p?.ExitCode}.");
                Console.ResetColor();
                return false;
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  [-] Error deleting service: {ex.Message}");
            Console.ResetColor();
            return false;
        }
    }
}
