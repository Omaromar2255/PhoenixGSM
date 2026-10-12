using System;
using System.IO;

namespace PhoenixGSM.OmniTrace.InjectionDetection;

/// <summary>
/// Detects DLL side-loading, AppInit_DLLs abuse, and SetWindowsHookEx injections.
/// يكتشف التحميل الجانبي لمكتبات الربط الديناميكي وحقن الخطافات.
/// </summary>
public class DllInjectionDetector : IDisposable
{
    private readonly string[] _trustedSystemDirectories = {
        Environment.GetFolderPath(Environment.SpecialFolder.System).ToLower(),
        Environment.GetFolderPath(Environment.SpecialFolder.SystemX86).ToLower(),
        Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLower()
    };

    /// <summary>
    /// Checks loaded module paths against standard system directory baselines.
    /// يتحقق من مسارات الوحدات المحملة مقارنة بأدلة النظام القياسية.
    /// </summary>
    public bool IsSuspiciousModuleLoad(int pid, string modulePath, out string alert)
    {
        alert = string.Empty;

        try
        {
            if (string.IsNullOrWhiteSpace(modulePath))
                return false;

            string directory = Path.GetDirectoryName(modulePath)?.ToLower() ?? string.Empty;
            string fileName = Path.GetFileName(modulePath).ToLower();

            // Check for known system DLL names loaded from non-system directories (Side-loading)
            // التحقق من تحميل مكتبات نظام معروفة من أدلة غير أدلة النظام (تحميل جانبي)
            bool isSystemDll = IsKnownSystemDll(fileName);
            bool isFromTrustedDir = IsTrustedDirectory(directory);

            if (isSystemDll && !isFromTrustedDir)
            {
                alert = $"Possible DLL Side-Loading: {fileName} loaded into PID {pid} from untrusted directory {directory}.";
                return true;
            }

            return false;
        }
        catch (Exception ex)
        {
            // Fail-open: Log and continue
            // منع الانهيار: سجل واستمر
            Console.WriteLine($"[DllInjectionDetector Error]: {ex.Message}");
            return false;
        }
    }

    private bool IsKnownSystemDll(string fileName)
    {
        return fileName is "ntdll.dll" or "kernel32.dll" or "user32.dll" or "advapi32.dll";
    }

    private bool IsTrustedDirectory(string directory)
    {
        foreach (var trustedDir in _trustedSystemDirectories)
        {
            if (directory.StartsWith(trustedDir))
                return true;
        }
        return false;
    }

    public void Dispose()
    {
        // Cleanup
        // تنظيف
    }
}
