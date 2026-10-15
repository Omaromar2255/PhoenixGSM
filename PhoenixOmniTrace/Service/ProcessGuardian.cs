using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace PhoenixGSM.OmniTrace.Service;

/// <summary>
/// LAYER 16 — Process Self-Protection &amp; Restart Guardian
///
/// Problem: GSM tools (Global Unlocker, Chimera, UnlockTool) call
/// OpenProcess(PROCESS_TERMINATE) + TerminateProcess() on any process
/// whose name or window title matches their anti-snooping keyword list.
///
/// Solution: Modify the current process DACL to deny PROCESS_TERMINATE
/// permission to non-admin users. This is a standard Windows security
/// technique used by many services (SQL Server, antivirus, etc.) to
/// prevent unauthorized process termination.
///
/// Additionally maintains a "breadcrumb" file that an external launcher
/// can check to detect abnormal termination and auto-restart the application.
/// </summary>
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public sealed class ProcessGuardian : IDisposable
{
    private CancellationTokenSource? _cts;
    private Task? _watchdogTask;
    private string? _breadcrumbPath;

    public bool IsProtected { get; private set; }

    /// <summary>
    /// Apply process protection and start the watchdog.
    /// Call this early in application startup before creating windows.
    /// </summary>
    public void Activate(string? breadcrumbPath = null)
    {
        _breadcrumbPath = breadcrumbPath ?? StealthConfig.BreadcrumbPath;

        // 1. Harden process DACL — deny PROCESS_TERMINATE to non-owner
        HardenProcessDacl();

        // 2. Write running breadcrumb for external auto-restart launcher
        WriteBreadcrumb("RUNNING");

        // 3. Start watchdog to periodically re-apply DACL (some tools reset it)
        _cts = new CancellationTokenSource();
        _watchdogTask = Task.Run(() => WatchdogLoop(_cts.Token));

        IsProtected = true;
    }

    /// <summary>
    /// Modify the process DACL to deny PROCESS_TERMINATE (0x0001) to
    /// the Everyone group and Built-in Users, while preserving full
    /// access for the process Owner and Built-in Administrators.
    ///
    /// SDDL breakdown:
    ///   D:            — DACL follows
    ///   (D;;0x1;;;WD) — Deny PROCESS_TERMINATE to Everyone (World)
    ///   (D;;0x1;;;BU) — Deny PROCESS_TERMINATE to Built-in Users
    ///   (A;;GA;;;OW)  — Allow GENERIC_ALL to Owner
    ///   (A;;GA;;;BA)  — Allow GENERIC_ALL to Built-in Administrators
    /// </summary>
    private void HardenProcessDacl()
    {
        try
        {
            IntPtr hProcess = GetCurrentProcess();

            // SDDL: Deny TerminateProcess to Everyone & Users; Allow all to Owner & Admins
            const string sddl = "D:(D;;0x1;;;WD)(D;;0x1;;;BU)(A;;GA;;;OW)(A;;GA;;;BA)";

            if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
                    sddl, 1 /* SDDL_REVISION_1 */, out IntPtr pSD, out _))
            {
                return;
            }

            try
            {
                if (GetSecurityDescriptorDacl(pSD, out bool bDaclPresent, out IntPtr pDacl, out _)
                    && bDaclPresent && pDacl != IntPtr.Zero)
                {
                    // SE_KERNEL_OBJECT = 6, DACL_SECURITY_INFORMATION = 4
                    SetSecurityInfo(hProcess, 6, 4,
                        IntPtr.Zero, IntPtr.Zero, pDacl, IntPtr.Zero);
                }
            }
            finally
            {
                LocalFree(pSD);
            }
        }
        catch
        {
            // Fail-open: if DACL hardening fails (e.g. non-admin), continue unprotected
        }
    }

    private async Task WatchdogLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(10_000, ct);
                WriteBreadcrumb("RUNNING");
                HardenProcessDacl(); // Re-apply in case tools reset ACLs
            }
            catch (OperationCanceledException) { break; }
            catch { }
        }
    }

    private void WriteBreadcrumb(string status)
    {
        if (string.IsNullOrEmpty(_breadcrumbPath)) return;
        try
        {
            var dir = System.IO.Path.GetDirectoryName(_breadcrumbPath);
            if (dir != null) System.IO.Directory.CreateDirectory(dir);
            System.IO.File.WriteAllText(_breadcrumbPath,
                $"{status}|{DateTime.UtcNow:O}|{Environment.ProcessId}");
        }
        catch { }
    }

    /// <summary>
    /// Mark clean shutdown so external launcher knows this was intentional.
    /// </summary>
    public void MarkCleanShutdown()
    {
        WriteBreadcrumb("CLEAN_SHUTDOWN");
    }

    public void Dispose()
    {
        MarkCleanShutdown();
        _cts?.Cancel();
        try { _watchdogTask?.Wait(1000); } catch { }
        _cts?.Dispose();
    }

    // ═══ P/Invoke Declarations ═══

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
        string sddl, uint revision, out IntPtr pSD, out uint size);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetSecurityDescriptorDacl(
        IntPtr pSD, out bool bPresent, out IntPtr pDacl, out bool bDefaulted);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint SetSecurityInfo(
        IntPtr handle, int objectType, uint securityInfo,
        IntPtr psidOwner, IntPtr psidGroup, IntPtr pDacl, IntPtr pSacl);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr hMem);
}
