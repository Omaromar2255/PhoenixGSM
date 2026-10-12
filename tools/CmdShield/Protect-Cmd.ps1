<#
.SYNOPSIS
    Phoenix CmdShield — Protects Command Prompt processes from being terminated by GSM tools.
.DESCRIPTION
    Applies Windows DACL Hardening to deny PROCESS_TERMINATE (0x0001) permission to Everyone and Built-in Users,
    effectively shielding cmd.exe against Q-Unlocker, Global Unlocker, and other anti-snooping tools.
#>

param(
    [int]$ProcessId = 0
)

$code = @"
using System;
using System.Runtime.InteropServices;

public class ProcessDaclHarden {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
        string sddl, uint revision, out IntPtr pSD, out uint size);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool GetSecurityDescriptorDacl(
        IntPtr pSD, out bool bPresent, out IntPtr pDacl, out bool bDefaulted);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern uint SetSecurityInfo(
        IntPtr handle, int objectType, uint securityInfo,
        IntPtr psidOwner, IntPtr psidGroup, IntPtr pDacl, IntPtr pSacl);

    [DllImport("kernel32.dll")]
    public static extern IntPtr LocalFree(IntPtr hMem);

    public static bool ProtectPid(int pid) {
        IntPtr hProcess = OpenProcess(0x00040000 | 0x00080000, false, pid); // WRITE_DAC | READ_CONTROL
        if (hProcess == IntPtr.Zero) return false;

        try {
            const string sddl = "D:(D;;0x1;;;WD)(D;;0x1;;;BU)(A;;GA;;;OW)(A;;GA;;;BA)";
            IntPtr pSD;
            uint size;
            if (!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1, out pSD, out size)) {
                return false;
            }

            IntPtr pDacl;
            bool present = false;
            bool defaulted = false;
            try {
                if (GetSecurityDescriptorDacl(pSD, out present, out pDacl, out defaulted) && present) {
                    uint res = SetSecurityInfo(hProcess, 6 /* SE_KERNEL_OBJECT */, 4 /* DACL */,
                        IntPtr.Zero, IntPtr.Zero, pDacl, IntPtr.Zero);
                    return res == 0;
                }
            } finally {
                LocalFree(pSD);
            }
        } finally {
            CloseHandle(hProcess);
        }
        return false;
    }
}
"@

if (-not ([System.Management.Automation.PSTypeName]'ProcessDaclHarden').Type) {
    Add-Type -TypeDefinition $code -Language CSharp
}

if ($ProcessId -gt 0) {
    $ok = [ProcessDaclHarden]::ProtectPid($ProcessId)
    if ($ok) {
        Write-Host "[+] Protected PID $ProcessId from PROCESS_TERMINATE" -ForegroundColor Green
    } else {
        Write-Host "[-] Failed to protect PID $ProcessId (Requires Admin)" -ForegroundColor Yellow
    }
} else {
    $cmds = Get-Process -Name "cmd" -ErrorAction SilentlyContinue
    if ($cmds) {
        foreach ($c in $cmds) {
            $ok = [ProcessDaclHarden]::ProtectPid($c.Id)
            if ($ok) {
                Write-Host "[+] Protected CMD PID $($c.Id) from termination" -ForegroundColor Green
            }
        }
    } else {
        Write-Host "[*] No active cmd.exe processes found to protect." -ForegroundColor Cyan
    }
}
