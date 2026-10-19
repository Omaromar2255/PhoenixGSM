using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PhoenixGSM.MonitoringStudio.Services;

public partial class MonitoringEngine
{
    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern IntPtr FindWindow(string? lpClassName, string? lpWindowName);

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern IntPtr FindWindowEx(IntPtr hwndParent, IntPtr hwndChildAfter, string? lpszClass, string? lpszWindow);

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    private static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    private static extern bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out int lpdwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("psapi.dll", SetLastError = true)]
    private static extern bool EnumProcessModulesEx(IntPtr hProcess, [Out] IntPtr[] lphModule, uint cb, out uint lpcbNeeded, uint dwFilterFlag);

    [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetModuleBaseName(IntPtr hProcess, IntPtr hModule, StringBuilder lpBaseName, uint nSize);

    private const uint WM_COMMAND = 0x0111;
    private const uint BM_CLICK = 0x00F5;
    private const int IDIGNORE = 5;
    private const int SW_HIDE = 0;

    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint PROCESS_VM_OPERATION = 0x0008;
    private const uint PROCESS_VM_READ = 0x0010;
    private const uint PROCESS_VM_WRITE = 0x0020;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint LIST_MODULES_ALL = 0x03;

    private static readonly ConcurrentDictionary<int, bool> _patchedMinGwProcesses = new();

    /// <summary>
    /// 1. Passively patches msvcrt.dll!_assert and _wassert in KEY-Tool.exe to immediate return (0xC3 = ret),
    ///    which is identical to clicking "Ignore" in 0ns without ever creating the modal MessageBox or freezing KEY-Tool.exe!
    /// 2. Also polls every 15ms to hide and dismiss any existing "MinGW Runtime Assertion" popup.
    /// </summary>
    private static async Task AutoDismissMinGwAssertionLoopAsync(CancellationToken token)
    {
        string[] assertionTitles =
        [
            "MinGW Runtime Assertion",
            "Microsoft Visual C++ Runtime Library"
        ];

        string[] ignoreButtonLabels =
        [
            "&Ignore",
            "Ignore",
            "تجاهل"
        ];

        int cycle = 0;

        while (!token.IsCancellationRequested)
        {
            try
            {
                // Every ~450ms, ensure KEY-Tool.exe has msvcrt!_assert patched to 0xC3 (ret = instant Ignore)
                if (cycle++ % 30 == 0)
                {
                    PatchKnownToolMinGwAssert();
                }

                foreach (string title in assertionTitles)
                {
                    IntPtr hDlg = FindWindow("#32770", title);
                    if (hDlg == IntPtr.Zero)
                    {
                        hDlg = FindWindow(null, title);
                    }

                    if (hDlg != IntPtr.Zero)
                    {
                        // Hide immediately so it never flickers on screen
                        ShowWindow(hDlg, SW_HIDE);

                        // Patch the owning process immediately so the dialog never pops up a second time
                        if (GetWindowThreadProcessId(hDlg, out int dlgPid) != 0 && dlgPid > 4)
                        {
                            TryPatchProcessMsvcrtAssert(dlgPid);
                        }

                        // Send IDIGNORE (5) directly to the dialog procedure and click the Ignore button
                        PostMessage(hDlg, WM_COMMAND, (IntPtr)IDIGNORE, IntPtr.Zero);
                        SendMessage(hDlg, WM_COMMAND, (IntPtr)IDIGNORE, IntPtr.Zero);

                        foreach (string btnText in ignoreButtonLabels)
                        {
                            IntPtr hBtn = FindWindowEx(hDlg, IntPtr.Zero, "Button", btnText);
                            if (hBtn != IntPtr.Zero)
                            {
                                PostMessage(hBtn, BM_CLICK, IntPtr.Zero, IntPtr.Zero);
                                break;
                            }
                        }
                    }
                }
            }
            catch { }

            await Task.Delay(15, token).ConfigureAwait(false);
        }
    }

    private static void PatchKnownToolMinGwAssert()
    {
        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    if (proc.Id <= 4 || proc.Id == Environment.ProcessId) continue;
                    if (_patchedMinGwProcesses.ContainsKey(proc.Id)) continue;

                    string pn = proc.ProcessName;
                    if (pn.Contains("KEY-Tool", StringComparison.OrdinalIgnoreCase) ||
                        pn.Contains("keytool", StringComparison.OrdinalIgnoreCase) ||
                        pn.Contains("AndroidBridge", StringComparison.OrdinalIgnoreCase))
                    {
                        if (TryPatchProcessMsvcrtAssert(proc.Id))
                        {
                            _patchedMinGwProcesses[proc.Id] = true;
                        }
                    }
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }
        catch { }
    }

    /// <summary>
    /// Locates msvcrt.dll (both 32-bit SysWOW64 and 64-bit System32) inside the target process,
    /// parses its PE Export Table in memory for "_assert" and "_wassert", and writes 0xC3 (ret)
    /// so MinGW assertions return immediately without opening a modal MessageBox or pausing USB threads.
    /// </summary>
    private static bool TryPatchProcessMsvcrtAssert(int pid)
    {
        IntPtr hProc = IntPtr.Zero;
        try
        {
            hProc = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
                false,
                pid);

            if (hProc == IntPtr.Zero) return false;

            IntPtr[] hMods = new IntPtr[1024];
            if (!EnumProcessModulesEx(hProc, hMods, (uint)(hMods.Length * IntPtr.Size), out uint cbNeeded, LIST_MODULES_ALL))
            {
                return false;
            }

            int count = Math.Min(hMods.Length, (int)(cbNeeded / (uint)IntPtr.Size));
            var sb = new StringBuilder(260);
            bool patchedAny = false;

            for (int i = 0; i < count; i++)
            {
                sb.Clear();
                if (GetModuleBaseName(hProc, hMods[i], sb, (uint)sb.Capacity) == 0) continue;
                string modName = sb.ToString();

                if (modName.Equals("msvcrt.dll", StringComparison.OrdinalIgnoreCase) ||
                    modName.Equals("ucrtbase.dll", StringComparison.OrdinalIgnoreCase))
                {
                    if (PatchExportedCdeclFunctionToRet(hProc, hMods[i], "_assert"))
                        patchedAny = true;
                    if (PatchExportedCdeclFunctionToRet(hProc, hMods[i], "_wassert"))
                        patchedAny = true;
                }
            }

            if (patchedAny)
            {
                _patchedMinGwProcesses[pid] = true;
            }
            return patchedAny;
        }
        catch
        {
            return false;
        }
        finally
        {
            if (hProc != IntPtr.Zero) CloseHandle(hProc);
        }
    }

    private static bool PatchExportedCdeclFunctionToRet(IntPtr hProc, IntPtr moduleBase, string targetExportName)
    {
        try
        {
            byte[] headerBuf = new byte[4096];
            if (!ReadProcessMemory(hProc, moduleBase, headerBuf, headerBuf.Length, out int readBytes) || readBytes < 512)
                return false;

            if (headerBuf[0] != 'M' || headerBuf[1] != 'Z') return false;
            int e_lfanew = BitConverter.ToInt32(headerBuf, 0x3C);
            if (e_lfanew <= 0 || e_lfanew + 0x90 > readBytes) return false;
            if (headerBuf[e_lfanew] != 'P' || headerBuf[e_lfanew + 1] != 'E') return false;

            ushort magic = BitConverter.ToUInt16(headerBuf, e_lfanew + 0x18);
            int exportDirOffset = magic switch
            {
                0x010B => e_lfanew + 0x78, // PE32 (32-bit WOW64)
                0x020B => e_lfanew + 0x88, // PE32+ (64-bit)
                _ => -1
            };
            if (exportDirOffset < 0) return false;

            uint exportDirRva = BitConverter.ToUInt32(headerBuf, exportDirOffset);
            uint exportDirSize = BitConverter.ToUInt32(headerBuf, exportDirOffset + 4);
            if (exportDirRva == 0 || exportDirSize == 0) return false;

            byte[] expDir = new byte[40];
            long baseAddr = moduleBase.ToInt64();
            if (!ReadProcessMemory(hProc, (IntPtr)(baseAddr + exportDirRva), expDir, 40, out int expRead) || expRead < 40)
                return false;

            uint numNames = BitConverter.ToUInt32(expDir, 24);
            uint addrOfFunctionsRva = BitConverter.ToUInt32(expDir, 28);
            uint addrOfNamesRva = BitConverter.ToUInt32(expDir, 32);
            uint addrOfNameOrdinalsRva = BitConverter.ToUInt32(expDir, 36);

            if (numNames == 0 || numNames > 16384) return false;

            byte[] nameRvasBuf = new byte[numNames * 4];
            byte[] ordinalsBuf = new byte[numNames * 2];
            if (!ReadProcessMemory(hProc, (IntPtr)(baseAddr + addrOfNamesRva), nameRvasBuf, nameRvasBuf.Length, out _) ||
                !ReadProcessMemory(hProc, (IntPtr)(baseAddr + addrOfNameOrdinalsRva), ordinalsBuf, ordinalsBuf.Length, out _))
            {
                return false;
            }

            byte[] nameBuf = new byte[32];
            for (int i = 0; i < numNames; i++)
            {
                uint nameRva = BitConverter.ToUInt32(nameRvasBuf, i * 4);
                if (nameRva == 0) continue;

                if (!ReadProcessMemory(hProc, (IntPtr)(baseAddr + nameRva), nameBuf, nameBuf.Length, out int nRead) || nRead <= 0)
                    continue;

                int len = Array.IndexOf(nameBuf, (byte)0, 0, nRead);
                if (len <= 0) continue;

                string exportName = Encoding.ASCII.GetString(nameBuf, 0, len);
                if (string.Equals(exportName, targetExportName, StringComparison.Ordinal))
                {
                    ushort ordinal = BitConverter.ToUInt16(ordinalsBuf, i * 2);
                    byte[] funcRvaBytes = new byte[4];
                    if (!ReadProcessMemory(hProc, (IntPtr)(baseAddr + addrOfFunctionsRva + (ordinal * 4U)), funcRvaBytes, 4, out _))
                        return false;

                    uint funcRva = BitConverter.ToUInt32(funcRvaBytes, 0);
                    // Ensure not a forwarded export
                    if (funcRva >= exportDirRva && funcRva < exportDirRva + exportDirSize)
                        return false;

                    IntPtr funcPtr = (IntPtr)(baseAddr + funcRva);
                    byte[] retPatch = [0xC3]; // x86/x64 near return (cdecl/fastcall caller cleans stack)

                    if (VirtualProtectEx(hProc, funcPtr, (UIntPtr)1, PAGE_EXECUTE_READWRITE, out uint oldProtect))
                    {
                        WriteProcessMemory(hProc, funcPtr, retPatch, 1, out _);
                        VirtualProtectEx(hProc, funcPtr, (UIntPtr)1, oldProtect, out _);
                        return true;
                    }
                }
            }
        }
        catch { }
        return false;
    }
}
