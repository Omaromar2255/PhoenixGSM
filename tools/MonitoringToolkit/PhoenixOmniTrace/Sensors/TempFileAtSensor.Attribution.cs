using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace PhoenixGSM.OmniTrace.Sensors;

public sealed partial class TempFileAtSensor
{
    private static readonly string[] KnownGsmTools =
    [
        "z3x", "octoplus", "chimera", "samfw", "odin", "3utools",
        "miflash", "qfil", "fastboot", "spflash", "umt", "hydra",
        "miracle", "unlocktool", "pandora", "dftpro", "easyjtag",
        "qunlock", "q-unlock", "simunlock", "sk_unlock", "skunlock",
        "globalunlocker", "global_unlocker", "global unlocker", "key-tool", "keytool",
        "athun", "trd", "samsungtool", "eftsu", "eft"
    ];

    private sealed record AttributionResult(string ProcessName, int ProcessId);

    private AttributionResult AttributeCreatingProcess(string filePath)
    {
        // 1. Try Windows Restart Manager API to identify process holding the handle
        try
        {
            var rmProc = QueryProcessLockingFile(filePath);
            if (rmProc != null)
            {
                return rmProc;
            }
        }
        catch { }

        // 2. Check if parent path contains tool name (e.g. Temp\UnlockTool\AT)
        try
        {
            string dir = Path.GetDirectoryName(filePath) ?? "";
            string[] parts = dir.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            foreach (var part in parts)
            {
                if (IsKnownGsmTool(part))
                {
                    string name = part.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? part : $"{part}.exe";
                    return new AttributionResult(name, 0);
                }
            }
        }
        catch { }

        // 3. Check active processes registered in correlation engine
        try
        {
            var active = _bus.Correlation.ActiveProcesses;
            if (active.Count > 0)
            {
                var candidate = active.FirstOrDefault(p => IsKnownGsmTool(p.ImageName));
                if (candidate != null)
                {
                    return new AttributionResult(candidate.ImageName, candidate.ProcessId);
                }
            }
        }
        catch { }

        // 4. Check active system running processes for known GSM tools
        try
        {
            var running = Process.GetProcesses();
            foreach (var p in running)
            {
                try
                {
                    string pName = p.ProcessName;
                    if (IsKnownGsmTool(pName))
                    {
                        int pid = p.Id;
                        string exeName = pName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? pName : $"{pName}.exe";
                        return new AttributionResult(exeName, pid);
                    }
                }
                catch { }
                finally
                {
                    p.Dispose();
                }
            }
        }
        catch { }

        // 5. Fallback default
        return new AttributionResult("Tool.exe", 0);
    }

    private static bool IsKnownGsmTool(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return false;
        foreach (var tool in KnownGsmTools)
        {
            if (name.Contains(tool, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    private static AttributionResult? QueryProcessLockingFile(string filePath)
    {
        uint handle = 0;
        string key = Guid.NewGuid().ToString();

        int res = RmStartSession(out handle, 0, key);
        if (res != 0) return null;

        try
        {
            string[] files = [filePath];
            res = RmRegisterResources(handle, (uint)files.Length, files, 0, null, 0, null);
            if (res != 0) return null;

            uint pnProcInfoNeeded = 0;
            uint pnProcInfo = 0;
            uint lpdwRebootReasons = 0;

            res = RmGetList(handle, out pnProcInfoNeeded, ref pnProcInfo, null, out lpdwRebootReasons);
            if (pnProcInfoNeeded == 0) return null;

            var processInfo = new RM_PROCESS_INFO[pnProcInfoNeeded];
            pnProcInfo = pnProcInfoNeeded;

            res = RmGetList(handle, out pnProcInfoNeeded, ref pnProcInfo, processInfo, out lpdwRebootReasons);
            if (res == 0 && pnProcInfo > 0)
            {
                var first = processInfo[0];
                int pid = first.Process.dwProcessId;
                string name = first.strAppName;

                if (pid > 0)
                {
                    try
                    {
                        using var proc = Process.GetProcessById(pid);
                        string procName = proc.ProcessName;
                        if (!procName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                            procName += ".exe";
                        return new AttributionResult(procName, pid);
                    }
                    catch { }
                }

                if (!string.IsNullOrWhiteSpace(name))
                {
                    if (!name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                        name += ".exe";
                    return new AttributionResult(name, pid);
                }
            }
        }
        catch
        {
            // Fail-open
        }
        finally
        {
            RmEndSession(handle);
        }

        return null;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct RM_UNIQUE_PROCESS
    {
        public int dwProcessId;
        public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;
    }

    private const int CCH_RM_MAX_APP_NAME = 255;
    private const int CCH_RM_MAX_SVC_NAME = 63;

    private enum RM_APP_TYPE
    {
        RmUnknownApp = 0,
        RmMainWindow = 1,
        RmOtherWindow = 2,
        RmService = 3,
        RmExplorer = 4,
        RmConsole = 5,
        RmCritical = 1000
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct RM_PROCESS_INFO
    {
        public RM_UNIQUE_PROCESS Process;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_APP_NAME + 1)]
        public string strAppName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_SVC_NAME + 1)]
        public string strServiceShortName;
        public RM_APP_TYPE ApplicationType;
        public uint AppStatus;
        public uint TSSessionId;
        [MarshalAs(UnmanagedType.Bool)]
        public bool bRestartable;
    }

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, string strSessionKey);

    [DllImport("rstrtmgr.dll")]
    private static extern int RmEndSession(uint pSessionHandle);

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmRegisterResources(uint pSessionHandle, uint nFiles, string[] rgsFileNames, uint nApplications, RM_UNIQUE_PROCESS[]? rgApplications, uint nServices, string[]? rgsServiceNames);

    [DllImport("rstrtmgr.dll")]
    private static extern int RmGetList(uint pSessionHandle, out uint pnProcInfoNeeded, ref uint pnProcInfo, [In, Out] RM_PROCESS_INFO[]? rgAffectedApps, out uint lpdwRebootReasons);
}
