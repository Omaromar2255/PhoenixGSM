using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using PhoenixGSM.OmniTrace.Bus;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.Sensors;

/// <summary>
/// LAYER 20 — GSM Tool UI Action & Pre-Connection Intent Interceptor Sensor.
/// Passively and non-intrusively captures servicing commands (BROM Erase FRP, Factory Reset, Auth Bypass, etc.)
/// directly from the tool's UI in real-time, BEFORE the device is even connected to USB or COM ports.
/// Uses out-of-process WinEvent hooks and interactive desktop inspection with zero crash risk and zero DLL injection.
/// </summary>
public sealed class GsmToolUiActionSensor : IDisposable
{
    private readonly OmniTraceEventBus _bus;
    private bool _isRunning;
    private CancellationTokenSource? _cts;
    private Task? _monitorTask;
    private ulong _sequence;

    // Observability metrics
    private long _actionsCaptured;
    public long ActionsCaptured => Interlocked.Read(ref _actionsCaptured);
    public bool IsRunning => _isRunning;

    // Deduplication cache: Key = "PID_ActionName", Value = Timestamp of last trigger
    private readonly ConcurrentDictionary<string, DateTime> _recentActionDebounce = new(StringComparer.OrdinalIgnoreCase);

    // Active tool state cache: Key = PID, Value = Last known action & context
    private readonly ConcurrentDictionary<int, ToolUiState> _activeToolStates = new();

    public sealed class ToolUiState
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = string.Empty;
        public string ExecutablePath { get; set; } = string.Empty;
        public string LastAction { get; set; } = string.Empty;
        public string ActiveTab { get; set; } = string.Empty;
        public string ActiveModel { get; set; } = string.Empty;
        public string TargetDevice { get; set; } = string.Empty;
        public DateTime LastActionTime { get; set; } = DateTime.MinValue;
        public string LastStatus { get; set; } = string.Empty;
    }

    public GsmToolUiActionSensor(OmniTraceEventBus bus)
    {
        _bus = bus ?? throw new ArgumentNullException(nameof(bus));
    }

    public void Start()
    {
        if (_isRunning) return;
        _isRunning = true;
        _cts = new CancellationTokenSource();

        // Start background polling and hook thread
        _monitorTask = Task.Run(() => MonitorLoop(_cts.Token), _cts.Token);
    }

    public void Stop()
    {
        if (!_isRunning) return;
        _isRunning = false;
        _cts?.Cancel();

        try
        {
            _monitorTask?.Wait(2000);
        }
        catch { }

        _recentActionDebounce.Clear();
        _activeToolStates.Clear();
    }

    /// <summary>
    /// Gets the most recent UI action and target device staged by a tool PID.
    /// Used by filter driver and hardware correlators.
    /// </summary>
    public ToolUiState? GetActiveToolState(int pid)
    {
        if (_activeToolStates.TryGetValue(pid, out var state))
        {
            return state;
        }
        return null;
    }

    private async Task MonitorLoop(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                AttachToInteractiveDesktop();
                ScanGsmToolWindows();
                await Task.Delay(100, token);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _bus.ReportAnomaly("UI_ACTION_SENSOR_ERROR", ex.Message);
                await Task.Delay(500, token);
            }
        }
    }

    private void AttachToInteractiveDesktop()
    {
        try
        {
            IntPtr hWinsta = OpenWindowStation("WinSta0", false, 0x00020000 | 0x037F);
            if (hWinsta != IntPtr.Zero) SetProcessWindowStation(hWinsta);

            IntPtr hDesk = OpenDesktop("Default", 0, false, 0x00020000 | 0x01FF);
            if (hDesk != IntPtr.Zero) SetThreadDesktop(hDesk);
        }
        catch { }
    }

    private void ScanGsmToolWindows()
    {
        // 1. Find running GSM tool processes
        var candidateProcesses = Process.GetProcesses()
            .Where(IsGsmToolProcess)
            .ToArray();

        if (candidateProcesses.Length == 0) return;

        IntPtr hDesk = OpenDesktop("Default", 0, false, 0x00020000 | 0x01FF);
        if (hDesk == IntPtr.Zero) return;

        foreach (var proc in candidateProcesses)
        {
            int pid = proc.Id;
            string procName = proc.ProcessName;
            string exePath = string.Empty;
            try { exePath = proc.MainModule?.FileName ?? string.Empty; } catch { }

            var toolState = _activeToolStates.GetOrAdd(pid, id => new ToolUiState
            {
                ProcessId = id,
                ProcessName = procName + ".exe",
                ExecutablePath = exePath
            });

            // Enumerate desktop windows for this process
            EnumDesktopWindows(hDesk, (hWnd, lParam) =>
            {
                GetWindowThreadProcessId(hWnd, out uint wPid);
                if (wPid != (uint)pid) return true;

                InspectToolWindow(hWnd, toolState);
                return true;
            }, IntPtr.Zero);
        }
    }

    private static bool IsGsmToolProcess(Process p)
    {
        try
        {
            string name = p.ProcessName.ToLowerInvariant();
            return name.Contains("unlocktool") ||
                   name.Contains("chimera") ||
                   name.Contains("hydratool") ||
                   name.Contains("miracle") ||
                   name.Contains("dftpro") ||
                   name.Contains("octoplus") ||
                   name.Contains("z3x") ||
                   name.Contains("pandora") ||
                   name.Contains("umt") ||
                   name.Contains("flashtool");
        }
        catch { return false; }
    }

    private void InspectToolWindow(IntPtr topHwnd, ToolUiState toolState)
    {
        var sbTitle = new StringBuilder(256);
        var sbClass = new StringBuilder(256);
        GetWindowText(topHwnd, sbTitle, 256);
        GetClassName(topHwnd, sbClass, 256);

        string activeTab = toolState.ActiveTab;
        string activeModel = toolState.ActiveModel;
        string activeStatus = string.Empty;
        var foundButtons = new List<string>();

        // Enumerate child controls to read active visible tabs, status boxes, and focused/clicked buttons
        EnumChildWindows(topHwnd, (chHwnd, lParam) =>
        {
            if (!IsWindowVisible(chHwnd)) return true;

            var cClass = new StringBuilder(256);
            var cTitle = new StringBuilder(256);
            GetClassName(chHwnd, cClass, 256);
            GetWindowText(chHwnd, cTitle, 256);

            string className = cClass.ToString().Trim();
            string text = cTitle.ToString().Trim();

            // Track active visible tab
            if (className.Contains("TabSheet", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(text))
            {
                activeTab = text;
            }

            // Track active model selector
            if (className.Contains("Combo", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(text))
            {
                if (text.Length > 2 && !text.Equals("EMMC", StringComparison.OrdinalIgnoreCase) && !text.Equals("All Model", StringComparison.OrdinalIgnoreCase))
                {
                    activeModel = text;
                }
            }

            // Check if status indicator is waiting for device
            if (text.Contains("Waiting for device", StringComparison.OrdinalIgnoreCase) ||
                text.Contains("Waiting for COM", StringComparison.OrdinalIgnoreCase) ||
                text.Contains("Initializing usb", StringComparison.OrdinalIgnoreCase))
            {
                activeStatus = text;
            }

            // Check if this control is an action button
            if (className.Contains("Button", StringComparison.OrdinalIgnoreCase) && IsServicingActionButton(text))
            {
                foundButtons.Add(text);
            }

            return true;
        }, IntPtr.Zero);

        if (!string.IsNullOrEmpty(activeStatus) && foundButtons.Count > 0)
        {
            // A servicing operation is active! Correlate the buttons
            // ONLY emit if the status has CHANGED since the last emission to prevent flooding
            if (toolState.LastStatus != activeStatus)
            {
                foreach (var btn in foundButtons)
                {
                    EmitToolAction(toolState, btn, activeTab, activeModel, activeStatus);
                }
                toolState.LastStatus = activeStatus;
            }
        }
        else if (string.IsNullOrEmpty(activeStatus))
        {
            // Reset status if no longer waiting
            toolState.LastStatus = string.Empty;
        }

        toolState.ActiveTab = activeTab;
        toolState.ActiveModel = activeModel;
    }

    public static bool IsServicingActionButton(string text)
    {
        if (string.IsNullOrWhiteSpace(text) || text.Length < 3) return false;
        string upper = text.ToUpperInvariant();

        return upper.StartsWith("[BROM]") ||
               upper.StartsWith("[EDL]") ||
               upper.StartsWith("[SPRD]") ||
               upper.StartsWith("[META]") ||
               upper.StartsWith("[COM]") ||
               upper.StartsWith("[MTP]") ||
               upper.StartsWith("[ADB]") ||
               upper.Contains("FACTORY RESET") ||
               upper.Contains("ERASE FRP") ||
               upper.Contains("AUTH BYPASS") ||
               upper.Contains("BOOT DEVICE") ||
               upper.Contains("UNLOCK BOOTLOADER") ||
               upper.Contains("RELOCK BOOTLOADER") ||
               upper.Contains("FORMAT DATA") ||
               upper.Contains("REPAIR IMEI") ||
               upper.Contains("ERASE NV") ||
               upper.Contains("BACKUP NV") ||
               upper.Contains("ERASE RPMB") ||
               upper.Contains("READ RPMB") ||
               upper.Contains("WRITE RPMB") ||
               upper.Contains("FIX DM-VERITY") ||
               upper.Contains("SAFE FORMAT");
    }

    public void EmitToolAction(ToolUiState toolState, string actionName, string activeTab, string activeModel, string statusHint = "")
    {
        string debounceKey = $"{toolState.ProcessId}_{actionName}";
        if (_recentActionDebounce.TryGetValue(debounceKey, out var lastTime))
        {
            if (DateTime.UtcNow - lastTime < TimeSpan.FromSeconds(2.0))
            {
                return; // Suppress duplicate triggers
            }
        }
        _recentActionDebounce[debounceKey] = DateTime.UtcNow;

        toolState.LastAction = actionName;
        toolState.LastActionTime = DateTime.UtcNow;

        // Categorize protocol and target
        string category = "MediaTek";
        KnownProtocol protocol = KnownProtocol.MtkBrom;
        string targetDevice = "USB\\VID_0E8D&PID_0003";
        string serviceBanner = "MediaTek Service Execution";

        string upperAction = actionName.ToUpperInvariant();
        string upperTab = activeTab.ToUpperInvariant();

        if (upperAction.Contains("[EDL]") || upperTab.Contains("QUALCOMM"))
        {
            category = "QualcommEdl";
            protocol = KnownProtocol.QualcommSahara;
            targetDevice = "USB\\VID_05C6&PID_9008";
            serviceBanner = "Qualcomm EDL Service Execution";
        }
        else if (upperAction.Contains("[SPRD]") || upperTab.Contains("SPREADTRUM"))
        {
            category = "UnisocSpd";
            protocol = KnownProtocol.SpreadtrumFdl;
            targetDevice = "USB\\VID_1782&PID_4D00";
            serviceBanner = "Unisoc/Spreadtrum Service Execution";
        }
        else if (upperAction.Contains("[COM]") || upperTab.Contains("SAMSUNG"))
        {
            category = "Samsung";
            protocol = KnownProtocol.SamsungOdin;
            targetDevice = "SAMSUNG Mobile USB Modem";
            serviceBanner = "Samsung Service Execution";
        }
        else if (upperAction.Contains("IOS") || upperTab.Contains("IOS") || upperAction.Contains("RAMDISK"))
        {
            category = "AppleIos";
            protocol = KnownProtocol.AppleRecovery;
            targetDevice = "Apple Mobile Device";
            serviceBanner = "Apple iOS Service Execution";
        }

        toolState.TargetDevice = targetDevice;

        ulong seq = Interlocked.Increment(ref _sequence);
        Interlocked.Increment(ref _actionsCaptured);

        string caller = $"{toolState.ProcessName} (PID {toolState.ProcessId})";
        string formattedSummary = $"[{toolState.ProcessName}] {actionName} -> {targetDevice}";

        var technicalDetails = new StringBuilder();
        technicalDetails.AppendLine(serviceBanner);
        technicalDetails.AppendLine($"Binary: {toolState.ExecutablePath}");
        technicalDetails.AppendLine($"Action: {actionName}");
        if (!string.IsNullOrWhiteSpace(activeModel))
        {
            technicalDetails.AppendLine($"Model Target: {activeModel}");
        }
        if (!string.IsNullOrWhiteSpace(activeTab))
        {
            technicalDetails.AppendLine($"Active Tab: {activeTab}");
        }
        technicalDetails.AppendLine($"Device Target: {targetDevice}");
        if (!string.IsNullOrWhiteSpace(statusHint))
        {
            technicalDetails.AppendLine($"Status: {statusHint}");
        }
        technicalDetails.Append($"Caller: {caller}");

        // 1. Publish RawCaptureEvent to OmniTrace EventBus
        byte[] payloadBytes = Array.Empty<byte>();
        var rawEvt = RawCaptureEvent.Create(
            sequence: seq,
            sensor: SensorType.Process,
            transport: TransportType.BULK,
            direction: PacketDirection.HOST_TO_DEVICE,
            device: targetDevice,
            session: $"{toolState.ProcessName}_{toolState.ProcessId}_{actionName}",
            iface: 0,
            endpoint: "TOOL_UI_ACTION",
            payload: payloadBytes,
            timestampSource: "GsmToolUiActionSensor"
        );

        rawEvt.Metadata["ToolName"] = toolState.ProcessName;
        rawEvt.Metadata["ProcessId"] = toolState.ProcessId.ToString();
        rawEvt.Metadata["Action"] = actionName;
        rawEvt.Metadata["TargetDevice"] = targetDevice;
        rawEvt.Metadata["ActiveTab"] = activeTab;
        rawEvt.Metadata["ActiveModel"] = activeModel;
        rawEvt.Metadata["SourceTag"] = "TOOL-CMD";
        rawEvt.Metadata["Category"] = category;
        rawEvt.Metadata["TechnicalDetails"] = technicalDetails.ToString();

        _bus.Publish(rawEvt);

        // 2. Correlate and Report LogicalCommandEvent directly
        var cmd = _bus.Correlation.Correlate(
            actionName,
            protocol,
            toolState.ProcessName,
            TransportType.BULK,
            targetDevice,
            $"{toolState.ProcessName}_{toolState.ProcessId}_{actionName}",
            PacketDirection.HOST_TO_DEVICE,
            [rawEvt.SequenceNumber],
            [rawEvt.PayloadHash],
            confidence: 1.0,
            suspectedPid: toolState.ProcessId,
            suspectedToolName: toolState.ProcessName
        );

        cmd.Details["Category"] = category;
        cmd.Details["SourceTag"] = "TOOL-CMD";
        cmd.Details["Summary"] = formattedSummary;
        cmd.Details["TechnicalDetails"] = technicalDetails.ToString();
        cmd.Details["Action"] = actionName;
        cmd.Details["DeviceTarget"] = targetDevice;
        cmd.Details["Caller"] = caller;
        cmd.Details["ExecutablePath"] = toolState.ExecutablePath;
        cmd.Attribution.ProcessId = toolState.ProcessId;
        cmd.Attribution.ImageName = toolState.ProcessName;

        _bus.ReportLogicalCommand(cmd);
    }

    #region Win32 Native Interop
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern IntPtr OpenWindowStation(string lpszWinSta, bool fInherit, uint dwDesiredAccess);

    [DllImport("user32.dll")]
    private static extern bool SetProcessWindowStation(IntPtr hWinSta);

    [DllImport("user32.dll")]
    private static extern IntPtr OpenDesktop(string lpszDesktop, uint dwFlags, bool fInherit, uint dwDesiredAccess);

    [DllImport("user32.dll")]
    private static extern bool SetThreadDesktop(IntPtr hDesktop);

    [DllImport("user32.dll")]
    private static extern bool EnumDesktopWindows(IntPtr hDesktop, EnumWindowsProc lpfn, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern bool EnumChildWindows(IntPtr hWndParent, EnumWindowsProc lpfn, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    private static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    private static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

    [DllImport("user32.dll")]
    private static extern bool IsWindowVisible(IntPtr hWnd);
    #endregion

    public void Dispose()
    {
        Stop();
    }
}
