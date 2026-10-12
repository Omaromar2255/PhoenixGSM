using System;
using System.Collections.Generic;
using System.Linq;
using PhoenixGSM.MonitoringStudio.Models;
using PhoenixGSM.UsbMonitor;

namespace PhoenixGSM.MonitoringStudio.ViewModels;

public partial class MainViewModel
{
    private void InitializeSystemStatus()
    {
        bool testSigning = DriverManager.IsTestSigningEnabled();
        TestSigningText = testSigning ? "🟢 Enabled (BCD Mode)" : "🔴 Disabled";

        bool svcInstalled = DriverManager.IsServiceInstalled();
        string svcState = DriverManager.GetServiceStatus();
        bool devAccessible = _engine.IsDriverConnected;
        bool filterConfigured = DriverManager.IsPortAndModemFilterConfigured();

        _isFilterMonitoringEnabled = filterConfigured;
        OnPropertyChanged(nameof(IsFilterMonitoringEnabled));
        OnPropertyChanged(nameof(FilterMonitoringStatusText));
        OnPropertyChanged(nameof(FilterMonitoringStatusColor));
        OnPropertyChanged(nameof(FilterMonitoringButtonText));
        OnPropertyChanged(nameof(FilterMonitoringCardText));
        OnPropertyChanged(nameof(FilterToggleButtonText));

        if (filterConfigured)
        {
            DriverStatusText = "🟢 Active (Modem/Port Filter ON)";
            DriverStatusColor = "#00FF9D";
        }
        else if (devAccessible)
        {
            DriverStatusText = "⚪ Normal State (Stock - Filter OFF)";
            DriverStatusColor = "#8E9AA8";
        }
        else if (svcInstalled)
        {
            DriverStatusText = $"🟡 Registered ({svcState})";
            DriverStatusColor = "#FFB800";
        }
        else
        {
            DriverStatusText = "🔴 Not Installed";
            DriverStatusColor = "#FF5252";
        }
    }

    private void HandleEventReceived(LiveEventItem item)
    {
        _dispatcher.InvokeAsync(() =>
        {
            if (Events.Count >= 10000)
            {
                Events.RemoveAt(0);
            }

            Events.Add(item);
            TotalEventsCount++;

            if (IsPhoneDirectedCommand(item) || (IsCaptureDeviceResponsesEnabled && IsPhoneDeviceResponse(item)))
            {
                PhoneCommandsCount++;
            }

            switch (item.Category)
            {
                case EventSourceCategory.UsbDriver: UsbCount++; break;
                case EventSourceCategory.AdbProxy: AdbCount++; break;
                case EventSourceCategory.SerialPort: SerialCount++; break;
                case EventSourceCategory.Process: ProcessCount++; break;
                case EventSourceCategory.NetworkUrl: NetworkCount++; break;
                case EventSourceCategory.TempFileAt: TempAtCount++; break;
                case EventSourceCategory.Mtp: MtpCount++; break;
                case EventSourceCategory.MediaTek: MtkCount++; break;
                case EventSourceCategory.UnisocSpd: SpdCount++; break;
                case EventSourceCategory.QualcommEdl: EdlCount++; break;
                case EventSourceCategory.InProcess: InProcessCount++; break;
                case EventSourceCategory.AppleIos: AppleCount++; break;
                case EventSourceCategory.ArtifactVault: ArtifactVaultCount++; break;
                case EventSourceCategory.Cmd: CmdCount++; break;
                case EventSourceCategory.Shell: ShellCount++; break;
            }

            if (FilterEventPredicate(item))
            {
                VisibleEventsCount++;
            }
            else
            {
                HiddenEventsCount++;
                OnPropertyChanged(nameof(ExclusionBadgeText));
            }

            if (SelectedEvent == null)
            {
                SelectedEvent = item;
            }

            if (AutoScroll)
            {
                RequestScrollToBottom?.Invoke();
            }
        });
    }

    private void HandleTopologyChanged(List<PhoenixGSM.UsbMonitorDiscovery.Models.UsbDeviceInfo> devices)
    {
        _dispatcher.InvokeAsync(() =>
        {
            var phoneDevices = devices.Where(d => d.IsAndroidAdb || d.IsPhoneOrModem).ToList();
            if (phoneDevices.Count > 0)
            {
                var adbDevs = phoneDevices.Where(d => d.IsAndroidAdb).ToList();
                var modemDevs = phoneDevices.Where(d => !d.IsAndroidAdb && d.IsPhoneOrModem).ToList();

                var descriptions = phoneDevices.Select(d =>
                {
                    string name = d.DeviceName.Length > 20 ? d.DeviceName[..18] + ".." : d.DeviceName;
                    if (!string.IsNullOrWhiteSpace(d.AttachedPort))
                    {
                        return $"{name} [{d.AttachedPort}]";
                    }
                    if (d.IsPhoneOrModem && !d.IsAndroidAdb)
                    {
                        return $"{name} ({d.DeviceModeHint ?? "Modem/Normal"})";
                    }
                    return name;
                });

                string namesStr = string.Join(", ", descriptions);
                if (adbDevs.Count > 0 && modemDevs.Count > 0)
                {
                    ConnectedDevicesText = $"🟢 {phoneDevices.Count} Connected (ADB & Modem: {namesStr})";
                }
                else if (modemDevs.Count > 0)
                {
                    ConnectedDevicesText = $"📱 {modemDevs.Count} Phone/Modem ({namesStr})";
                }
                else
                {
                    ConnectedDevicesText = $"🟢 {adbDevs.Count} ADB Connected ({namesStr})";
                }
            }
            else if (devices.Count > 0)
            {
                ConnectedDevicesText = $"⚪ {devices.Count} USB Device(s) (No Phone/Modem)";
            }
            else
            {
                ConnectedDevicesText = "⚪ No USB Devices";
            }
        });
    }

    private void HandleComPortsChanged(string[] ports)
    {
        _dispatcher.InvokeAsync(() =>
        {
            if (ports.Length > 0)
            {
                ComPortsText = $"🟢 {ports.Length} Port(s) ({string.Join(", ", ports)})";
            }
            else
            {
                ComPortsText = "⚪ No COM Ports";
            }
        });
    }

    private void HandleToolsChanged(List<string> tools)
    {
        _dispatcher.InvokeAsync(() =>
        {
            if (tools.Count > 0)
            {
                DetectedToolsText = $"⚡ {string.Join(", ", tools)}";
            }
            else
            {
                DetectedToolsText = "⚪ Idle (No Tools)";
            }
        });
    }

    private void HandleDriverStatusChanged(bool active, string message)
    {
        _dispatcher.InvokeAsync(() =>
        {
            if (active)
            {
                DriverStatusText = $"🟢 {message}";
                DriverStatusColor = "#00FF9D";
            }
            else
            {
                DriverStatusText = $"🟡 {message}";
                DriverStatusColor = "#FFB800";
            }
        });
    }

    private bool FilterEventPredicate(object obj)
    {
        if (obj is not LiveEventItem item) return false;

        // "Show hidden logs only" logic
        if (ShowHiddenLogsOnly)
        {
            if (HiddenSourceTags.Count > 0 && !string.IsNullOrEmpty(item.SourceTag))
            {
                if (HiddenSourceTags.Contains(item.SourceTag)) return true;
            }
            return false; // If we only want hidden logs and this one isn't hidden, skip it.
        }

        // Dynamic SourceTag exclusions
        if (HiddenSourceTags.Count > 0 && !string.IsNullOrEmpty(item.SourceTag))
        {
            if (HiddenSourceTags.Contains(item.SourceTag)) return false;
        }

        // 1. Category Exclusions (استبعاد وإخفاء السجلات حسب طلب المستخدم)
        if (HideUrls && item.Category == EventSourceCategory.NetworkUrl) return false;
        if (HideAdb && item.Category == EventSourceCategory.AdbProxy) return false;
        if (HideUsb && item.Category == EventSourceCategory.UsbDriver) return false;
        if (HideSerial && item.Category == EventSourceCategory.SerialPort) return false;
        if (HideProcesses && item.Category == EventSourceCategory.Process) return false;
        if (HideTempAt && item.Category == EventSourceCategory.TempFileAt) return false;
        if (HideApple && item.Category == EventSourceCategory.AppleIos) return false;
        if (HideMtp && item.Category == EventSourceCategory.Mtp) return false;
        if (HideArtifacts && item.Category == EventSourceCategory.ArtifactVault) return false;
        if (HideCmd && item.Category == EventSourceCategory.Cmd) return false;
        if (HideShell && item.Category == EventSourceCategory.Shell) return false;

        // 2. Selected Tab Category check
        if (SelectedCategory != EventSourceCategory.All)
        {
            if (SelectedCategory == EventSourceCategory.PhoneCommands)
            {
                if (IsCaptureDeviceResponsesEnabled)
                {
                    if (!IsPhoneInteraction(item)) return false;
                }
                else
                {
                    if (!IsPhoneDirectedCommand(item)) return false;
                }
            }
            else if (SelectedCategory == EventSourceCategory.Process)
            {
                // When "⚙️ Tools" (Process) tab is selected:
                // Show all process-level actions, driver filter changes, utility commands, and sub-process executions
                bool isToolExecution = item.Category == EventSourceCategory.Process ||
                                       item.SourceTag == "TOOL-CMD" ||
                                       item.SourceTag == "TOOL-ACTION" ||
                                       item.SourceTag == "MTK-FILTER" ||
                                       item.SourceTag == "QCOM-FILTER" ||
                                       item.SourceTag == "SPD-FILTER" ||
                                       item.SourceTag == "USB-FILTER" ||
                                       item.SourceTag == "WMIC-QUERY" ||
                                       item.SourceTag == "DEVCON" ||
                                       item.SourceTag == "PNPUTIL" ||
                                       item.SourceTag == "DPINST" ||
                                       item.SourceTag == "CMD-EXEC" ||
                                       item.SourceTag == "GSM-PROC" ||
                                       item.SourceTag == "FIREHOSE-CLI" ||
                                       item.SourceTag == "MTK-CLI" ||
                                       item.SourceTag == "SPD-CLI" ||
                                       item.SourceTag == "APPLE-CLI";

                if (!isToolExecution) return false;
            }
            else if (SelectedCategory == EventSourceCategory.Cmd)
            {
                // When "🖥️ CMD" tab is selected:
                // Show CMD events, shell commands, batch executions, WMIC queries, DevCon, PnPUtil
                bool isCmdOrHost = item.Category == EventSourceCategory.Cmd ||
                                   item.Category == EventSourceCategory.Shell ||
                                   item.SourceTag == "CMD-EXEC" ||
                                   item.SourceTag == "CMD-HOST" ||
                                   item.SourceTag == "CMD-AUDIT" ||
                                   item.SourceTag == "WMIC-QUERY" ||
                                   item.SourceTag == "DEVCON" ||
                                   item.SourceTag == "PNPUTIL";

                if (!isCmdOrHost) return false;
            }
            else if (SelectedCategory == EventSourceCategory.MediaTek)
            {
                bool isMtk = item.Category == EventSourceCategory.MediaTek ||
                             item.SourceTag == "MTK-FILTER" ||
                             item.SourceTag == "MTK-TOOL" ||
                             item.SourceTag == "MTK-CLI";

                if (!isMtk) return false;
            }
            else if (SelectedCategory == EventSourceCategory.QualcommEdl)
            {
                bool isEdl = item.Category == EventSourceCategory.QualcommEdl ||
                             item.SourceTag == "QCOM-FILTER" ||
                             item.SourceTag == "QCOM-EDL" ||
                             item.SourceTag == "FIREHOSE-CLI";

                if (!isEdl) return false;
            }
            else if (SelectedCategory == EventSourceCategory.UnisocSpd)
            {
                bool isSpd = item.Category == EventSourceCategory.UnisocSpd ||
                             item.SourceTag == "SPD-FILTER" ||
                             item.SourceTag == "SPD-TOOL" ||
                             item.SourceTag == "SPD-CLI";

                if (!isSpd) return false;
            }
            else if (item.Category != SelectedCategory)
            {
                return false;
            }
        }

        // 3. Search text check
        if (!string.IsNullOrWhiteSpace(SearchText))
        {
            string q = SearchText.Trim().ToLower();
            bool matches =
                item.Command.ToLower().Contains(q) ||
                item.Summary.ToLower().Contains(q) ||
                item.EndpointOrTarget.ToLower().Contains(q) ||
                item.Protocol.ToLower().Contains(q) ||
                item.PayloadAscii.ToLower().Contains(q) ||
                item.AdditionalDetails.ToLower().Contains(q);

            if (!matches) return false;
        }

        return true;
    }

    /// <summary>
    /// Identifies pure Host-to-Device commands directed to the connected mobile phone.
    /// Filters out background OS noise, GoogleUpdater, inbound dump streams, and routine keep-alive ACKs.
    /// Delegates to PhoenixGSM.OmniTrace.Commands.PhoneCommandClassifier for universal cross-layer evaluation.
    /// </summary>
    public static bool IsPhoneDirectedCommand(LiveEventItem item)
    {
        if (item == null) return false;
        return PhoenixGSM.OmniTrace.Commands.PhoneCommandClassifier.IsPhoneDirectedCommand(
            item.Command,
            item.Summary,
            item.Direction,
            item.Protocol,
            item.Category.ToString(),
            item.AdditionalDetails);
    }

    /// <summary>
    /// Identifies incoming responses received from the connected mobile phone.
    /// Delegates to PhoenixGSM.OmniTrace.Commands.PhoneCommandClassifier.
    /// </summary>
    public static bool IsPhoneDeviceResponse(LiveEventItem item)
    {
        if (item == null) return false;
        return PhoenixGSM.OmniTrace.Commands.PhoneCommandClassifier.IsPhoneDeviceResponse(
            item.Command,
            item.Summary,
            item.Direction,
            item.Protocol,
            item.Category.ToString(),
            item.AdditionalDetails);
    }

    /// <summary>
    /// Evaluates if an event represents a phone interaction (command or response depending on configuration).
    /// </summary>
    public bool IsPhoneInteraction(LiveEventItem item)
    {
        if (item == null) return false;
        return PhoenixGSM.OmniTrace.Commands.PhoneCommandClassifier.IsPhoneInteraction(
            item.Command,
            item.Summary,
            item.Direction,
            item.Protocol,
            item.Category.ToString(),
            item.AdditionalDetails,
            includeResponses: IsCaptureDeviceResponsesEnabled);
    }

    /// <summary>
    /// Extracts the pure clean executable command from a LiveEventItem without any framing, timestamps, or noise.
    /// </summary>
    public static string? ExtractPurePhoneCommand(LiveEventItem item)
    {
        if (item == null) return null;
        return PhoenixGSM.OmniTrace.Commands.PhoneCommandClassifier.ExtractPureCommand(
            item.Command,
            item.Summary,
            item.Direction,
            item.Protocol,
            item.Category.ToString(),
            item.PayloadAscii,
            item.AdditionalDetails);
    }

    /// <summary>
    /// Extracts the clean response text from a LiveEventItem without framing.
    /// </summary>
    public static string? ExtractPurePhoneResponse(LiveEventItem item)
    {
        if (item == null) return null;
        return PhoenixGSM.OmniTrace.Commands.PhoneCommandClassifier.ExtractPureResponse(
            item.Command,
            item.Summary,
            item.Direction,
            item.Protocol,
            item.Category.ToString(),
            item.PayloadAscii,
            item.AdditionalDetails);
    }

    private void ClearLogs()
    {
        Events.Clear();
        TotalEventsCount = 0;
        PhoneCommandsCount = 0;
        UsbCount = 0;
        AdbCount = 0;
        SerialCount = 0;
        ProcessCount = 0;
        NetworkCount = 0;
        TempAtCount = 0;
        MtpCount = 0;
        MtkCount = 0;
        SpdCount = 0;
        EdlCount = 0;
        InProcessCount = 0;
        AppleCount = 0;
        ArtifactVaultCount = 0;
        CmdCount = 0;
        ShellCount = 0;
        SelectedEvent = null;
        VisibleEventsCount = 0;
        HiddenEventsCount = 0;
        OnPropertyChanged(nameof(ExclusionBadgeText));
    }
}
