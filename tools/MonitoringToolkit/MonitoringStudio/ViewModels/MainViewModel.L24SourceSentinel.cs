using System;
using System.IO;
using System.Windows;
using System.Windows.Input;
using PhoenixGSM.MonitoringStudio.Models;
using PhoenixOmniTrace.L24_SourceSentinel.Core;
using PhoenixOmniTrace.L24_SourceSentinel.Models;
using PhoenixOmniTrace.L24_SourceSentinel.UI;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.MonitoringStudio.ViewModels;

public partial class MainViewModel
{
    private SourceSentinelViewModel? _l24SentinelVm;
    public SourceSentinelViewModel L24SentinelViewModel => _l24SentinelVm ??= CreateBoundL24SentinelViewModel();

    public bool IsL24SentinelActive => _l24SentinelVm != null && _l24SentinelVm.IsL24Active;

    public string L24MasterStatusText => IsL24SentinelActive
        ? "🟢 نشطة"
        : "⏹️ معطلة";

    public string L24MasterStatusColor => IsL24SentinelActive ? "#34D399" : "#F87171";
    public string L24MasterButtonBackground => IsL24SentinelActive ? "#064E3B" : "#3B1219";
    public string L24MasterButtonBorder => IsL24SentinelActive ? "#10B981" : "#EF4444";
    public string L24MasterTooltip => IsL24SentinelActive
        ? "الطبقة 24 تعمل وتراقب بالخلفية. انقر هنا لإيقافها بالكامل وتوفير موارد الجهاز 100%."
        : "الطبقة 24 معطلة بالكامل ولا تستهلك أي موارد. انقر هنا لتشغيلها وتفعيل المراقبة الشاملة.";

    private ICommand? _toggleL24ActiveCommand;
    public ICommand ToggleL24ActiveCommand => _toggleL24ActiveCommand ??= new RelayCommand(_ =>
    {
        if (_l24SentinelVm == null)
        {
            var vm = L24SentinelViewModel; // Creates and starts it
        }
        else
        {
            _l24SentinelVm.ToggleL24MasterCommand.Execute(null);
        }
        NotifyL24StudioStateChanged();
    });

    public void NotifyL24StudioStateChanged()
    {
        OnPropertyChanged(nameof(IsL24SentinelActive));
        OnPropertyChanged(nameof(L24MasterStatusText));
        OnPropertyChanged(nameof(L24MasterStatusColor));
        OnPropertyChanged(nameof(L24MasterButtonBackground));
        OnPropertyChanged(nameof(L24MasterButtonBorder));
        OnPropertyChanged(nameof(L24MasterTooltip));
    }

    private ICommand? _openSourceSentinelWindowCommand;

    /// <summary>
    /// زر مستقل لفتح نافذة طبقة الاعتراض المستقلة من المصدر L24_SourceSentinel
    /// مع ربطها المباشر بناقل OmniTraceEventBus لالتقاط كافة أوامر الهاتف المنفذة والملفات والـ USB والـ ADB.
    /// </summary>
    public ICommand OpenSourceSentinelWindowCommand => _openSourceSentinelWindowCommand ??= new RelayCommand(_ =>
    {
        var win = new SourceSentinelWindow
        {
            Owner = Application.Current?.MainWindow,
            DataContext = L24SentinelViewModel
        };

        NotifyL24StudioStateChanged();
        win.Show();
    });

    public void InitializeL24SourceSentinelLayer()
    {
        _ = L24SentinelViewModel;
        NotifyL24StudioStateChanged();
    }

    private SourceSentinelViewModel CreateBoundL24SentinelViewModel()
    {
        var vm = new SourceSentinelViewModel();
        BindOmniTraceBusToL24(vm);
        return vm;
    }

    private void BindOmniTraceBusToL24(SourceSentinelViewModel vm)
    {
        try
        {
            // 1. ربط ناقل OmniService.EventBus الرئيسي مباشرة بجسر الطبقة 24 لضمان عدم ضياع أي أمر منطقي أو خام
            if (_engine.OmniService?.EventBus != null)
            {
                vm.AttachToOmniTraceBus(_engine.OmniService.EventBus);
            }

            // 2. تمرير كافة فئات الأحداث الحية من المحرك الرئيسي (UsbDriver, AdbProxy, Shell, Cmd, SerialPort, TempFileAt, MediaTek, QualcommEdl, UnisocSpd, AppleIos, Mtp, ToolSource, ArtifactVault)
            _engine.OnEventReceived += item =>
            {
                try
                {
                    if (!vm.IsL24Active || item == null) return;

                    // تجاهل رسائل حالة المحرك الداخلية
                    if (item.Protocol == "ENGINE" && (item.Command == "STARTED" || item.Command == "STOPPED"))
                        return;

                    bool isIn = item.Direction is "IN" or "<<" or "DEV->HOST";
                    SentinelStage stage = SentinelStage.RawCommandExecution;
                    string savedPath = string.Empty;

                    if (item.Category == EventSourceCategory.NetworkUrl)
                    {
                        stage = SentinelStage.NetworkPreEncryption;
                    }
                    else if (item.Category == EventSourceCategory.ArtifactVault)
                    {
                        stage = SentinelStage.LocalFilePreparation;
                        if (!string.IsNullOrWhiteSpace(item.EndpointOrTarget) && File.Exists(item.EndpointOrTarget))
                        {
                            if (L24FileArchiver.TryArchiveDiscoveredFile(item.EndpointOrTarget, $"StudioArtifactVault ({item.Protocol})", out string sPath, out _, out _))
                                savedPath = sPath;
                            else
                                savedPath = item.EndpointOrTarget;
                        }
                        else if (item.RawPayload != null && item.RawPayload.Length > 0)
                        {
                            string suggested = !string.IsNullOrWhiteSpace(item.Command) ? Path.GetFileName(item.Command) : "Captured_Artifact.bin";
                            if (L24FileArchiver.TryArchiveRawBuffer(item.RawPayload, suggested, $"StudioArtifactRaw ({item.Protocol})", out string sPath, out _, out _))
                                savedPath = sPath;
                        }
                    }

                    string cat = isIn
                        ? $"{item.Protocol} Phone Response"
                        : item.Category switch
                        {
                            EventSourceCategory.MediaTek => "MediaTek BROM / DA Command",
                            EventSourceCategory.QualcommEdl => "Qualcomm EDL / Firehose Protocol",
                            EventSourceCategory.UnisocSpd => "Unisoc / SPD BSL Frame",
                            EventSourceCategory.AppleIos => "Apple iOS / Lockdown / DFU Command",
                            EventSourceCategory.SerialPort or EventSourceCategory.TempFileAt => "Modem AT Command",
                            EventSourceCategory.AdbProxy or EventSourceCategory.Shell => "ADB / Interactive Shell",
                            EventSourceCategory.Cmd or EventSourceCategory.Process or EventSourceCategory.ToolSource => "Tool Command Execution",
                            EventSourceCategory.Mtp => "MTP Protocol Command",
                            EventSourceCategory.ArtifactVault => "Archived Helper / Loader File",
                            EventSourceCategory.NetworkUrl => "Network URL / Server Connection",
                            _ => $"{item.Protocol} Executed Command"
                        };

                    string pureCmd = !string.IsNullOrWhiteSpace(item.Command) ? item.Command.Trim() : item.Summary;
                    string summaryDesc = !string.IsNullOrWhiteSpace(item.Summary) ? item.Summary : pureCmd;

                    vm.Orchestrator.PublishExternalTelemetryEvent(new SourceTelemetryEvent
                    {
                        Timestamp = item.Timestamp,
                        Stage = stage,
                        HookedApiName = $"StudioEngine_{item.SourceTag}",
                        CallerModuleOrigin = $"{item.Protocol} ({item.Direction})",
                        TargetResource = !string.IsNullOrWhiteSpace(savedPath) ? savedPath : item.EndpointOrTarget,
                        CommandCategory = cat,
                        DecodedCommandText = summaryDesc,
                        PureCommandText = pureCmd,
                        SavedFilePath = savedPath,
                        RawPayloadHex = item.RawPayload != null && item.RawPayload.Length > 0
                            ? Convert.ToHexString(item.RawPayload.AsSpan(0, Math.Min(item.RawPayload.Length, 256)))
                            : string.Empty,
                        PayloadSize = item.RawPayload?.Length ?? pureCmd.Length
                    });
                }
                catch { }
            };
        }
        catch { }
    }
}
