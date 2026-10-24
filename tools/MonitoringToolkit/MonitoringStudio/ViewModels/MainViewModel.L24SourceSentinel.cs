using System;
using System.Windows;
using System.Windows.Input;
using PhoenixGSM.MonitoringStudio.Models;
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
    /// مع ربطها المباشر بناقل OmniTraceEventBus لالتقاط كافة أوامر MTK والمودم والبورتات و ADB.
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
            _engine.OnEventReceived += item =>
            {
                try
                {
                    // إسقاط فوري عند تعطيل الطبقة L24 لتوفير موارد المعالج والذاكرة 100%
                    if (!vm.IsL24Active) return;

                    if (item.Category is EventSourceCategory.SerialPort or
                        EventSourceCategory.TempFileAt or
                        EventSourceCategory.MediaTek or
                        EventSourceCategory.QualcommEdl or
                        EventSourceCategory.UnisocSpd)
                    {
                        bool isIn = item.Direction is "IN" or "<<";
                        string cat = isIn
                            ? "Modem Phone Response"
                            : (item.Category == EventSourceCategory.MediaTek
                                ? "MediaTek BROM / DA Command"
                                : item.Category == EventSourceCategory.QualcommEdl
                                    ? "Qualcomm EDL / Firehose Protocol"
                                    : "Modem AT Command");

                        string prefix = isIn
                            ? "رد الهاتف الفعلي على أمر المودم: "
                            : "أمر مودم صريح صادر من الأداة: ";

                        vm.Orchestrator.PublishExternalTelemetryEvent(new SourceTelemetryEvent
                        {
                            Timestamp = item.Timestamp,
                            Stage = SentinelStage.RawCommandExecution,
                            HookedApiName = $"OmniBus_{item.SourceTag}",
                            CallerModuleOrigin = $"{item.Protocol} ({item.Direction})",
                            TargetResource = item.EndpointOrTarget,
                            CommandCategory = cat,
                            DecodedCommandText = item.Command.StartsWith("AT", StringComparison.OrdinalIgnoreCase) || isIn
                                ? $"{prefix}{item.Command}"
                                : item.Summary,
                            RawPayloadHex = item.RawPayload != null && item.RawPayload.Length > 0
                                ? BitConverter.ToString(item.RawPayload, 0, Math.Min(item.RawPayload.Length, 128)).Replace("-", "")
                                : string.Empty,
                            PayloadSize = item.RawPayload?.Length ?? item.Command.Length
                        });
                    }
                }
                catch { }
            };
        }
        catch { }
    }
}
