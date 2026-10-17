using System.Windows;
using System.Windows.Input;
using PhoenixOmniTrace.L24_SourceSentinel.UI;

namespace PhoenixGSM.MonitoringStudio.ViewModels;

public partial class MainViewModel
{
    private ICommand? _openSourceSentinelWindowCommand;

    /// <summary>
    /// زر مستقل لفتح نافذة طبقة الاعتراض المستقلة من المصدر L24_SourceSentinel
    /// مع ربطها المباشر بناقل OmniTraceEventBus لالتقاط كافة أوامر MTK والمودم والبورتات و ADB.
    /// </summary>
    public ICommand OpenSourceSentinelWindowCommand => _openSourceSentinelWindowCommand ??= new RelayCommand(_ =>
    {
        var win = new SourceSentinelWindow
        {
            Owner = Application.Current?.MainWindow
        };

        var vm = win.ViewModel ?? (win.DataContext as SourceSentinelViewModel);
        if (vm != null && _engine.OmniService?.EventBus != null)
        {
            vm.AttachToOmniTraceBus(_engine.OmniService.EventBus);
        }

        win.Show();
    });
}
