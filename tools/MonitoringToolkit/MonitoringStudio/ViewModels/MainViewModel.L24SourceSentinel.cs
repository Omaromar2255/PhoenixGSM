using System.Windows;
using System.Windows.Input;

namespace PhoenixGSM.MonitoringStudio.ViewModels;

public partial class MainViewModel
{
    private ICommand? _openSourceSentinelWindowCommand;

    /// <summary>
    /// زر مستقل لفتح نافذة طبقة الاعتراض المستقلة من المصدر L24_SourceSentinel
    /// </summary>
    public ICommand OpenSourceSentinelWindowCommand => _openSourceSentinelWindowCommand ??= new RelayCommand(_ =>
    {
        var win = new PhoenixOmniTrace.L24_SourceSentinel.UI.SourceSentinelWindow
        {
            Owner = Application.Current?.MainWindow
        };
        win.Show();
    });
}
