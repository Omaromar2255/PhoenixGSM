using System.Windows;

namespace PhoenixOmniTrace.L24_SourceSentinel.UI;

public partial class SourceSentinelWindow : Window
{
    public SourceSentinelViewModel? ViewModel => SentinelControl?.DataContext as SourceSentinelViewModel;

    public SourceSentinelWindow()
    {
        InitializeComponent();
        Title = "System Device Host";
    }
}
