using System.Windows.Controls;

namespace PhoenixOmniTrace.L24_SourceSentinel.UI;

public partial class SourceSentinelControl : UserControl
{
    public SourceSentinelControl()
    {
        InitializeComponent();
        if (DataContext == null)
        {
            DataContext = new SourceSentinelViewModel();
        }
    }
}
