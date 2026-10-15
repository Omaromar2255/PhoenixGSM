using System.Windows.Controls;
using PhoenixGSM.MonitoringStudio.ViewModels;

namespace PhoenixGSM.MonitoringStudio.Views.Components;

/// <summary>
/// Interaction logic for ToolSourceInterceptionView.xaml
/// </summary>
public partial class ToolSourceInterceptionView : UserControl
{
    public ToolSourceInterceptionView()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
    }

    private void OnDataContextChanged(object sender, System.Windows.DependencyPropertyChangedEventArgs e)
    {
        if (e.NewValue is MainViewModel vm)
        {
            vm.RequestToolSourceScrollToBottom += OnRequestScrollToBottom;
        }
        if (e.OldValue is MainViewModel oldVm)
        {
            oldVm.RequestToolSourceScrollToBottom -= OnRequestScrollToBottom;
        }
    }

    private void OnRequestScrollToBottom()
    {
        if (ToolSourceGrid.Items.Count > 0)
        {
            var lastItem = ToolSourceGrid.Items[^1];
            ToolSourceGrid.ScrollIntoView(lastItem);
        }
    }
}
