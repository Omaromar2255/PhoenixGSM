using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using PhoenixGSM.MonitoringStudio.ViewModels;

namespace PhoenixGSM.MonitoringStudio.Views.Components;

public partial class TechnicianAuditView : UserControl
{
    private DateTime _lastProgrammaticScrollTime = DateTime.MinValue;
    private bool _isAutoPausedByUserScroll = false;

    public TechnicianAuditView()
    {
        InitializeComponent();

        Loaded += (s, e) =>
        {
            if (DataContext is MainViewModel vm)
            {
                vm.RequestTechAuditScrollToBottom += () =>
                {
                    Dispatcher.InvokeAsync(ScrollToBottom);
                };
            }
        };
    }

    public void ScrollToBottom()
    {
        _lastProgrammaticScrollTime = DateTime.UtcNow;
        _isAutoPausedByUserScroll = false;

        if (TechAuditDataGrid.Items.Count > 0)
        {
            try
            {
                TechAuditDataGrid.ScrollIntoView(TechAuditDataGrid.Items[TechAuditDataGrid.Items.Count - 1]);
            }
            catch
            {
                // Ignore transient layout updates
            }
        }
    }

    private void TechAuditDataGrid_PreviewMouseWheel(object sender, MouseWheelEventArgs e)
    {
        if (DataContext is MainViewModel vm)
        {
            if (e.Delta > 0)
            {
                // User scrolled UP -> Pause auto-scrolling
                if (vm.AutoScroll)
                {
                    _isAutoPausedByUserScroll = true;
                    vm.AutoScroll = false;
                }
            }
            else if (e.Delta < 0)
            {
                CheckIfAtBottomAndResume(vm);
            }
        }
    }

    private void TechAuditDataGrid_ScrollChanged(object sender, ScrollChangedEventArgs e)
    {
        if ((DateTime.UtcNow - _lastProgrammaticScrollTime).TotalMilliseconds < 250)
        {
            return;
        }

        if (DataContext is not MainViewModel vm) return;

        if (e.VerticalChange < 0)
        {
            if (vm.AutoScroll)
            {
                _isAutoPausedByUserScroll = true;
                vm.AutoScroll = false;
            }
        }
        else if (e.VerticalChange > 0)
        {
            CheckIfAtBottomAndResume(vm, e);
        }
    }

    private void CheckIfAtBottomAndResume(MainViewModel vm, ScrollChangedEventArgs? e = null)
    {
        if (!_isAutoPausedByUserScroll || vm.AutoScroll) return;

        if (e != null)
        {
            bool isAtBottom = e.VerticalOffset >= (e.ExtentHeight - e.ViewportHeight - 15);
            if (isAtBottom)
            {
                _isAutoPausedByUserScroll = false;
                vm.AutoScroll = true;
            }
        }
        else
        {
            var sv = FindScrollViewer(TechAuditDataGrid);
            if (sv != null)
            {
                bool isAtBottom = sv.VerticalOffset >= (sv.ExtentHeight - sv.ViewportHeight - 15);
                if (isAtBottom)
                {
                    _isAutoPausedByUserScroll = false;
                    vm.AutoScroll = true;
                }
            }
        }
    }

    private static ScrollViewer? FindScrollViewer(DependencyObject parent)
    {
        if (parent == null) return null;
        int count = VisualTreeHelper.GetChildrenCount(parent);
        for (int i = 0; i < count; i++)
        {
            var child = VisualTreeHelper.GetChild(parent, i);
            if (child is ScrollViewer sv) return sv;
            var res = FindScrollViewer(child);
            if (res != null) return res;
        }
        return null;
    }
}
