using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using PhoenixGSM.MonitoringStudio.ViewModels;

namespace PhoenixGSM.MonitoringStudio.Views.Components
{
    /// <summary>
    /// Interaction logic for EventsGridView.xaml
    /// </summary>
    public partial class EventsGridView : UserControl
    {
        private DateTime _lastProgrammaticScrollTime = DateTime.MinValue;
        private bool _isAutoPausedByUserScroll = false;

        public EventsGridView()
        {
            InitializeComponent();
        }

        /// <summary>
        /// Provides direct access to the underlying DataGrid control.
        /// </summary>
        public DataGrid DataGridControl => EventsDataGrid;

        /// <summary>
        /// Scrolls the DataGrid to the bottom-most item.
        /// </summary>
        public void ScrollToBottom()
        {
            _lastProgrammaticScrollTime = DateTime.UtcNow;
            _isAutoPausedByUserScroll = false;

            if (EventsDataGrid.Items.Count > 0)
            {
                try
                {
                    EventsDataGrid.ScrollIntoView(EventsDataGrid.Items[EventsDataGrid.Items.Count - 1]);
                }
                catch
                {
                    // Ignore layout and virtualization race conditions
                }
            }
        }

        private void EventsDataGrid_PreviewMouseWheel(object sender, MouseWheelEventArgs e)
        {
            if (DataContext is MainViewModel vm)
            {
                if (e.Delta > 0)
                {
                    // User scrolled UP -> Pause auto-scrolling immediately so reading is uninterrupted
                    if (vm.AutoScroll)
                    {
                        _isAutoPausedByUserScroll = true;
                        vm.AutoScroll = false;
                    }
                }
                else if (e.Delta < 0)
                {
                    // User scrolled DOWN -> If they reach the bottom, resume auto-scrolling
                    CheckIfAtBottomAndResume(vm);
                }
            }
        }

        private void EventsDataGrid_ScrollChanged(object sender, ScrollChangedEventArgs e)
        {
            // Ignore programmatic scroll events triggered by our own ScrollToBottom
            if ((DateTime.UtcNow - _lastProgrammaticScrollTime).TotalMilliseconds < 250)
            {
                return;
            }

            if (DataContext is not MainViewModel vm) return;

            // User scrolled UP via vertical scrollbar drag or track click
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
                var sv = FindScrollViewer(EventsDataGrid);
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
}
