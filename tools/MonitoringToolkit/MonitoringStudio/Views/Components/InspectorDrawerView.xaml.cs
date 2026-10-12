using System;
using System.Windows;
using System.Windows.Controls;
using PhoenixGSM.MonitoringStudio.ViewModels;

namespace PhoenixGSM.MonitoringStudio.Views.Components
{
    /// <summary>
    /// Interaction logic for InspectorDrawerView.xaml
    /// </summary>
    public partial class InspectorDrawerView : UserControl
    {
        private bool _isDrawerExpanded = true;

        /// <summary>
        /// Gets or sets whether the bottom drawer content area is expanded.
        /// </summary>
        public bool IsDrawerExpanded
        {
            get => _isDrawerExpanded;
            set
            {
                _isDrawerExpanded = value;
                UpdateDrawerState();
                DrawerToggled?.Invoke(this, _isDrawerExpanded);
            }
        }

        /// <summary>
        /// Fires when the drawer expanded state is toggled.
        /// </summary>
        public event EventHandler<bool>? DrawerToggled;

        public InspectorDrawerView()
        {
            InitializeComponent();
        }

        private void ToggleDrawer_Click(object sender, RoutedEventArgs e)
        {
            IsDrawerExpanded = !IsDrawerExpanded;
        }

        private void UpdateDrawerState()
        {
            if (DrawerContentGrid != null && DrawerContentRow != null)
            {
                if (_isDrawerExpanded)
                {
                    DrawerContentRow.Height = new GridLength(1, GridUnitType.Star);
                    DrawerContentGrid.Visibility = Visibility.Visible;
                }
                else
                {
                    DrawerContentRow.Height = GridLength.Auto;
                    DrawerContentGrid.Visibility = Visibility.Collapsed;
                }
            }

            if (ToggleDrawerBtn != null)
            {
                ToggleDrawerBtn.Content = _isDrawerExpanded ? "🔽 Collapse Drawer" : "🔼 Expand Drawer";
            }
        }

        private void CopyText_Click(object sender, RoutedEventArgs e)
        {
            if (DataContext is MainViewModel vm && vm.SelectedEvent != null)
            {
                if (!string.IsNullOrEmpty(vm.SelectedEvent.PayloadAscii))
                {
                    Clipboard.SetText(vm.SelectedEvent.PayloadAscii);
                    MessageBox.Show("Payload text copied to clipboard!", "Copied", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
        }

        private void CopyHex_Click(object sender, RoutedEventArgs e)
        {
            if (DataContext is MainViewModel vm && vm.SelectedEvent != null)
            {
                if (!string.IsNullOrEmpty(vm.SelectedEvent.PayloadHex))
                {
                    Clipboard.SetText(vm.SelectedEvent.PayloadHex);
                    MessageBox.Show("Hex dump copied to clipboard!", "Copied", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
        }
    }
}
