using System.IO;
using System.Windows;
using PhoenixGSM.MonitoringStudio.ViewModels;

namespace PhoenixGSM.MonitoringStudio;

public partial class MainWindow : Window
{
    private const int WM_CLOSE = 0x0010;
    private const int WM_QUERYENDSESSION = 0x0011;
    private const int WM_ENDSESSION = 0x0016;
    private const int WM_SYSCOMMAND = 0x0112;
    private const int SC_CLOSE = 0xF060;

    private bool _userInitiatedClose = false;
    private DateTime _lastUserCloseAttempt = DateTime.MinValue;

    public MainWindow()
    {
        try
        {
            File.AppendAllText(@"C:\Users\pc5\softwer\PhoenixGSM\gui_debug.log", $"[MainWindow] {DateTime.Now}: Constructor entering, calling InitializeComponent...\n");
            InitializeComponent();
            File.AppendAllText(@"C:\Users\pc5\softwer\PhoenixGSM\gui_debug.log", $"[MainWindow] {DateTime.Now}: InitializeComponent completed successfully!\n");
        }
        catch (Exception ex)
        {
            File.AppendAllText(@"C:\Users\pc5\softwer\PhoenixGSM\gui_debug.log", $"[MainWindow CRASH] {DateTime.Now}: InitializeComponent failed: {ex}\n");
            throw;
        }

        Loaded += (s, e) =>
        {
            if (DataContext is MainViewModel vm)
            {
                vm.RequestScrollToBottom += () =>
                {
                    Dispatcher.InvokeAsync(() =>
                    {
                        EventsGridComp.ScrollToBottom();
                    });
                };
            }

            InspectorComp.DrawerToggled += (invoker, isExpanded) =>
            {
                if (isExpanded)
                {
                    InspectorRow.Height = new GridLength(40, GridUnitType.Star);
                    InspectorRow.MinHeight = 140;
                }
                else
                {
                    InspectorRow.Height = GridLength.Auto;
                    InspectorRow.MinHeight = 32;
                }
            };
        };

        Closing += (s, e) =>
        {
            bool isRecentUserAction = (DateTime.UtcNow - _lastUserCloseAttempt).TotalSeconds < 2;
            if (!_userInitiatedClose && !isRecentUserAction)
            {
                e.Cancel = true;
                File.AppendAllText(@"C:\Users\pc5\softwer\PhoenixGSM\gui_debug.log", 
                    $"[Anti-Kill Shield] {DateTime.Now}: Blocked external Closing event! Window preserved.\n");
                return;
            }

            File.AppendAllText(@"C:\Users\pc5\softwer\PhoenixGSM\gui_debug.log", $"[Window Closing] Cancel={e.Cancel}\n");
            App.EnsureStockWindowsConfiguration();
        };

        Closed += (s, e) =>
        {
            File.AppendAllText(@"C:\Users\pc5\softwer\PhoenixGSM\gui_debug.log", $"[Window Closed]\n");
            App.EnsureStockWindowsConfiguration();
        };
    }

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        if (PresentationSource.FromVisual(this) is System.Windows.Interop.HwndSource source)
        {
            source.AddHook(WndProc);
        }
    }

    private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (msg == WM_SYSCOMMAND)
        {
            int sc = (int)wParam.ToInt64() & 0xFFF0;
            if (sc == SC_CLOSE)
            {
                _userInitiatedClose = true;
                _lastUserCloseAttempt = DateTime.UtcNow;
                File.AppendAllText(@"C:\Users\pc5\softwer\PhoenixGSM\gui_debug.log", 
                    $"[WndProc] {DateTime.Now}: User-initiated close via WM_SYSCOMMAND (SC_CLOSE).\n");
            }
        }
        else if (msg == WM_QUERYENDSESSION || msg == WM_ENDSESSION)
        {
            _userInitiatedClose = true;
            _lastUserCloseAttempt = DateTime.UtcNow;
        }
        else if (msg == WM_CLOSE)
        {
            bool isRecentUserAction = (DateTime.UtcNow - _lastUserCloseAttempt).TotalSeconds < 2;
            if (!_userInitiatedClose && !isRecentUserAction)
            {
                handled = true; // Drop message before WPF processes it
                File.AppendAllText(@"C:\Users\pc5\softwer\PhoenixGSM\gui_debug.log", 
                    $"[Anti-Kill Shield] {DateTime.Now}: DROPPED external WM_CLOSE injected by third-party process!\n");
                return IntPtr.Zero;
            }
        }

        return IntPtr.Zero;
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