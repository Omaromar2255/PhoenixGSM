using PhoenixGSM.MonitoringStudio.Models;

namespace PhoenixGSM.MonitoringStudio.ViewModels;

public partial class MainViewModel
{
    private LiveEventItem? _selectedEvent;
    public LiveEventItem? SelectedEvent
    {
        get => _selectedEvent;
        set { _selectedEvent = value; OnPropertyChanged(); }
    }

    private EventSourceCategory _selectedCategory = EventSourceCategory.All;
    public EventSourceCategory SelectedCategory
    {
        get => _selectedCategory;
        set
        {
            if (_selectedCategory != value)
            {
                _selectedCategory = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(IsAllSelected));
                OnPropertyChanged(nameof(IsPhoneCommandsSelected));
                OnPropertyChanged(nameof(IsUsbDriverSelected));
                OnPropertyChanged(nameof(IsAdbProxySelected));
                OnPropertyChanged(nameof(IsSerialPortSelected));
                OnPropertyChanged(nameof(IsProcessSelected));
                OnPropertyChanged(nameof(IsNetworkUrlSelected));
                OnPropertyChanged(nameof(IsTempFileAtSelected));
                OnPropertyChanged(nameof(IsMtpSelected));
                OnPropertyChanged(nameof(IsMediaTekSelected));
                OnPropertyChanged(nameof(IsUnisocSpdSelected));
                OnPropertyChanged(nameof(IsQualcommEdlSelected));
                OnPropertyChanged(nameof(IsAppleIosSelected));
                OnPropertyChanged(nameof(IsArtifactVaultSelected));
                OnPropertyChanged(nameof(IsCmdSelected));
                OnPropertyChanged(nameof(IsShellSelected));
                FilteredEvents.Refresh();
            }
        }
    }

    public bool IsAllSelected => SelectedCategory == EventSourceCategory.All;
    public bool IsPhoneCommandsSelected => SelectedCategory == EventSourceCategory.PhoneCommands;
    public bool IsUsbDriverSelected => SelectedCategory == EventSourceCategory.UsbDriver;
    public bool IsAdbProxySelected => SelectedCategory == EventSourceCategory.AdbProxy;
    public bool IsSerialPortSelected => SelectedCategory == EventSourceCategory.SerialPort;
    public bool IsProcessSelected => SelectedCategory == EventSourceCategory.Process;
    public bool IsNetworkUrlSelected => SelectedCategory == EventSourceCategory.NetworkUrl;
    public bool IsTempFileAtSelected => SelectedCategory == EventSourceCategory.TempFileAt;
    public bool IsMtpSelected => SelectedCategory == EventSourceCategory.Mtp;
    public bool IsMediaTekSelected => SelectedCategory == EventSourceCategory.MediaTek;
    public bool IsUnisocSpdSelected => SelectedCategory == EventSourceCategory.UnisocSpd;
    public bool IsQualcommEdlSelected => SelectedCategory == EventSourceCategory.QualcommEdl;
    public bool IsAppleIosSelected => SelectedCategory == EventSourceCategory.AppleIos;
    public bool IsArtifactVaultSelected => SelectedCategory == EventSourceCategory.ArtifactVault;
    public bool IsCmdSelected => SelectedCategory == EventSourceCategory.Cmd;
    public bool IsShellSelected => SelectedCategory == EventSourceCategory.Shell;

    private string _searchText = "";
    public string SearchText
    {
        get => _searchText;
        set
        {
            if (_searchText != value)
            {
                _searchText = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(IsAllSelected));
                OnPropertyChanged(nameof(IsUsbDriverSelected));
                OnPropertyChanged(nameof(IsAdbProxySelected));
                OnPropertyChanged(nameof(IsSerialPortSelected));
                OnPropertyChanged(nameof(IsProcessSelected));
                OnPropertyChanged(nameof(IsNetworkUrlSelected));
                OnPropertyChanged(nameof(IsTempFileAtSelected));
                OnPropertyChanged(nameof(IsMtpSelected));
                OnPropertyChanged(nameof(IsMediaTekSelected));
                OnPropertyChanged(nameof(IsUnisocSpdSelected));
                OnPropertyChanged(nameof(IsQualcommEdlSelected));
                OnPropertyChanged(nameof(IsAppleIosSelected));
                OnPropertyChanged(nameof(IsArtifactVaultSelected));
                OnPropertyChanged(nameof(IsCmdSelected));
                OnPropertyChanged(nameof(IsShellSelected));
                FilteredEvents.Refresh();
            }
        }
    }

    private bool _autoScroll = true;
    public bool AutoScroll
    {
        get => _autoScroll;
        set
        {
            if (_autoScroll != value)
            {
                _autoScroll = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(IsAutoScrollPaused));
                OnPropertyChanged(nameof(AutoScrollStatusText));
                OnPropertyChanged(nameof(AutoScrollButtonText));
                OnPropertyChanged(nameof(AutoScrollShortText));
                OnPropertyChanged(nameof(AutoScrollIcon));
                OnPropertyChanged(nameof(AutoScrollStatusColor));
                OnPropertyChanged(nameof(AutoScrollButtonBg));
                OnPropertyChanged(nameof(AutoScrollButtonBorder));
                if (value)
                {
                    RequestScrollToBottom?.Invoke();
                    RequestTechAuditScrollToBottom?.Invoke();
                }
            }
        }
    }

    public bool IsAutoScrollPaused => !AutoScroll;
    public string AutoScrollStatusText => AutoScroll ? "التمرير التلقائي: مفعّل (Auto-Scroll: ON)" : "التمرير التلقائي: متوقف (Auto-Scroll: OFF)";
    public string AutoScrollButtonText => AutoScroll ? "⏸️ إيقاف التمرير" : "▶️ استئناف التمرير";
    public string AutoScrollShortText => AutoScroll ? "Auto-Scroll: ON" : "Auto-Scroll: OFF";
    public string AutoScrollIcon => AutoScroll ? "🔄" : "⏸️";
    public string AutoScrollStatusColor => AutoScroll ? "#00FF9D" : "#FFB800";
    public string AutoScrollButtonBg => AutoScroll ? "#0C2E20" : "#2E2405";
    public string AutoScrollButtonBorder => AutoScroll ? "#00FF9D" : "#FFB800";

    private bool _isMonitoring = true;
    public bool IsMonitoring
    {
        get => _isMonitoring;
        set
        {
            _isMonitoring = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(MonitoringButtonText));
            OnPropertyChanged(nameof(MonitoringButtonColor));
        }
    }

    public string MonitoringButtonText => IsMonitoring ? "⏸ إيقاف مؤقت (Pause)" : "▶ بدء الالتقاط (Start)";
    public string MonitoringButtonColor => IsMonitoring ? "#E65100" : "#00B0FF";

    // Live Metrics & Status Texts
    private string _driverStatusText = "Checking...";
    public string DriverStatusText
    {
        get => _driverStatusText;
        set { _driverStatusText = value; OnPropertyChanged(); }
    }

    private string _driverStatusColor = "#FFB800";
    public string DriverStatusColor
    {
        get => _driverStatusColor;
        set { _driverStatusColor = value; OnPropertyChanged(); }
    }

    private string _testSigningText = "Checking...";
    public string TestSigningText
    {
        get => _testSigningText;
        set { _testSigningText = value; OnPropertyChanged(); }
    }

    private string _connectedDevicesText = "Scanning USB...";
    public string ConnectedDevicesText
    {
        get => _connectedDevicesText;
        set { _connectedDevicesText = value; OnPropertyChanged(); }
    }

    private string _comPortsText = "Scanning COM...";
    public string ComPortsText
    {
        get => _comPortsText;
        set { _comPortsText = value; OnPropertyChanged(); }
    }

    private string _detectedToolsText = "None Active";
    public string DetectedToolsText
    {
        get => _detectedToolsText;
        set { _detectedToolsText = value; OnPropertyChanged(); }
    }
}
