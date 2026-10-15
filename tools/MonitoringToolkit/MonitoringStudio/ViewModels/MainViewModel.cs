using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Threading;
using PhoenixGSM.MonitoringStudio.Models;
using PhoenixGSM.MonitoringStudio.Services;

namespace PhoenixGSM.MonitoringStudio.ViewModels;

public partial class MainViewModel : INotifyPropertyChanged
{
    private readonly MonitoringEngine _engine = new();
    private readonly Dispatcher _dispatcher;

    public ObservableCollection<LiveEventItem> Events { get; } = [];
    public ICollectionView FilteredEvents { get; }

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

    // ══════════════════════════════════════════════════════════════
    // Granular Sensor Capture Flags (تشغيل / إيقاف كل مجس على حدة)
    // ══════════════════════════════════════════════════════════════
    public bool IsUsbMonitoringEnabled
    {
        get => _engine.IsUsbMonitoringEnabled;
        set
        {
            if (_engine.IsUsbMonitoringEnabled != value)
            {
                _engine.IsUsbMonitoringEnabled = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(UsbMonitoringStatusText));
                OnPropertyChanged(nameof(UsbMonitoringStatusColor));
            }
        }
    }
    public string UsbMonitoringStatusText => IsUsbMonitoringEnabled ? "ON" : "OFF";
    public string UsbMonitoringStatusColor => IsUsbMonitoringEnabled ? "#00E5FF" : "#607286";

    public bool IsAdbMonitoringEnabled
    {
        get => _engine.IsAdbMonitoringEnabled;
        set
        {
            if (_engine.IsAdbMonitoringEnabled != value)
            {
                _engine.IsAdbMonitoringEnabled = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(AdbMonitoringStatusText));
                OnPropertyChanged(nameof(AdbMonitoringStatusColor));
            }
        }
    }
    public string AdbMonitoringStatusText => IsAdbMonitoringEnabled ? "ON" : "OFF";
    public string AdbMonitoringStatusColor => IsAdbMonitoringEnabled ? "#00FF9D" : "#607286";

    public bool IsSerialMonitoringEnabled
    {
        get => _engine.IsSerialMonitoringEnabled;
        set
        {
            if (_engine.IsSerialMonitoringEnabled != value)
            {
                _engine.IsSerialMonitoringEnabled = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(SerialMonitoringStatusText));
                OnPropertyChanged(nameof(SerialMonitoringStatusColor));
            }
        }
    }
    public string SerialMonitoringStatusText => IsSerialMonitoringEnabled ? "ON" : "OFF";
    public string SerialMonitoringStatusColor => IsSerialMonitoringEnabled ? "#FFB800" : "#607286";

    public bool IsProcessMonitoringEnabled
    {
        get => _engine.IsProcessMonitoringEnabled;
        set
        {
            if (_engine.IsProcessMonitoringEnabled != value)
            {
                _engine.IsProcessMonitoringEnabled = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(ProcessMonitoringStatusText));
                OnPropertyChanged(nameof(ProcessMonitoringStatusColor));
            }
        }
    }
    public string ProcessMonitoringStatusText => IsProcessMonitoringEnabled ? "ON" : "OFF";
    public string ProcessMonitoringStatusColor => IsProcessMonitoringEnabled ? "#C084FC" : "#607286";

    public bool IsUrlMonitoringEnabled
    {
        get => _engine.IsUrlMonitoringEnabled;
        set
        {
            if (_engine.IsUrlMonitoringEnabled != value)
            {
                _engine.IsUrlMonitoringEnabled = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(UrlMonitoringStatusText));
                OnPropertyChanged(nameof(UrlMonitoringStatusColor));
                OnPropertyChanged(nameof(UrlMonitoringButtonText));
            }
        }
    }
    public string UrlMonitoringButtonText => IsUrlMonitoringEnabled ? "🌐 الروابط: مفعّلة (ON)" : "🌐 الروابط: معطّلة (OFF)";
    public string UrlMonitoringStatusText => IsUrlMonitoringEnabled ? "ON" : "OFF";
    public string UrlMonitoringStatusColor => IsUrlMonitoringEnabled ? "#F43F5E" : "#607286";

    public bool IsTempAtMonitoringEnabled
    {
        get => _engine.IsTempAtMonitoringEnabled;
        set
        {
            if (_engine.IsTempAtMonitoringEnabled != value)
            {
                _engine.IsTempAtMonitoringEnabled = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(TempAtMonitoringStatusText));
                OnPropertyChanged(nameof(TempAtMonitoringStatusColor));
            }
        }
    }
    public string TempAtMonitoringStatusText => IsTempAtMonitoringEnabled ? "ON" : "OFF";
    public string TempAtMonitoringStatusColor => IsTempAtMonitoringEnabled ? "#FB923C" : "#607286";

    public bool IsAppleMonitoringEnabled
    {
        get => _engine.IsAppleMonitoringEnabled;
        set
        {
            if (_engine.IsAppleMonitoringEnabled != value)
            {
                _engine.IsAppleMonitoringEnabled = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(AppleMonitoringStatusText));
                OnPropertyChanged(nameof(AppleMonitoringStatusColor));
            }
        }
    }
    public string AppleMonitoringStatusText => IsAppleMonitoringEnabled ? "ON" : "OFF";
    public string AppleMonitoringStatusColor => IsAppleMonitoringEnabled ? "#38BDF8" : "#607286";

    public bool IsArtifactVaultEnabled
    {
        get => _engine.IsArtifactVaultEnabled;
        set
        {
            if (_engine.IsArtifactVaultEnabled != value)
            {
                _engine.IsArtifactVaultEnabled = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(ArtifactVaultStatusText));
                OnPropertyChanged(nameof(ArtifactVaultStatusColor));
            }
        }
    }
    public string ArtifactVaultStatusText => IsArtifactVaultEnabled ? "ON" : "OFF";
    public string ArtifactVaultStatusColor => IsArtifactVaultEnabled ? "#FBBF24" : "#607286";

    public bool IsMtpMonitoringEnabled
    {
        get => _engine.IsMtpMonitoringEnabled;
        set
        {
            if (_engine.IsMtpMonitoringEnabled != value)
            {
                _engine.IsMtpMonitoringEnabled = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(MtpMonitoringStatusText));
                OnPropertyChanged(nameof(MtpMonitoringStatusColor));
            }
        }
    }
    public string MtpMonitoringStatusText => IsMtpMonitoringEnabled ? "ON" : "OFF";
    public string MtpMonitoringStatusColor => IsMtpMonitoringEnabled ? "#2DD4BF" : "#607286";

    public bool IsCmdMonitoringEnabled
    {
        get => _engine.IsCmdMonitoringEnabled;
        set
        {
            if (_engine.IsCmdMonitoringEnabled != value)
            {
                _engine.IsCmdMonitoringEnabled = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(CmdMonitoringStatusText));
                OnPropertyChanged(nameof(CmdMonitoringStatusColor));
            }
        }
    }
    public string CmdMonitoringStatusText => IsCmdMonitoringEnabled ? "ON" : "OFF";
    public string CmdMonitoringStatusColor => IsCmdMonitoringEnabled ? "#FFFFFF" : "#607286";

    public bool IsShellMonitoringEnabled
    {
        get => _engine.IsShellMonitoringEnabled;
        set
        {
            if (_engine.IsShellMonitoringEnabled != value)
            {
                _engine.IsShellMonitoringEnabled = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(ShellMonitoringStatusText));
                OnPropertyChanged(nameof(ShellMonitoringStatusColor));
            }
        }
    }
    public string ShellMonitoringStatusText => IsShellMonitoringEnabled ? "ON" : "OFF";
    public string ShellMonitoringStatusColor => IsShellMonitoringEnabled ? "#A5D6A7" : "#607286";

    // ══════════════════════════════════════════════════════════════
    // Kernel Modem & Ports Filter (مراقبة الفلتر لمنافذ المودم والـ COM)
    // ══════════════════════════════════════════════════════════════
    private bool _isFilterMonitoringEnabled = false;
    public bool IsFilterMonitoringEnabled
    {
        get => _isFilterMonitoringEnabled;
        set
        {
            if (_isFilterMonitoringEnabled != value)
            {
                _isFilterMonitoringEnabled = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(FilterMonitoringStatusText));
                OnPropertyChanged(nameof(FilterMonitoringStatusColor));
                OnPropertyChanged(nameof(FilterMonitoringButtonText));
                OnPropertyChanged(nameof(FilterMonitoringCardText));
                OnPropertyChanged(nameof(FilterToggleButtonText));
            }
        }
    }
    public string FilterMonitoringStatusText => IsFilterMonitoringEnabled ? "مفعّل (ON)" : "معطّل (OFF)";
    public string FilterMonitoringStatusColor => IsFilterMonitoringEnabled ? "#00FF9D" : "#8E9AA8";
    public string FilterMonitoringButtonText => IsFilterMonitoringEnabled ? "🛡️ فلتر المودم: مفعّل (ON)" : "🛡️ فلتر المودم: معطّل (OFF)";
    public string FilterMonitoringCardText => IsFilterMonitoringEnabled ? "🟢 مفعّل (UpperFilter نشط)" : "⚪ الوضع الطبيعي (Stock Native)";
    public string FilterToggleButtonText => IsFilterMonitoringEnabled ? "🛑 إيقاف الفلتر" : "⚡ تشغيل الفلتر";

    // ══════════════════════════════════════════════════════════════
    // Log Display Exclusions (خيارات إخفاء السجلات من العرض والتصدير)
    // ══════════════════════════════════════════════════════════════
    private bool _hideUrls = false;
    public bool HideUrls
    {
        get => _hideUrls;
        set
        {
            if (_hideUrls != value)
            {
                _hideUrls = value;
                OnPropertyChanged();
                OnExclusionChanged();
            }
        }
    }

    private bool _hideAdb = false;
    public bool HideAdb
    {
        get => _hideAdb;
        set
        {
            if (_hideAdb != value)
            {
                _hideAdb = value;
                OnPropertyChanged();
                OnExclusionChanged();
            }
        }
    }

    private bool _hideUsb = false;
    public bool HideUsb
    {
        get => _hideUsb;
        set
        {
            if (_hideUsb != value)
            {
                _hideUsb = value;
                OnPropertyChanged();
                OnExclusionChanged();
            }
        }
    }

    private bool _hideSerial = false;
    public bool HideSerial
    {
        get => _hideSerial;
        set
        {
            if (_hideSerial != value)
            {
                _hideSerial = value;
                OnPropertyChanged();
                OnExclusionChanged();
            }
        }
    }

    private bool _hideProcesses = false;
    public bool HideProcesses
    {
        get => _hideProcesses;
        set
        {
            if (_hideProcesses != value)
            {
                _hideProcesses = value;
                OnPropertyChanged();
                OnExclusionChanged();
            }
        }
    }

    private bool _hideTempAt = false;
    public bool HideTempAt
    {
        get => _hideTempAt;
        set
        {
            if (_hideTempAt != value)
            {
                _hideTempAt = value;
                OnPropertyChanged();
                OnExclusionChanged();
            }
        }
    }

    private bool _hideApple = false;
    public bool HideApple
    {
        get => _hideApple;
        set
        {
            if (_hideApple != value)
            {
                _hideApple = value;
                OnPropertyChanged();
                OnExclusionChanged();
            }
        }
    }

    private bool _hideMtp = false;
    public bool HideMtp
    {
        get => _hideMtp;
        set
        {
            if (_hideMtp != value)
            {
                _hideMtp = value;
                OnPropertyChanged();
                OnExclusionChanged();
            }
        }
    }

    private bool _hideArtifacts = false;
    public bool HideArtifacts
    {
        get => _hideArtifacts;
        set
        {
            if (_hideArtifacts != value)
            {
                _hideArtifacts = value;
                OnPropertyChanged();
                OnExclusionChanged();
            }
        }
    }

    private bool _hideCmd = false;
    public bool HideCmd
    {
        get => _hideCmd;
        set
        {
            if (_hideCmd != value)
            {
                _hideCmd = value;
                OnPropertyChanged();
                OnExclusionChanged();
            }
        }
    }

    private bool _hideShell = false;
    public bool HideShell
    {
        get => _hideShell;
        set
        {
            if (_hideShell != value)
            {
                _hideShell = value;
                OnPropertyChanged();
                OnExclusionChanged();
            }
        }
    }

    public ObservableCollection<string> HiddenSourceTags { get; } = new();

    private bool _showHiddenLogsOnly = false;
    public bool ShowHiddenLogsOnly
    {
        get => _showHiddenLogsOnly;
        set
        {
            if (_showHiddenLogsOnly != value)
            {
                _showHiddenLogsOnly = value;
                OnPropertyChanged();
                OnExclusionChanged();
            }
        }
    }

    public bool HasActiveExclusions => HideUrls || HideAdb || HideUsb || HideSerial ||
                                       HideProcesses || HideTempAt || HideApple ||
                                       HideMtp || HideArtifacts || HideCmd || HideShell ||
                                       HiddenSourceTags.Count > 0 || ShowHiddenLogsOnly;

    private int _visibleEventsCount = 0;
    public int VisibleEventsCount
    {
        get => _visibleEventsCount;
        set { _visibleEventsCount = value; OnPropertyChanged(); }
    }

    private int _hiddenEventsCount = 0;
    public int HiddenEventsCount
    {
        get => _hiddenEventsCount;
        set { _hiddenEventsCount = value; OnPropertyChanged(); }
    }

    public string ExclusionBadgeText => HiddenEventsCount > 0
        ? $"🛡️ {HiddenEventsCount} مستثنى ومخفي"
        : "🛡️ لا توجد مستثنيات";

    public void OnExclusionChanged()
    {
        FilteredEvents.Refresh();
        UpdateExclusionCounts();
        OnPropertyChanged(nameof(HasActiveExclusions));
        OnPropertyChanged(nameof(ExclusionBadgeText));
    }

    public void UpdateExclusionCounts()
    {
        int total = Events.Count;
        int visible = 0;
        foreach (var ev in Events)
        {
            if (FilterEventPredicate(ev)) visible++;
        }
        VisibleEventsCount = visible;
        HiddenEventsCount = total - visible;
        OnPropertyChanged(nameof(ExclusionBadgeText));
    }

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

    // Live Metrics
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

    private int _totalEventsCount = 0;
    public int TotalEventsCount
    {
        get => _totalEventsCount;
        set { _totalEventsCount = value; OnPropertyChanged(); }
    }

    private int _phoneCommandsCount = 0;
    public int PhoneCommandsCount
    {
        get => _phoneCommandsCount;
        set { _phoneCommandsCount = value; OnPropertyChanged(); }
    }

    private int _usbCount = 0;
    public int UsbCount
    {
        get => _usbCount;
        set { _usbCount = value; OnPropertyChanged(); }
    }

    private int _adbCount = 0;
    public int AdbCount
    {
        get => _adbCount;
        set { _adbCount = value; OnPropertyChanged(); }
    }

    private int _serialCount = 0;
    public int SerialCount
    {
        get => _serialCount;
        set { _serialCount = value; OnPropertyChanged(); }
    }

    private int _processCount = 0;
    public int ProcessCount
    {
        get => _processCount;
        set { _processCount = value; OnPropertyChanged(); }
    }

    private int _networkCount = 0;
    public int NetworkCount
    {
        get => _networkCount;
        set { _networkCount = value; OnPropertyChanged(); }
    }

    private int _tempAtCount = 0;
    public int TempAtCount
    {
        get => _tempAtCount;
        set { _tempAtCount = value; OnPropertyChanged(); }
    }

    private int _mtpCount = 0;
    public int MtpCount
    {
        get => _mtpCount;
        set { _mtpCount = value; OnPropertyChanged(); }
    }

    private int _mtkCount = 0;
    public int MtkCount
    {
        get => _mtkCount;
        set { _mtkCount = value; OnPropertyChanged(); }
    }

    private int _spdCount = 0;
    public int SpdCount
    {
        get => _spdCount;
        set { _spdCount = value; OnPropertyChanged(); }
    }

    private int _edlCount = 0;
    public int EdlCount
    {
        get => _edlCount;
        set { _edlCount = value; OnPropertyChanged(); }
    }

    private int _inProcessCount = 0;
    public int InProcessCount
    {
        get => _inProcessCount;
        set { _inProcessCount = value; OnPropertyChanged(); }
    }

    private int _appleCount = 0;
    public int AppleCount
    {
        get => _appleCount;
        set { _appleCount = value; OnPropertyChanged(); }
    }

    private int _artifactVaultCount = 0;
    public int ArtifactVaultCount
    {
        get => _artifactVaultCount;
        set { _artifactVaultCount = value; OnPropertyChanged(); }
    }

    private int _cmdCount = 0;
    public int CmdCount
    {
        get => _cmdCount;
        set { _cmdCount = value; OnPropertyChanged(); }
    }

    private int _shellCount = 0;
    public int ShellCount
    {
        get => _shellCount;
        set { _shellCount = value; OnPropertyChanged(); }
    }

    // Commands
    public ICommand ToggleMonitoringCommand { get; }
    public ICommand ToggleFilterMonitoringCommand { get; }
    public ICommand ToggleUrlMonitoringCommand { get; }
    public ICommand ToggleUsbMonitoringCommand { get; }
    public ICommand ToggleAdbMonitoringCommand { get; }
    public ICommand ToggleSerialMonitoringCommand { get; }
    public ICommand ToggleProcessMonitoringCommand { get; }
    public ICommand ToggleTempAtMonitoringCommand { get; }
    public ICommand ToggleAppleMonitoringCommand { get; }
    public ICommand ToggleArtifactVaultCommand { get; }
    public ICommand ToggleMtpMonitoringCommand { get; }
    public ICommand ToggleCmdMonitoringCommand { get; }
    public ICommand ToggleShellMonitoringCommand { get; }
    public ICommand EnableAllSensorsCommand { get; }
    public ICommand DisableAllSensorsCommand { get; }
    public ICommand ResetExclusionsCommand { get; }
    public ICommand ClearLogsCommand { get; }
    public ICommand SimulateTrafficCommand { get; }
    public ICommand InstallDriverCommand { get; }
    public ICommand OpenFilterManagerCommand { get; }
    public ICommand ExportLogsCommand { get; }
    public ICommand ExportPurePhoneCommandsCommand { get; }
    public ICommand AnalyzeWithAiCommand { get; }
    public ICommand SelectCategoryCommand { get; }
    public ICommand QueryPhoneCommand { get; }
    public ICommand HideSelectedSourceTagCommand { get; }
    public ICommand ToggleShowHiddenLogsOnlyCommand { get; }
    public ICommand ToggleAutoScrollCommand { get; }
    public ICommand ResumeAutoScrollCommand { get; }
    public ICommand PauseAutoScrollCommand { get; }

    public event Action? RequestScrollToBottom;
    public event Action? RequestTechAuditScrollToBottom;

    public void ResetExclusions()
    {
        HideUrls = false;
        HideAdb = false;
        HideUsb = false;
        HideSerial = false;
        HideProcesses = false;
        HideTempAt = false;
        HideApple = false;
        HideMtp = false;
        HideArtifacts = false;
        HideCmd = false;
        HideShell = false;
        HiddenSourceTags.Clear();
        _showHiddenLogsOnly = false;
        OnPropertyChanged(nameof(ShowHiddenLogsOnly));
        OnExclusionChanged();
    }

    public void SetAllSensors(bool enabled)
    {
        IsUsbMonitoringEnabled = enabled;
        IsAdbMonitoringEnabled = enabled;
        IsSerialMonitoringEnabled = enabled;
        IsProcessMonitoringEnabled = enabled;
        IsUrlMonitoringEnabled = enabled;
        IsTempAtMonitoringEnabled = enabled;
        IsAppleMonitoringEnabled = enabled;
        IsArtifactVaultEnabled = enabled;
        IsMtpMonitoringEnabled = enabled;
        IsCmdMonitoringEnabled = enabled;
        IsShellMonitoringEnabled = enabled;
    }

    public MainViewModel()
    {
        _dispatcher = Application.Current?.Dispatcher ?? Dispatcher.CurrentDispatcher;

        FilteredEvents = CollectionViewSource.GetDefaultView(Events);
        FilteredEvents.Filter = FilterEventPredicate;

        ToggleMonitoringCommand = new RelayCommand(_ => ToggleMonitoring());
        ToggleFilterMonitoringCommand = new RelayCommand(_ => ToggleFilterMonitoring());
        ToggleUrlMonitoringCommand = new RelayCommand(_ => IsUrlMonitoringEnabled = !IsUrlMonitoringEnabled);
        ToggleUsbMonitoringCommand = new RelayCommand(_ => IsUsbMonitoringEnabled = !IsUsbMonitoringEnabled);
        ToggleAdbMonitoringCommand = new RelayCommand(_ => IsAdbMonitoringEnabled = !IsAdbMonitoringEnabled);
        ToggleSerialMonitoringCommand = new RelayCommand(_ => IsSerialMonitoringEnabled = !IsSerialMonitoringEnabled);
        ToggleProcessMonitoringCommand = new RelayCommand(_ => IsProcessMonitoringEnabled = !IsProcessMonitoringEnabled);
        ToggleTempAtMonitoringCommand = new RelayCommand(_ => IsTempAtMonitoringEnabled = !IsTempAtMonitoringEnabled);
        ToggleAppleMonitoringCommand = new RelayCommand(_ => IsAppleMonitoringEnabled = !IsAppleMonitoringEnabled);
        ToggleArtifactVaultCommand = new RelayCommand(_ => IsArtifactVaultEnabled = !IsArtifactVaultEnabled);
        ToggleMtpMonitoringCommand = new RelayCommand(_ => IsMtpMonitoringEnabled = !IsMtpMonitoringEnabled);
        ToggleCmdMonitoringCommand = new RelayCommand(_ => IsCmdMonitoringEnabled = !IsCmdMonitoringEnabled);
        ToggleShellMonitoringCommand = new RelayCommand(_ => IsShellMonitoringEnabled = !IsShellMonitoringEnabled);
        EnableAllSensorsCommand = new RelayCommand(_ => SetAllSensors(true));
        DisableAllSensorsCommand = new RelayCommand(_ => SetAllSensors(false));
        ResetExclusionsCommand = new RelayCommand(_ => ResetExclusions());
        ClearLogsCommand = new RelayCommand(_ => ClearLogs());
        SimulateTrafficCommand = new RelayCommand(async _ => await SimulateTrafficAsync());
        InstallDriverCommand = new RelayCommand(_ => OpenFilterManager());
        OpenFilterManagerCommand = new RelayCommand(_ => OpenFilterManager());
        ExportLogsCommand = new RelayCommand(_ => ExportLogs());
        ExportPurePhoneCommandsCommand = new RelayCommand(_ => ExportPurePhoneCommandsOnly());
        AnalyzeWithAiCommand = new RelayCommand(async _ => await AnalyzeWithAiAsync());
        QueryPhoneCommand = new RelayCommand(async _ => await QueryPhoneLiveAsync());
        
        HideSelectedSourceTagCommand = new RelayCommand(_ => 
        {
            if (SelectedEvent != null && !string.IsNullOrEmpty(SelectedEvent.SourceTag))
            {
                if (!HiddenSourceTags.Contains(SelectedEvent.SourceTag))
                {
                    HiddenSourceTags.Add(SelectedEvent.SourceTag);
                    OnExclusionChanged();
                }
            }
        });

        ToggleShowHiddenLogsOnlyCommand = new RelayCommand(_ => 
        {
            ShowHiddenLogsOnly = !ShowHiddenLogsOnly;
        });

        SelectCategoryCommand = new RelayCommand(p =>
        {
            if (p is string s && Enum.TryParse<EventSourceCategory>(s, out var cat))
            {
                SelectedCategory = cat;
            }
        });

        ToggleAutoScrollCommand = new RelayCommand(_ => AutoScroll = !AutoScroll);
        ResumeAutoScrollCommand = new RelayCommand(_ => AutoScroll = true);
        PauseAutoScrollCommand = new RelayCommand(_ => AutoScroll = false);

        // Connect engine callbacks
        _engine.OnEventReceived += HandleEventReceived;
        _engine.OnTopologyChanged += HandleTopologyChanged;
        _engine.OnComPortsChanged += HandleComPortsChanged;
        _engine.OnToolsChanged += HandleToolsChanged;
        _engine.OnDriverStatusChanged += HandleDriverStatusChanged;

        InitializeSystemStatus();
        InitializeTechnicianAuditLayer();
        InitializeToolSourceInterceptionLayer();
        _engine.Start();
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? propName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propName));
    }
}
