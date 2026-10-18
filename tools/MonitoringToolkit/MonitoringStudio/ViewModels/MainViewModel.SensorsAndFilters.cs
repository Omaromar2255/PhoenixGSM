using System.Collections.ObjectModel;

namespace PhoenixGSM.MonitoringStudio.ViewModels;

public partial class MainViewModel
{
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
}
