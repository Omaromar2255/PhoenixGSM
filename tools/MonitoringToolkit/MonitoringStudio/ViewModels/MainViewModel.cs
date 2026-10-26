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

    public event Action? RequestScrollToBottom;
    public event Action? RequestTechAuditScrollToBottom;

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
        InitializeL24SourceSentinelLayer();
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? propName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propName));
    }
}
