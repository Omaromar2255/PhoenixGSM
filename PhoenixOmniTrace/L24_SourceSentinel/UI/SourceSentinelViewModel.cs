using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Windows;
using System.Windows.Data;
using PhoenixOmniTrace.L24_SourceSentinel.Core;
using PhoenixOmniTrace.L24_SourceSentinel.Models;

namespace PhoenixOmniTrace.L24_SourceSentinel.UI;

public sealed partial class SourceSentinelViewModel : INotifyPropertyChanged, IDisposable
{
    private readonly SourceSentinelOrchestrator _orchestrator;
    public SourceSentinelOrchestrator Orchestrator => _orchestrator;
    private readonly object _lockObj = new();

    // 1. الأوامر الفعلية المنفذة للجهاز (معزول 100% عن الرام)
    public ObservableCollection<SourceTelemetryEvent> ExecutedDeviceEvents { get; } = [];
    public ICollectionView FilteredExecutedEvents { get; }

    // 2. أوامر الهاتف الصافية للتجربة المباشرة
    public ObservableCollection<SourceTelemetryEvent> PurePhoneTestableEvents { get; } = [];
    public ICollectionView FilteredPurePhoneEvents { get; }

    // 3. الأوامر المكتشفة في الذاكرة
    public ObservableCollection<SourceTelemetryEvent> DiscoveredRamEvents { get; } = [];
    public ICollectionView FilteredDiscoveredRamEvents { get; }

    // 4. رادار المنافذ والملفات المحفوظة والمكتبات
    public ObservableCollection<SourceTelemetryEvent> RadarAndFileEvents { get; } = [];
    public ICollectionView FilteredRadarEvents { get; }

    // 5. التبويب الخامس: السجل الشامل الخام بدون فلترة
    public ObservableCollection<SourceTelemetryEvent> UnfilteredRawEvents { get; } = [];
    public ICollectionView FilteredUnfilteredRawEvents { get; }

    // القائمة المنظمة الشاملة
    public ObservableCollection<SourceTelemetryEvent> LiveEvents { get; } = [];
    public ICollectionView FilteredEvents { get; }

    public ObservableCollection<LoadedModuleArtifact> LoadedArtifacts { get; } = [];
    public ICollectionView FilteredArtifacts { get; }

    private SourceTelemetryEvent? _selectedEvent;
    public SourceTelemetryEvent? SelectedEvent
    {
        get => _selectedEvent;
        set
        {
            if (_selectedEvent != value)
            {
                _selectedEvent = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(SelectedEventHexDump));
                OnPropertyChanged(nameof(SelectedEventAsciiText));
                OnPropertyChanged(nameof(SelectedEventDetails));
            }
        }
    }

    private LoadedModuleArtifact? _selectedArtifact;
    public LoadedModuleArtifact? SelectedArtifact
    {
        get => _selectedArtifact;
        set
        {
            if (_selectedArtifact != value)
            {
                _selectedArtifact = value;
                OnPropertyChanged();
                if (value != null)
                {
                    ActiveOriginFilter = value.ModuleName;
                }
            }
        }
    }

    private string? _activeOriginFilter;
    public string? ActiveOriginFilter
    {
        get => _activeOriginFilter;
        set
        {
            if (_activeOriginFilter != value)
            {
                _activeOriginFilter = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(IsOriginFilterActive));
                RefreshAllViews();
            }
        }
    }
    public bool IsOriginFilterActive => !string.IsNullOrWhiteSpace(_activeOriginFilter);

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
                RefreshAllViews();
            }
        }
    }

    // العدادات الحية للأقسام الخمسة
    public int TotalEventsCount => LiveEvents.Count;
    public int ExecutedCommandsCount => ExecutedDeviceEvents.Count;
    public int PurePhoneCommandsCount => PurePhoneTestableEvents.Count;
    public int DiscoveredRamCommandsCount => DiscoveredRamEvents.Count;
    public int RadarEventsCount => RadarAndFileEvents.Count;
    public int UnfilteredRawEventsCount => UnfilteredRawEvents.Count;

    private string _statusMessage = "مستعد لمراقبة الأداة من المصدر (Ready)";
    public string StatusMessage { get => _statusMessage; set { _statusMessage = value; OnPropertyChanged(); } }

    public int SelectedDiscoveryModeIndex
    {
        get => (int)_orchestrator.DiscoveryMode;
        set
        {
            if (Enum.IsDefined(typeof(L24DiscoveryMode), value) && (int)_orchestrator.DiscoveryMode != value)
            {
                _orchestrator.DiscoveryMode = (L24DiscoveryMode)value;
                OnPropertyChanged();
            }
        }
    }

    public bool ShowPhoneResponses
    {
        get => _orchestrator.ShowPhoneResponses;
        set
        {
            if (_orchestrator.ShowPhoneResponses != value)
            {
                _orchestrator.ShowPhoneResponses = value;
                OnPropertyChanged();
                RefreshAllViews();
            }
        }
    }

    public bool IsRamHunterEnabled
    {
        get => _orchestrator.IsRamHunterEnabled;
        set
        {
            if (_orchestrator.IsRamHunterEnabled != value)
            {
                _orchestrator.IsRamHunterEnabled = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(RamHunterToggleButtonText));
                OnPropertyChanged(nameof(RamHunterToggleBtnBackground));
                OnPropertyChanged(nameof(RamHunterToggleBtnBorder));
            }
        }
    }

    public string RamHunterToggleButtonText => IsRamHunterEnabled ? "🧠 فاحص الرام: نشط (إيقاف مؤقت)" : "⏸️ فاحص الرام: متوقف (تشغيل)";
    public string RamHunterToggleBtnBackground => IsRamHunterEnabled ? "#064E3B" : "#450A0A";
    public string RamHunterToggleBtnBorder => IsRamHunterEnabled ? "#10B981" : "#EF4444";

    public bool SuppressIdleStaticBaseline
    {
        get => _orchestrator.SuppressIdleStaticBaseline;
        set
        {
            if (_orchestrator.SuppressIdleStaticBaseline != value)
            {
                _orchestrator.SuppressIdleStaticBaseline = value;
                OnPropertyChanged();
            }
        }
    }

    public bool ScanDynamicHeapOnly
    {
        get => _orchestrator.ScanDynamicHeapOnly;
        set
        {
            if (_orchestrator.ScanDynamicHeapOnly != value)
            {
                _orchestrator.ScanDynamicHeapOnly = value;
                OnPropertyChanged();
            }
        }
    }

    private bool _isCategoryConfigPanelVisible;
    public bool IsCategoryConfigPanelVisible
    {
        get => _isCategoryConfigPanelVisible;
        set
        {
            if (_isCategoryConfigPanelVisible != value)
            {
                _isCategoryConfigPanelVisible = value;
                OnPropertyChanged();
            }
        }
    }

    public bool IsL24Active => _orchestrator.IsActive;

    public string L24MasterStatusText => IsL24Active ? "🟢 الطبقة 24 تعمل وتراقب الآن" : "⏹️ الطبقة 24 معطلة (توفير الموارد)";
    public string L24MasterStatusColor => IsL24Active ? "#34D399" : "#F87171";
    public string L24MasterBadgeText => IsL24Active ? "⚡ L24 ACTIVE" : "💤 L24 STANDBY";
    public string L24MasterBackground => IsL24Active ? "#064E3B" : "#450A0A";
    public string L24MasterBorder => IsL24Active ? "#10B981" : "#EF4444";
    public string L24MasterButtonText => IsL24Active ? "⏹️ إيقاف الطبقة 24 بالكامل" : "▶️ تشغيل وتفعيل الطبقة 24";
    public string L24MasterButtonBackground => IsL24Active ? "#7F1D1D" : "#065F46";
    public string L24MasterButtonBorder => IsL24Active ? "#EF4444" : "#10B981";
    public string L24MasterTooltip => IsL24Active 
        ? "الطبقة 24 تعمل وتراقب الذاكرة والملفات والمنافذ. اضغط لإيقافها تماماً وإيقاف كافة مهام الخلفية وتوفير موارد الجهاز 100%." 
        : "الطبقة 24 معطلة بالكامل ولا تستهلك أي موارد بالخلفية. اضغط لتشغيلها وتفعيل المراقبة الشاملة.";

    public void NotifyL24StateChanged()
    {
        OnPropertyChanged(nameof(IsL24Active));
        OnPropertyChanged(nameof(L24MasterStatusText));
        OnPropertyChanged(nameof(L24MasterStatusColor));
        OnPropertyChanged(nameof(L24MasterBadgeText));
        OnPropertyChanged(nameof(L24MasterBackground));
        OnPropertyChanged(nameof(L24MasterBorder));
        OnPropertyChanged(nameof(L24MasterButtonText));
        OnPropertyChanged(nameof(L24MasterButtonBackground));
        OnPropertyChanged(nameof(L24MasterButtonBorder));
        OnPropertyChanged(nameof(L24MasterTooltip));
    }

    public bool IsUnfilteredRawLoggingEnabled
    {
        get => _orchestrator.IsUnfilteredRawLoggingEnabled;
        set
        {
            if (_orchestrator.IsUnfilteredRawLoggingEnabled != value)
            {
                _orchestrator.IsUnfilteredRawLoggingEnabled = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(UnfilteredRawStatusText));
                OnPropertyChanged(nameof(UnfilteredRawStatusColor));
                OnPropertyChanged(nameof(UnfilteredRawStatusBorder));
                OnPropertyChanged(nameof(UnfilteredRawStatusBackground));
                OnPropertyChanged(nameof(UnfilteredRawToggleActionText));
                OnPropertyChanged(nameof(UnfilteredRawToggleBtnBackground));
                OnPropertyChanged(nameof(UnfilteredRawToggleBtnBorder));
            }
        }
    }

    public string UnfilteredRawStatusText => IsUnfilteredRawLoggingEnabled ? "🟢 يعمل ويسجل آنياً" : "⏸️ متوقف مؤقتاً";
    public string UnfilteredRawStatusColor => IsUnfilteredRawLoggingEnabled ? "#4ADE80" : "#F87171";
    public string UnfilteredRawStatusBorder => IsUnfilteredRawLoggingEnabled ? "#16A34A" : "#DC2626";
    public string UnfilteredRawStatusBackground => IsUnfilteredRawLoggingEnabled ? "#052E16" : "#450A0A";
    public string UnfilteredRawToggleActionText => IsUnfilteredRawLoggingEnabled ? "⏸️ إيقاف السجل الخام مؤقتاً" : "▶️ تشغيل واستئناف السجل الخام";
    public string UnfilteredRawToggleBtnBackground => IsUnfilteredRawLoggingEnabled ? "#7F1D1D" : "#14532D";
    public string UnfilteredRawToggleBtnBorder => IsUnfilteredRawLoggingEnabled ? "#EF4444" : "#22C55E";

    public SourceSentinelViewModel()
    {
        _orchestrator = new SourceSentinelOrchestrator();

        FilteredExecutedEvents = CollectionViewSource.GetDefaultView(ExecutedDeviceEvents);
        FilteredExecutedEvents.Filter = FilterExecutedDeviceItem;

        FilteredPurePhoneEvents = CollectionViewSource.GetDefaultView(PurePhoneTestableEvents);
        FilteredPurePhoneEvents.Filter = FilterCommonItem;

        FilteredDiscoveredRamEvents = CollectionViewSource.GetDefaultView(DiscoveredRamEvents);
        FilteredDiscoveredRamEvents.Filter = FilterDiscoveredRamItem;

        FilteredRadarEvents = CollectionViewSource.GetDefaultView(RadarAndFileEvents);
        FilteredRadarEvents.Filter = FilterCommonItem;

        FilteredUnfilteredRawEvents = CollectionViewSource.GetDefaultView(UnfilteredRawEvents);
        FilteredUnfilteredRawEvents.Filter = FilterUnfilteredRawItem;

        FilteredEvents = CollectionViewSource.GetDefaultView(LiveEvents);
        FilteredArtifacts = CollectionViewSource.GetDefaultView(LoadedArtifacts);

        BindingOperations.EnableCollectionSynchronization(ExecutedDeviceEvents, _lockObj);
        BindingOperations.EnableCollectionSynchronization(PurePhoneTestableEvents, _lockObj);
        BindingOperations.EnableCollectionSynchronization(DiscoveredRamEvents, _lockObj);
        BindingOperations.EnableCollectionSynchronization(RadarAndFileEvents, _lockObj);
        BindingOperations.EnableCollectionSynchronization(UnfilteredRawEvents, _lockObj);
        BindingOperations.EnableCollectionSynchronization(LiveEvents, _lockObj);
        BindingOperations.EnableCollectionSynchronization(LoadedArtifacts, _lockObj);

        _orchestrator.OnTelemetryEventCaptured += OnEventCaptured;
        _orchestrator.OnUnfilteredRawEventCaptured += OnUnfilteredRawCaptured;
        _orchestrator.OnLogMessage += msg => StatusMessage = msg;

        ToggleL24MasterCommand = new RelayCommand(_ =>
        {
            if (_orchestrator.IsActive)
                _orchestrator.Stop();
            else
                _orchestrator.Start();
            NotifyL24StateChanged();
        });

        StartL24Command = new RelayCommand(_ =>
        {
            _orchestrator.Start();
            NotifyL24StateChanged();
        });

        StopL24Command = new RelayCommand(_ =>
        {
            _orchestrator.Stop();
            NotifyL24StateChanged();
        });

        ToggleRamHunterCommand = new RelayCommand(_ =>
        {
            IsRamHunterEnabled = !IsRamHunterEnabled;
        });

        CaptureIdleBaselineCommand = new RelayCommand(_ =>
        {
            _orchestrator.CaptureIdleBaselineSnapshot();
        });

        ResetIdleBaselineCommand = new RelayCommand(_ =>
        {
            _orchestrator.ResetIdleBaselineSnapshot();
        });

        LaunchToolCommand = new RelayCommand(_ => ExecuteLaunchTool());
        AttachProcessCommand = new RelayCommand(_ => ExecuteAttachProcess());
        ToggleUnfilteredRawLoggingCommand = new RelayCommand(_ =>
        {
            IsUnfilteredRawLoggingEnabled = !IsUnfilteredRawLoggingEnabled;
        });

        ClearUnfilteredRawCommand = new RelayCommand(_ =>
        {
            lock (_lockObj)
            {
                UnfilteredRawEvents.Clear();
                _orchestrator.ClearUnfilteredRawEvents();
                OnPropertyChanged(nameof(UnfilteredRawEventsCount));
            }
        });

        ToggleCategoryConfigPanelCommand = new RelayCommand(_ => IsCategoryConfigPanelVisible = !IsCategoryConfigPanelVisible);

        EnableAllCategoriesCommand = new RelayCommand(_ =>
        {
            foreach (L24CommandGroup grp in Enum.GetValues<L24CommandGroup>())
                _orchestrator.SetCategoryDetectionEnabled(grp, true);
            ExcludeUrlsFromDiscovered = false;
            NotifyAllCategoryProperties();
            FilteredDiscoveredRamEvents.Refresh();
        });

        DisableAllCategoriesCommand = new RelayCommand(_ =>
        {
            foreach (L24CommandGroup grp in Enum.GetValues<L24CommandGroup>())
                _orchestrator.SetCategoryDetectionEnabled(grp, false);
            NotifyAllCategoryProperties();
            FilteredDiscoveredRamEvents.Refresh();
        });

        ExcludeUrlsCommand = new RelayCommand(_ =>
        {
            ExcludeUrlsFromDiscovered = true;
            IsServerCloudCategoryEnabled = false;
            NotifyAllCategoryProperties();
            FilteredDiscoveredRamEvents.Refresh();
        });

        ToggleCategoryCommand = new RelayCommand(param =>
        {
            if (param is string catStr && Enum.TryParse<L24CommandGroup>(catStr, out var grp))
            {
                bool curr = _orchestrator.IsCategoryDetectionEnabled(grp);
                _orchestrator.SetCategoryDetectionEnabled(grp, !curr);
                NotifyAllCategoryProperties();
                FilteredDiscoveredRamEvents.Refresh();
            }
        });

        ClearEventsCommand = new RelayCommand(_ => ExecuteClearEvents());
        ExportLogsCommand = new RelayCommand(_ => ExecuteExportLogs());
        ExportPurePhoneCommandsCommand = new RelayCommand(_ => ExecuteExportPurePhoneCommands());
        ExportSelectedDiscoveredCategoryCommand = new RelayCommand(_ => ExecuteExportSelectedDiscoveredCategory());
        ExportAllDiscoveredCategoriesSeparatelyCommand = new RelayCommand(_ => ExecuteExportAllDiscoveredCategoriesSeparately());
        ExportUnfilteredRawLogsCommand = new RelayCommand(_ => ExecuteExportUnfilteredRawLogs());
        OpenLogsFolderCommand = new RelayCommand(_ => ExecuteOpenLogsFolder());
        OpenCapturedFilesFolderCommand = new RelayCommand(_ => ExecuteOpenCapturedFilesFolder());
        ClearOriginFilterCommand = new RelayCommand(_ => { ActiveOriginFilter = null; SelectedArtifact = null; });
        SetDiscoveredCategoryFilterCommand = new RelayCommand(param => { if (param is string cat) DiscoveredCategoryFilter = cat; });

        _orchestrator.Start();
    }

    public void AttachToOmniTraceBus(PhoenixGSM.OmniTrace.Bus.OmniTraceEventBus bus)
    {
        _orchestrator.AttachToOmniTraceEventBus(bus);
    }

    private void OnUnfilteredRawCaptured(SourceTelemetryEvent rawEvt)
    {
        if (!IsL24Active || !IsUnfilteredRawLoggingEnabled) return;
        Application.Current?.Dispatcher.InvokeAsync(() =>
        {
            lock (_lockObj)
            {
                if (UnfilteredRawEvents.Count >= 50000)
                    UnfilteredRawEvents.RemoveAt(0);
                UnfilteredRawEvents.Add(rawEvt);
                OnPropertyChanged(nameof(UnfilteredRawEventsCount));
            }
        });
    }

    private void OnEventCaptured(SourceTelemetryEvent evt)
    {
        if (!IsL24Active || evt == null) return;
        Application.Current?.Dispatcher.InvokeAsync(() =>
        {
            lock (_lockObj)
            {
                if (LiveEvents.Count >= 30000) LiveEvents.RemoveAt(0);
                LiveEvents.Add(evt);

                if (!string.IsNullOrWhiteSpace(evt.SavedFilePath) || evt.Stage is SentinelStage.RamUnpackOrModuleLoad or SentinelStage.LocalFilePreparation)
                {
                    AddArtifactIfNotExists(evt);
                }

                switch (evt.Scope)
                {
                    case L24CommandScope.ExecutedOnDevice:
                        if (!L24CommandClassifier.IsUrlOrNetworkOrAuth(evt) && evt.CommandGroup != L24CommandGroup.ServerCloudLogin)
                        {
                            ExecutedDeviceEvents.Add(evt);
                        }
                        else
                        {
                            if (_orchestrator.IsCategoryDetectionEnabled(L24CommandGroup.ServerCloudLogin) && !ExcludeUrlsFromDiscovered)
                            {
                                DiscoveredRamEvents.Add(evt);
                                UpdateDiscoveredCategoryCounters();
                            }
                        }
                        break;

                    case L24CommandScope.DiscoveredInRam:
                        if (_orchestrator.IsCategoryDetectionEnabled(evt.CommandGroup))
                        {
                            if (!ExcludeUrlsFromDiscovered || (evt.CommandGroup != L24CommandGroup.ServerCloudLogin && !L24CommandClassifier.IsUrlOrNetworkOrAuth(evt)))
                            {
                                DiscoveredRamEvents.Add(evt);
                                UpdateDiscoveredCategoryCounters();
                            }
                        }
                        break;

                    case L24CommandScope.RadarAndFiles:
                        RadarAndFileEvents.Add(evt);
                        break;
                }

                if (L24CommandClassifier.IsPurePhoneTestable(evt, out string cleanTestable))
                {
                    string normKey = RamCommandConsolidator.NormalizeCommandKey(cleanTestable);
                    bool alreadyInPure = PurePhoneTestableEvents.Any(x =>
                        string.Equals(RamCommandConsolidator.NormalizeCommandKey(x.PureCommandText), normKey, StringComparison.OrdinalIgnoreCase));

                    if (!alreadyInPure)
                    {
                        evt.PureCommandText = cleanTestable;
                        PurePhoneTestableEvents.Add(evt);
                    }
                }

                NotifyCounterProperties();
            }
        });
    }

    private void NotifyCounterProperties()
    {
        OnPropertyChanged(nameof(TotalEventsCount));
        OnPropertyChanged(nameof(ExecutedCommandsCount));
        OnPropertyChanged(nameof(PurePhoneCommandsCount));
        OnPropertyChanged(nameof(DiscoveredRamCommandsCount));
        OnPropertyChanged(nameof(RadarEventsCount));
        OnPropertyChanged(nameof(UnfilteredRawEventsCount));
    }

    private void AddArtifactIfNotExists(SourceTelemetryEvent evt)
    {
        string path = !string.IsNullOrWhiteSpace(evt.SavedFilePath) ? evt.SavedFilePath : evt.TargetResource;
        string moduleName = Path.GetFileName(path);
        if (string.IsNullOrWhiteSpace(moduleName)) moduleName = evt.CallerModuleOrigin;

        bool exists = LoadedArtifacts.Any(a => a.ModuleName.Equals(moduleName, StringComparison.OrdinalIgnoreCase)
                                            || a.FilePath.Equals(path, StringComparison.OrdinalIgnoreCase));
        if (!exists)
        {
            LoadedArtifacts.Add(new LoadedModuleArtifact(
                ModuleName: moduleName,
                FilePath: path,
                BaseAddress: IntPtr.Zero,
                MemorySize: evt.PayloadSize,
                IsUnpackedInRam: evt.HookedApiName.Contains("VirtualProtect", StringComparison.OrdinalIgnoreCase) || evt.CommandCategory.Contains("Carved", StringComparison.OrdinalIgnoreCase),
                DetectionTimestamp: evt.Timestamp,
                ProcessId: evt.ProcessId
            ));
        }
    }

    public string SelectedEventHexDump
    {
        get
        {
            if (SelectedEvent == null || string.IsNullOrWhiteSpace(SelectedEvent.RawPayloadHex))
                return "[لا توجد بايتات خام مسجلة لهذا الحدث]";

            try
            {
                byte[] bytes = Convert.FromHexString(SelectedEvent.RawPayloadHex);
                var sb = new StringBuilder();
                for (int i = 0; i < bytes.Length; i += 16)
                {
                    sb.AppendFormat("{0:X4}: ", i);
                    int chunk = Math.Min(16, bytes.Length - i);
                    for (int j = 0; j < 16; j++)
                    {
                        sb.Append(j < chunk ? $"{bytes[i + j]:X2} " : "   ");
                        if (j == 7) sb.Append(' ');
                    }
                    sb.Append(" | ");
                    for (int j = 0; j < chunk; j++)
                    {
                        byte b = bytes[i + j];
                        sb.Append(b is >= 32 and <= 126 ? (char)b : '.');
                    }
                    sb.AppendLine();
                }
                return sb.ToString();
            }
            catch
            {
                return SelectedEvent.RawPayloadHex;
            }
        }
    }

    public string SelectedEventAsciiText => SelectedEvent?.PureCommandText ?? "";

    public string SelectedEventDetails => SelectedEvent == null
        ? "اختر حدثاً من الجدول لعرض التفاصيل الجنائية الدقيقة."
        : $"النطاق: {SelectedEvent.ScopeBadge} | المجموعة: {SelectedEvent.CommandGroupBadge}\n" +
          $"الأمر الصافي: {SelectedEvent.PureCommandText}\n" +
          $"المصدر (Origin): {SelectedEvent.CallerModuleOrigin} | الهدف: {SelectedEvent.TargetResource}\n" +
          (!string.IsNullOrWhiteSpace(SelectedEvent.SavedFilePath) ? $"💾 مسار الملف المحفوظ: {SelectedEvent.SavedFilePath}\n" : "") +
          $"الدالة: {SelectedEvent.HookedApiName} | الحجم: {SelectedEvent.PayloadSize} بايت";

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? propName = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propName));

    public void Dispose() => _orchestrator.Dispose();
}
