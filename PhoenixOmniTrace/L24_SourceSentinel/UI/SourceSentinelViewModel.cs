using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Windows;
using System.Windows.Data;
using System.Windows.Input;
using Microsoft.Win32;
using PhoenixOmniTrace.L24_SourceSentinel.Core;
using PhoenixOmniTrace.L24_SourceSentinel.Models;

namespace PhoenixOmniTrace.L24_SourceSentinel.UI;

public sealed class SourceSentinelViewModel : INotifyPropertyChanged, IDisposable
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

    // 3. الأوامر المكتشفة في الذاكرة (مع فلترة الـ 10 فئات شاملة الروابط وتسجيل الدخول وأبل وMTK وكوالكوم)
    public ObservableCollection<SourceTelemetryEvent> DiscoveredRamEvents { get; } = [];
    public ICollectionView FilteredDiscoveredRamEvents { get; }

    // 4. رادار المنافذ والملفات المحفوظة والمكتبات
    public ObservableCollection<SourceTelemetryEvent> RadarAndFileEvents { get; } = [];
    public ICollectionView FilteredRadarEvents { get; }

    // 5. التبويب الخامس الجديد: السجل الشامل الخام بدون فلترة (Unfiltered Raw Stream — يحفظ كل شيء لملف منفصل!)
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

    // التحكم الاختياري في آلية اكتشاف الأوامر من الـ RAM وإظهار ردود الهاتف
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

    // فلترة تبويب الأوامر المكتشفة في الذاكرة (11 خياراً شاملاً)
    private string _discoveredCategoryFilter = "All";
    public string DiscoveredCategoryFilter
    {
        get => _discoveredCategoryFilter;
        set
        {
            if (_discoveredCategoryFilter != value)
            {
                _discoveredCategoryFilter = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(IsDiscAllSelected));
                OnPropertyChanged(nameof(IsDiscModemSelected));
                OnPropertyChanged(nameof(IsDiscMtkSelected));
                OnPropertyChanged(nameof(IsDiscQualcommSelected));
                OnPropertyChanged(nameof(IsDiscAppleSelected));
                OnPropertyChanged(nameof(IsDiscAdbSelected));
                OnPropertyChanged(nameof(IsDiscServerCloudSelected));
                OnPropertyChanged(nameof(IsDiscTransferSelected));
                OnPropertyChanged(nameof(IsDiscArchiveSelected));
                OnPropertyChanged(nameof(IsDiscCryptoSelected));
                OnPropertyChanged(nameof(IsDiscOtherSelected));
                FilteredDiscoveredRamEvents.Refresh();
            }
        }
    }

    public bool IsDiscAllSelected => DiscoveredCategoryFilter == "All";
    public bool IsDiscModemSelected => DiscoveredCategoryFilter == "ModemAt";
    public bool IsDiscMtkSelected => DiscoveredCategoryFilter == "MediaTek";
    public bool IsDiscQualcommSelected => DiscoveredCategoryFilter == "Qualcomm";
    public bool IsDiscAppleSelected => DiscoveredCategoryFilter == "AppleIos";
    public bool IsDiscAdbSelected => DiscoveredCategoryFilter == "AdbFastboot";
    public bool IsDiscServerCloudSelected => DiscoveredCategoryFilter == "ServerCloudLogin";
    public bool IsDiscTransferSelected => DiscoveredCategoryFilter == "FileTransfer";
    public bool IsDiscArchiveSelected => DiscoveredCategoryFilter == "ArchiveUnpack";
    public bool IsDiscCryptoSelected => DiscoveredCategoryFilter == "CryptoAuth";
    public bool IsDiscOtherSelected => DiscoveredCategoryFilter == "OtherCommands";

    public int DiscModemCount => DiscoveredRamEvents.Count(e => e.CommandGroup == L24CommandGroup.ModemAt);
    public int DiscMtkCount => DiscoveredRamEvents.Count(e => e.CommandGroup == L24CommandGroup.MediaTek);
    public int DiscQualcommCount => DiscoveredRamEvents.Count(e => e.CommandGroup == L24CommandGroup.Qualcomm);
    public int DiscAppleCount => DiscoveredRamEvents.Count(e => e.CommandGroup == L24CommandGroup.AppleIos);
    public int DiscAdbCount => DiscoveredRamEvents.Count(e => e.CommandGroup == L24CommandGroup.AdbFastboot);
    public int DiscServerCloudCount => DiscoveredRamEvents.Count(e => e.CommandGroup == L24CommandGroup.ServerCloudLogin);
    public int DiscTransferCount => DiscoveredRamEvents.Count(e => e.CommandGroup == L24CommandGroup.FileTransfer);
    public int DiscArchiveCount => DiscoveredRamEvents.Count(e => e.CommandGroup == L24CommandGroup.ArchiveUnpack);
    public int DiscCryptoCount => DiscoveredRamEvents.Count(e => e.CommandGroup == L24CommandGroup.CryptoAuth);
    public int DiscOtherCount => DiscoveredRamEvents.Count(e => e.CommandGroup == L24CommandGroup.OtherCommands);

    // نصوص الأزرار الكاملة موضح بها اسم النوع والعدد وحالة التفعيل لتجنب ظهور أرقام مجردة
    public string DiscAllButtonText => $"🌐 الكل ({DiscoveredRamCommandsCount})";
    public string DiscModemButtonText => $"📻 المودم ({DiscModemCount}){(IsModemCategoryEnabled ? "" : " [معطل]")}";
    public string DiscMtkButtonText => $"🔶 ميدياتك ({DiscMtkCount}){(IsMtkCategoryEnabled ? "" : " [معطل]")}";
    public string DiscQualcommButtonText => $"🔷 كوالكوم و EDL ({DiscQualcommCount}){(IsQualcommCategoryEnabled ? "" : " [معطل]")}";
    public string DiscAppleButtonText => $"🍎 أبل Apple ({DiscAppleCount}){(IsAppleCategoryEnabled ? "" : " [معطل]")}";
    public string DiscAdbButtonText => $"🤖 ADB/Fastboot ({DiscAdbCount}){(IsAdbCategoryEnabled ? "" : " [معطل]")}";
    public string DiscServerCloudButtonText => $"🌐 الروابط والخوادم ({DiscServerCloudCount}){(IsServerCloudCategoryEnabled && !ExcludeUrlsFromDiscovered ? "" : " [معطل]")}";
    public string DiscTransferButtonText => $"📤 نقل وملفات بوت ({DiscTransferCount}){(IsTransferCategoryEnabled ? "" : " [معطل]")}";
    public string DiscArchiveButtonText => $"📦 فك ضغط ({DiscArchiveCount}){(IsArchiveCategoryEnabled ? "" : " [معطل]")}";
    public string DiscCryptoButtonText => $"🔐 تشفير ومفاتيح ({DiscCryptoCount}){(IsCryptoCategoryEnabled ? "" : " [معطل]")}";
    public string DiscOtherButtonText => $"🧩 أوامر أخرى ({DiscOtherCount}){(IsOtherCategoryEnabled ? "" : " [معطل]")}";

    // التحكم في تفعيل وإيقاف رصد كل فئة من فئات الأوامر بالذاكرة
    public bool IsModemCategoryEnabled
    {
        get => _orchestrator.IsCategoryDetectionEnabled(L24CommandGroup.ModemAt);
        set => SetCategoryState(L24CommandGroup.ModemAt, value, nameof(IsModemCategoryEnabled), nameof(DiscModemButtonText));
    }

    public bool IsMtkCategoryEnabled
    {
        get => _orchestrator.IsCategoryDetectionEnabled(L24CommandGroup.MediaTek);
        set => SetCategoryState(L24CommandGroup.MediaTek, value, nameof(IsMtkCategoryEnabled), nameof(DiscMtkButtonText));
    }

    public bool IsQualcommCategoryEnabled
    {
        get => _orchestrator.IsCategoryDetectionEnabled(L24CommandGroup.Qualcomm);
        set => SetCategoryState(L24CommandGroup.Qualcomm, value, nameof(IsQualcommCategoryEnabled), nameof(DiscQualcommButtonText));
    }

    public bool IsAppleCategoryEnabled
    {
        get => _orchestrator.IsCategoryDetectionEnabled(L24CommandGroup.AppleIos);
        set => SetCategoryState(L24CommandGroup.AppleIos, value, nameof(IsAppleCategoryEnabled), nameof(DiscAppleButtonText));
    }

    public bool IsAdbCategoryEnabled
    {
        get => _orchestrator.IsCategoryDetectionEnabled(L24CommandGroup.AdbFastboot);
        set => SetCategoryState(L24CommandGroup.AdbFastboot, value, nameof(IsAdbCategoryEnabled), nameof(DiscAdbButtonText));
    }

    public bool IsServerCloudCategoryEnabled
    {
        get => _orchestrator.IsCategoryDetectionEnabled(L24CommandGroup.ServerCloudLogin);
        set => SetCategoryState(L24CommandGroup.ServerCloudLogin, value, nameof(IsServerCloudCategoryEnabled), nameof(DiscServerCloudButtonText));
    }

    public bool IsTransferCategoryEnabled
    {
        get => _orchestrator.IsCategoryDetectionEnabled(L24CommandGroup.FileTransfer);
        set => SetCategoryState(L24CommandGroup.FileTransfer, value, nameof(IsTransferCategoryEnabled), nameof(DiscTransferButtonText));
    }

    public bool IsArchiveCategoryEnabled
    {
        get => _orchestrator.IsCategoryDetectionEnabled(L24CommandGroup.ArchiveUnpack);
        set => SetCategoryState(L24CommandGroup.ArchiveUnpack, value, nameof(IsArchiveCategoryEnabled), nameof(DiscArchiveButtonText));
    }

    public bool IsCryptoCategoryEnabled
    {
        get => _orchestrator.IsCategoryDetectionEnabled(L24CommandGroup.CryptoAuth);
        set => SetCategoryState(L24CommandGroup.CryptoAuth, value, nameof(IsCryptoCategoryEnabled), nameof(DiscCryptoButtonText));
    }

    public bool IsOtherCategoryEnabled
    {
        get => _orchestrator.IsCategoryDetectionEnabled(L24CommandGroup.OtherCommands);
        set => SetCategoryState(L24CommandGroup.OtherCommands, value, nameof(IsOtherCategoryEnabled), nameof(DiscOtherButtonText));
    }

    private void SetCategoryState(L24CommandGroup group, bool enabled, string propName, string buttonPropName)
    {
        if (_orchestrator.IsCategoryDetectionEnabled(group) != enabled)
        {
            _orchestrator.SetCategoryDetectionEnabled(group, enabled);
            OnPropertyChanged(propName);
            OnPropertyChanged(buttonPropName);
            FilteredDiscoveredRamEvents.Refresh();
        }
    }

    // استثناء الروابط من الأوامر المكتشفة في الذاكرة
    public bool ExcludeUrlsFromDiscovered
    {
        get => _orchestrator.ExcludeUrlsFromDiscovered;
        set
        {
            if (_orchestrator.ExcludeUrlsFromDiscovered != value)
            {
                _orchestrator.ExcludeUrlsFromDiscovered = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(DiscServerCloudButtonText));
                FilteredDiscoveredRamEvents.Refresh();
            }
        }
    }

    // استثناء الروابط من السجل الخام (مفعل افتراضياً)
    public bool ExcludeUrlsFromRawLog
    {
        get => _orchestrator.ExcludeUrlsFromRawLog;
        set
        {
            if (_orchestrator.ExcludeUrlsFromRawLog != value)
            {
                _orchestrator.ExcludeUrlsFromRawLog = value;
                OnPropertyChanged();
                FilteredUnfilteredRawEvents.Refresh();
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

    public ICommand ToggleL24MasterCommand { get; }
    public ICommand StartL24Command { get; }
    public ICommand StopL24Command { get; }

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

    public ICommand LaunchToolCommand { get; }
    public ICommand AttachProcessCommand { get; }
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

    public ICommand ToggleUnfilteredRawLoggingCommand { get; }
    public ICommand ClearUnfilteredRawCommand { get; }

    public ICommand ToggleCategoryConfigPanelCommand { get; }
    public ICommand EnableAllCategoriesCommand { get; }
    public ICommand DisableAllCategoriesCommand { get; }
    public ICommand ExcludeUrlsCommand { get; }
    public ICommand ToggleCategoryCommand { get; }

    public ICommand ClearEventsCommand { get; }
    public ICommand ExportLogsCommand { get; }
    public ICommand ExportPurePhoneCommandsCommand { get; }
    public ICommand ExportSelectedDiscoveredCategoryCommand { get; }
    public ICommand ExportAllDiscoveredCategoriesSeparatelyCommand { get; }
    public ICommand ExportUnfilteredRawLogsCommand { get; }
    public ICommand OpenLogsFolderCommand { get; }
    public ICommand OpenCapturedFilesFolderCommand { get; }
    public ICommand ClearOriginFilterCommand { get; }
    public ICommand SetDiscoveredCategoryFilterCommand { get; }

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

                switch (evt.Scope)
                {
                    case L24CommandScope.ExecutedOnDevice:
                        // حظر قاطع للروابط وطلبات الشبكة من تبويب الأوامر الفعلية للجهاز
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
                        if (evt.Stage is SentinelStage.RamUnpackOrModuleLoad or SentinelStage.LocalFilePreparation)
                        {
                            AddArtifactIfNotExists(evt);
                        }
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

    public void NotifyAllCategoryProperties()
    {
        OnPropertyChanged(nameof(IsModemCategoryEnabled));
        OnPropertyChanged(nameof(IsMtkCategoryEnabled));
        OnPropertyChanged(nameof(IsQualcommCategoryEnabled));
        OnPropertyChanged(nameof(IsAppleCategoryEnabled));
        OnPropertyChanged(nameof(IsAdbCategoryEnabled));
        OnPropertyChanged(nameof(IsServerCloudCategoryEnabled));
        OnPropertyChanged(nameof(IsTransferCategoryEnabled));
        OnPropertyChanged(nameof(IsArchiveCategoryEnabled));
        OnPropertyChanged(nameof(IsCryptoCategoryEnabled));
        OnPropertyChanged(nameof(IsOtherCategoryEnabled));
        OnPropertyChanged(nameof(ExcludeUrlsFromDiscovered));
        OnPropertyChanged(nameof(ExcludeUrlsFromRawLog));
        UpdateDiscoveredCategoryCounters();
    }

    private void UpdateDiscoveredCategoryCounters()
    {
        OnPropertyChanged(nameof(DiscModemCount));
        OnPropertyChanged(nameof(DiscMtkCount));
        OnPropertyChanged(nameof(DiscQualcommCount));
        OnPropertyChanged(nameof(DiscAppleCount));
        OnPropertyChanged(nameof(DiscAdbCount));
        OnPropertyChanged(nameof(DiscServerCloudCount));
        OnPropertyChanged(nameof(DiscTransferCount));
        OnPropertyChanged(nameof(DiscArchiveCount));
        OnPropertyChanged(nameof(DiscCryptoCount));
        OnPropertyChanged(nameof(DiscOtherCount));

        OnPropertyChanged(nameof(DiscAllButtonText));
        OnPropertyChanged(nameof(DiscModemButtonText));
        OnPropertyChanged(nameof(DiscMtkButtonText));
        OnPropertyChanged(nameof(DiscQualcommButtonText));
        OnPropertyChanged(nameof(DiscAppleButtonText));
        OnPropertyChanged(nameof(DiscAdbButtonText));
        OnPropertyChanged(nameof(DiscServerCloudButtonText));
        OnPropertyChanged(nameof(DiscTransferButtonText));
        OnPropertyChanged(nameof(DiscArchiveButtonText));
        OnPropertyChanged(nameof(DiscCryptoButtonText));
        OnPropertyChanged(nameof(DiscOtherButtonText));
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
                IsUnpackedInRam: evt.HookedApiName.Contains("VirtualProtect", StringComparison.OrdinalIgnoreCase),
                DetectionTimestamp: evt.Timestamp,
                ProcessId: evt.ProcessId
            ));
        }
    }

    private void RefreshAllViews()
    {
        FilteredExecutedEvents.Refresh();
        FilteredPurePhoneEvents.Refresh();
        FilteredDiscoveredRamEvents.Refresh();
        FilteredRadarEvents.Refresh();
        FilteredUnfilteredRawEvents.Refresh();
        FilteredEvents.Refresh();
    }

    private bool FilterExecutedDeviceItem(object obj)
    {
        if (obj is not SourceTelemetryEvent item) return false;

        // عزل 100%: حجب أي رابط أو طلب سيرفر أو تسجيل دخول من الظهور في تبويب الأوامر الفعلية
        if (item.CommandGroup == L24CommandGroup.ServerCloudLogin || L24CommandClassifier.IsUrlOrNetworkOrAuth(item))
            return false;

        return FilterCommonItem(item);
    }

    private bool FilterCommonItem(object obj)
    {
        if (obj is not SourceTelemetryEvent item) return false;
        if (!ShowPhoneResponses && item.IsPhoneResponse) return false;

        if (!string.IsNullOrWhiteSpace(_activeOriginFilter))
        {
            bool originMatches = item.CallerModuleOrigin.Contains(_activeOriginFilter, StringComparison.OrdinalIgnoreCase)
                              || item.TargetResource.Contains(_activeOriginFilter, StringComparison.OrdinalIgnoreCase);
            if (!originMatches) return false;
        }

        if (!string.IsNullOrWhiteSpace(_searchText))
        {
            string q = _searchText.Trim();
            return item.DecodedCommandText.Contains(q, StringComparison.OrdinalIgnoreCase)
                || item.PureCommandText.Contains(q, StringComparison.OrdinalIgnoreCase)
                || item.TargetResource.Contains(q, StringComparison.OrdinalIgnoreCase)
                || item.CallerModuleOrigin.Contains(q, StringComparison.OrdinalIgnoreCase)
                || item.CommandCategory.Contains(q, StringComparison.OrdinalIgnoreCase);
        }

        return true;
    }

    private bool FilterDiscoveredRamItem(object obj)
    {
        if (obj is not SourceTelemetryEvent item) return false;
        if (!FilterCommonItem(item)) return false;

        // إخفاء الفئات المعطلة من العرض
        if (!_orchestrator.IsCategoryDetectionEnabled(item.CommandGroup))
            return false;

        // استثناء الروابط عند تفعيل استثناء الروابط
        if (ExcludeUrlsFromDiscovered && (item.CommandGroup == L24CommandGroup.ServerCloudLogin || L24CommandClassifier.IsUrlOrNetworkOrAuth(item)))
            return false;

        if (_discoveredCategoryFilter != "All" && Enum.TryParse<L24CommandGroup>(_discoveredCategoryFilter, out var grp))
        {
            if (item.CommandGroup != grp) return false;
        }
        return true;
    }

    private bool FilterUnfilteredRawItem(object obj)
    {
        if (obj is not SourceTelemetryEvent item) return false;

        // استثناء الروابط واستدعاءات الخوادم من السجل الخام عند تفعيل الخيار (مفعل افتراضياً)
        if (ExcludeUrlsFromRawLog && (item.CommandGroup == L24CommandGroup.ServerCloudLogin || L24CommandClassifier.IsUrlOrNetworkOrAuth(item)))
            return false;

        if (string.IsNullOrWhiteSpace(_searchText)) return true;

        string q = _searchText.Trim();
        return item.DecodedCommandText.Contains(q, StringComparison.OrdinalIgnoreCase)
            || item.PureCommandText.Contains(q, StringComparison.OrdinalIgnoreCase)
            || item.TargetResource.Contains(q, StringComparison.OrdinalIgnoreCase)
            || item.CallerModuleOrigin.Contains(q, StringComparison.OrdinalIgnoreCase)
            || item.CommandCategory.Contains(q, StringComparison.OrdinalIgnoreCase)
            || item.HookedApiName.Contains(q, StringComparison.OrdinalIgnoreCase);
    }

    private void ExecuteClearEvents()
    {
        lock (_lockObj)
        {
            ExecutedDeviceEvents.Clear();
            PurePhoneTestableEvents.Clear();
            DiscoveredRamEvents.Clear();
            RadarAndFileEvents.Clear();
            UnfilteredRawEvents.Clear();
            LiveEvents.Clear();
            LoadedArtifacts.Clear();
            SelectedEvent = null;
            SelectedArtifact = null;
            NotifyCounterProperties();
            UpdateDiscoveredCategoryCounters();
        }
        ForensicNoiseGate.ResetSessionDeduplication();
        StatusMessage = "تم تنظيف كافة التبويبات وإعادة ضبط الجلسة.";
    }

    private void ExecuteExportUnfilteredRawLogs()
    {
        try
        {
            var items = UnfilteredRawEvents.ToList();
            string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            string baseFile = Path.Combine(_orchestrator.LogDirectory, $"L24_Unfiltered_Raw_Complete_{timestamp}");

            WriteCategoryExportFiles(baseFile, "السجل الشامل الخام بدون فلترة (Unfiltered Raw Stream - كافة العمليات والروابط وتسجيل الدخول)", items);
            StatusMessage = $"تم تصدير السجل الشامل الخام ({items.Count} عملية) إلى: {baseFile}.txt | ويُحفظ تلقائياً في: {Path.GetFileName(_orchestrator.UnfilteredRawTxtPath)}";
            MessageBox.Show(
                $"تم تصدير السجل الشامل الخام بدون فلترة ({items.Count} عملية) بنجاح:\n\n1. ملف التصدير الفوري:\n{baseFile}.txt\n\n2. ملف التسجيل التلقائي المستمر:\n{_orchestrator.UnfilteredRawTxtPath}",
                "تصدير السجل الشامل الخام (بدون فلترة)",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"تعذر تصدير السجل الخام: {ex.Message}", "خطأ", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void ExecuteExportSelectedDiscoveredCategory()
    {
        try
        {
            var items = FilteredDiscoveredRamEvents.Cast<SourceTelemetryEvent>().ToList();
            string catSlug = _discoveredCategoryFilter == "All" ? "All_Discovered" : _discoveredCategoryFilter;
            string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            string baseFile = Path.Combine(_orchestrator.LogDirectory, $"L24_Discovered_{catSlug}_{timestamp}");

            WriteCategoryExportFiles(baseFile, $"الأوامر المكتشفة في الذاكرة — الفئة: {catSlug}", items);
            StatusMessage = $"تم تصدير الفئة ({catSlug}) بنجاح ({items.Count} أمر) إلى: {baseFile}.txt";
            MessageBox.Show($"تم تصدير أوامر الفئة [{catSlug}] بنجاح ({items.Count} أمر):\n{baseFile}.txt\n{baseFile}.json",
                "تصدير الفئة المحددة", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"تعذر التصدير: {ex.Message}", "خطأ", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void ExecuteExportAllDiscoveredCategoriesSeparately()
    {
        try
        {
            string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            string exportFolder = Path.Combine(_orchestrator.LogDirectory, $"Export_By_Category_{timestamp}");
            Directory.CreateDirectory(exportFolder);

            int exportedFilesCount = 0;

            var executedList = ExecutedDeviceEvents.ToList();
            if (executedList.Count > 0)
            {
                WriteCategoryExportFiles(Path.Combine(exportFolder, "01_Executed_On_Device"), "الأوامر الفعلية المنفذة للجهاز", executedList);
                exportedFilesCount++;
            }

            var pureList = PurePhoneTestableEvents.ToList();
            if (pureList.Count > 0)
            {
                WriteCategoryExportFiles(Path.Combine(exportFolder, "02_Pure_Phone_Testable"), "أوامر الهاتف الصافية للتجربة", pureList);
                exportedFilesCount++;
            }

            var rawList = UnfilteredRawEvents.ToList();
            if (rawList.Count > 0)
            {
                WriteCategoryExportFiles(Path.Combine(exportFolder, "03_Unfiltered_Raw_Everything"), "السجل الشامل الخام بدون فلترة", rawList);
                exportedFilesCount++;
            }

            foreach (L24CommandGroup group in Enum.GetValues<L24CommandGroup>())
            {
                var groupItems = DiscoveredRamEvents.Where(e => e.CommandGroup == group).ToList();
                if (groupItems.Count == 0) continue;

                string slug = L24CommandClassifier.GetGroupShortSlug(group);
                string title = L24CommandClassifier.GetGroupArabicTitle(group);
                WriteCategoryExportFiles(Path.Combine(exportFolder, $"Discovered_{slug}"), title, groupItems);
                exportedFilesCount++;
            }

            StatusMessage = $"تم تصدير {exportedFilesCount} ملفات منفصلة في المجلد: {exportFolder}";
            MessageBox.Show($"تم تصدير كل نوع في ملفات منفصلة بنجاح ({exportedFilesCount} ملفات) داخل المجلد:\n{exportFolder}",
                "تصدير كافة الفئات بشكل منفصل", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"تعذر تصدير الفئات: {ex.Message}", "خطأ", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void ExecuteExportPurePhoneCommands()
    {
        try
        {
            var items = PurePhoneTestableEvents.ToList();
            string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            string baseFile = Path.Combine(_orchestrator.LogDirectory, $"L24_PurePhone_Testable_{timestamp}");

            WriteCategoryExportFiles(baseFile, "أوامر الهاتف الصافية القابلة للتجربة المباشرة", items);
            StatusMessage = $"تم تصدير أوامر الهاتف للتجربة ({items.Count} أمر) إلى: {baseFile}.txt";
            MessageBox.Show($"تم تصدير أوامر الهاتف الصافية للتجربة بنجاح:\n{baseFile}.txt\n{baseFile}.json",
                "تصدير أوامر الهاتف للتجربة", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"تعذر تصدير أوامر الهاتف: {ex.Message}", "خطأ", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private static void WriteCategoryExportFiles(string basePathWithoutExt, string headerTitle, List<SourceTelemetryEvent> items)
    {
        string txtPath = basePathWithoutExt + ".txt";
        string jsonPath = basePathWithoutExt + ".json";

        var sb = new StringBuilder();
        sb.AppendLine($"=== {headerTitle} ===");
        sb.AppendLine($"تاريخ التصدير: {DateTime.Now:yyyy-MM-dd HH:mm:ss} | إجمالي السجلات: {items.Count}");
        sb.AppendLine(new string('=', 80));
        sb.AppendLine();

        sb.AppendLine("--- [أولاً: القائمة الصافية السريعة] ---");
        foreach (var ev in items)
        {
            sb.AppendLine(ev.PureCommandText);
        }
        sb.AppendLine();
        sb.AppendLine(new string('=', 80));
        sb.AppendLine("--- [ثانياً: التفاصيل الجنائية الكاملة لكل حدث] ---");
        sb.AppendLine();

        foreach (var ev in items)
        {
            sb.AppendLine($"[{ev.TimeFormatted}] [PID:{ev.ProcessId}] [{ev.CommandGroupBadge}] ({ev.CommandCategory})");
            sb.AppendLine($"الأمر الصافي : {ev.PureCommandText}");
            sb.AppendLine($"الوصف       : {ev.DecodedCommandText}");
            sb.AppendLine($"الهدف/البورت : {ev.TargetResource} | المصدر: {ev.CallerModuleOrigin}");
            if (!string.IsNullOrWhiteSpace(ev.SavedFilePath))
                sb.AppendLine($"الملف المحفوظ: {ev.SavedFilePath}");
            sb.AppendLine(new string('-', 60));
        }

        File.WriteAllText(txtPath, sb.ToString(), Encoding.UTF8);

        var options = new JsonSerializerOptions
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            WriteIndented = true
        };
        var cleanDtos = items.Select(e => new
        {
            e.FormattedTimestamp,
            e.ProcessId,
            Scope = e.Scope.ToString(),
            Group = e.CommandGroup.ToString(),
            e.CommandCategory,
            e.PureCommandText,
            e.DecodedCommandText,
            e.TargetResource,
            e.SavedFilePath,
            e.CallerModuleOrigin,
            e.HookedApiName,
            e.PayloadSize
        });
        File.WriteAllText(jsonPath, JsonSerializer.Serialize(cleanDtos, options), Encoding.UTF8);
    }

    private void ExecuteLaunchTool()
    {
        var ofd = new OpenFileDialog
        {
            Title = "اختر الأداة المراد فحصها ومراقبة أوامرها من المصدر (Launch & Intercept)",
            Filter = "برامج تنفيذية (*.exe)|*.exe|كافة الملفات (*.*)|*.*"
        };

        if (ofd.ShowDialog() == true)
        {
            StatusMessage = $"جاري تشغيل واعتراض الأداة: {Path.GetFileName(ofd.FileName)}...";
            if (_orchestrator.LaunchAndInterceptTool(ofd.FileName))
                StatusMessage = $"الأداة تعمل الآن تحت المراقبة الشاملة: {Path.GetFileName(ofd.FileName)}";
        }
    }

    private void ExecuteAttachProcess()
    {
        var dialog = new Window
        {
            Title = "الارتباط بعملية قيد التشغيل بالرام (Attach PID)",
            Width = 420,
            Height = 190,
            WindowStartupLocation = WindowStartupLocation.CenterScreen,
            Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(17, 22, 34)),
            ResizeMode = ResizeMode.NoResize,
            Owner = Application.Current?.MainWindow
        };

        var stack = new System.Windows.Controls.StackPanel { Margin = new Thickness(16) };
        var label = new System.Windows.Controls.TextBlock
        {
            Text = "أدخل رقم العملية (Process ID - PID) للأداة المفحوصة:",
            Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(226, 232, 240)),
            Margin = new Thickness(0, 0, 0, 10),
            FontSize = 12
        };
        var textBox = new System.Windows.Controls.TextBox
        {
            Height = 28,
            Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(15, 23, 42)),
            Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(248, 250, 252)),
            BorderBrush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(51, 65, 85)),
            Padding = new Thickness(6, 2, 6, 2),
            Margin = new Thickness(0, 0, 0, 14)
        };
        var btnPanel = new System.Windows.Controls.StackPanel { Orientation = System.Windows.Controls.Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        var okBtn = new System.Windows.Controls.Button { Content = "ارتباط (Attach)", Width = 100, Height = 28, Margin = new Thickness(0, 0, 8, 0) };
        var cancelBtn = new System.Windows.Controls.Button { Content = "إلغاء", Width = 70, Height = 28 };

        okBtn.Click += (_, _) => { dialog.DialogResult = true; dialog.Close(); };
        cancelBtn.Click += (_, _) => { dialog.DialogResult = false; dialog.Close(); };

        btnPanel.Children.Add(okBtn);
        btnPanel.Children.Add(cancelBtn);
        stack.Children.Add(label);
        stack.Children.Add(textBox);
        stack.Children.Add(btnPanel);
        dialog.Content = stack;

        if (dialog.ShowDialog() == true && int.TryParse(textBox.Text.Trim(), out int pid))
        {
            if (_orchestrator.AttachToRunningProcess(pid))
                StatusMessage = $"تم الارتباط بنجاح بالعملية PID {pid}";
        }
    }

    private void ExecuteExportLogs()
    {
        _orchestrator.FlushAndExportSessionSnapshot();
        ExecuteExportAllDiscoveredCategoriesSeparately();
    }

    private void ExecuteOpenLogsFolder()
    {
        try
        {
            if (Directory.Exists(_orchestrator.LogDirectory))
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = _orchestrator.LogDirectory,
                    UseShellExecute = true
                });
            }
        }
        catch { }
    }

    private void ExecuteOpenCapturedFilesFolder()
    {
        try
        {
            string dir = _orchestrator.CapturedFilesDirectory;
            Directory.CreateDirectory(dir);
            Process.Start(new ProcessStartInfo
            {
                FileName = dir,
                UseShellExecute = true
            });
        }
        catch { }
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

    private sealed class RelayCommand : ICommand
    {
        private readonly Action<object?> _execute;
        private readonly Predicate<object?>? _canExecute;
        public RelayCommand(Action<object?> execute, Predicate<object?>? canExecute = null)
        {
            _execute = execute ?? throw new ArgumentNullException(nameof(execute));
            _canExecute = canExecute;
        }
        public bool CanExecute(object? parameter) => _canExecute?.Invoke(parameter) ?? true;
        public void Execute(object? parameter) => _execute(parameter);
        public event EventHandler? CanExecuteChanged
        {
            add => CommandManager.RequerySuggested += value;
            remove => CommandManager.RequerySuggested -= value;
        }
    }
}
