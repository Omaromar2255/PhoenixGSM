using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
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
    private readonly object _lockObj = new();

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
                FilteredEvents.Refresh();
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
                FilteredEvents.Refresh();
            }
        }
    }

    private string _stageFilterMode = "All"; // All, ModemUsb, Radar, RamModules, PipesShell
    public string StageFilterMode
    {
        get => _stageFilterMode;
        set
        {
            if (_stageFilterMode != value)
            {
                _stageFilterMode = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(IsAllFilterSelected));
                OnPropertyChanged(nameof(IsModemUsbFilterSelected));
                OnPropertyChanged(nameof(IsRadarFilterSelected));
                OnPropertyChanged(nameof(IsRamFilterSelected));
                OnPropertyChanged(nameof(IsPipesFilterSelected));
                FilteredEvents.Refresh();
            }
        }
    }

    public bool IsAllFilterSelected => StageFilterMode == "All";
    public bool IsModemUsbFilterSelected => StageFilterMode == "ModemUsb";
    public bool IsRadarFilterSelected => StageFilterMode == "Radar";
    public bool IsRamFilterSelected => StageFilterMode == "RamModules";
    public bool IsPipesFilterSelected => StageFilterMode == "PipesShell";

    // Metrics Counters
    public int TotalEventsCount => LiveEvents.Count;
    private int _rawCommandsCount;
    public int RawCommandsCount { get => _rawCommandsCount; private set { _rawCommandsCount = value; OnPropertyChanged(); } }
    private int _radarScansCount;
    public int RadarScansCount { get => _radarScansCount; private set { _radarScansCount = value; OnPropertyChanged(); } }
    private int _ramUnpacksCount;
    public int RamUnpacksCount { get => _ramUnpacksCount; private set { _ramUnpacksCount = value; OnPropertyChanged(); } }
    private int _networkEventsCount;
    public int NetworkEventsCount { get => _networkEventsCount; private set { _networkEventsCount = value; OnPropertyChanged(); } }

    private string _statusMessage = "مستعد لمراقبة الأداة من المصدر (Ready)";
    public string StatusMessage { get => _statusMessage; set { _statusMessage = value; OnPropertyChanged(); } }

    public ICommand LaunchToolCommand { get; }
    public ICommand AttachProcessCommand { get; }
    public ICommand ClearEventsCommand { get; }
    public ICommand ExportLogsCommand { get; }
    public ICommand OpenLogsFolderCommand { get; }
    public ICommand ClearOriginFilterCommand { get; }
    public ICommand SetFilterModeCommand { get; }

    public SourceSentinelViewModel()
    {
        _orchestrator = new SourceSentinelOrchestrator();

        FilteredEvents = CollectionViewSource.GetDefaultView(LiveEvents);
        FilteredEvents.Filter = FilterEventItem;

        FilteredArtifacts = CollectionViewSource.GetDefaultView(LoadedArtifacts);

        BindingOperations.EnableCollectionSynchronization(LiveEvents, _lockObj);
        BindingOperations.EnableCollectionSynchronization(LoadedArtifacts, _lockObj);

        _orchestrator.OnTelemetryEventCaptured += OnEventCaptured;
        _orchestrator.OnLogMessage += msg => StatusMessage = msg;

        // Commands
        LaunchToolCommand = new RelayCommand(_ => ExecuteLaunchTool());
        AttachProcessCommand = new RelayCommand(_ => ExecuteAttachProcess());
        ClearEventsCommand = new RelayCommand(_ => ExecuteClearEvents());
        ExportLogsCommand = new RelayCommand(_ => ExecuteExportLogs());
        OpenLogsFolderCommand = new RelayCommand(_ => ExecuteOpenLogsFolder());
        ClearOriginFilterCommand = new RelayCommand(_ => { ActiveOriginFilter = null; SelectedArtifact = null; });
        SetFilterModeCommand = new RelayCommand(param => { if (param is string mode) StageFilterMode = mode; });

        // بدء تشغيل الخادم تلقائياً
        _orchestrator.Start();
    }

    private void OnEventCaptured(SourceTelemetryEvent evt)
    {
        Application.Current?.Dispatcher.InvokeAsync(() =>
        {
            lock (_lockObj)
            {
                if (LiveEvents.Count >= 20000)
                {
                    LiveEvents.RemoveAt(0);
                }
                LiveEvents.Add(evt);

                // تحديث العدادات
                switch (evt.Stage)
                {
                    case SentinelStage.RawCommandExecution:
                        RawCommandsCount++;
                        break;
                    case SentinelStage.PortAndDeviceRadar:
                        RadarScansCount++;
                        break;
                    case SentinelStage.RamUnpackOrModuleLoad:
                        RamUnpacksCount++;
                        AddArtifactIfNotExists(evt);
                        break;
                    case SentinelStage.NetworkPreEncryption:
                        NetworkEventsCount++;
                        break;
                }
                OnPropertyChanged(nameof(TotalEventsCount));
            }
        });
    }

    private void AddArtifactIfNotExists(SourceTelemetryEvent evt)
    {
        string moduleName = Path.GetFileName(evt.TargetResource);
        if (string.IsNullOrWhiteSpace(moduleName)) moduleName = evt.CallerModuleOrigin;

        bool exists = LoadedArtifacts.Any(a => a.ModuleName.Equals(moduleName, StringComparison.OrdinalIgnoreCase)
                                            || a.FilePath.Equals(evt.TargetResource, StringComparison.OrdinalIgnoreCase));
        if (!exists)
        {
            var artifact = new LoadedModuleArtifact(
                ModuleName: moduleName,
                FilePath: evt.TargetResource,
                BaseAddress: IntPtr.Zero,
                MemorySize: evt.PayloadSize,
                IsUnpackedInRam: evt.HookedApiName.Contains("VirtualProtect", StringComparison.OrdinalIgnoreCase),
                DetectionTimestamp: evt.Timestamp,
                ProcessId: evt.ProcessId
            );
            LoadedArtifacts.Add(artifact);
        }
    }

    private bool FilterEventItem(object obj)
    {
        if (obj is not SourceTelemetryEvent item) return false;

        // فلترة حسب المصدر المحدد (Origin Attribution)
        if (!string.IsNullOrWhiteSpace(_activeOriginFilter))
        {
            bool originMatches = item.CallerModuleOrigin.Contains(_activeOriginFilter, StringComparison.OrdinalIgnoreCase)
                              || item.TargetResource.Contains(_activeOriginFilter, StringComparison.OrdinalIgnoreCase);
            if (!originMatches) return false;
        }

        // فلترة حسب وضع المرحلة
        if (StageFilterMode == "ModemUsb")
        {
            bool isModemUsb = item.CommandCategory.Contains("AT", StringComparison.OrdinalIgnoreCase)
                           || item.CommandCategory.Contains("MTK", StringComparison.OrdinalIgnoreCase)
                           || item.CommandCategory.Contains("BROM", StringComparison.OrdinalIgnoreCase)
                           || item.CommandCategory.Contains("Sahara", StringComparison.OrdinalIgnoreCase)
                           || item.CommandCategory.Contains("Firehose", StringComparison.OrdinalIgnoreCase)
                           || item.CommandCategory.Contains("Odin", StringComparison.OrdinalIgnoreCase)
                           || item.CommandCategory.Contains("BSL", StringComparison.OrdinalIgnoreCase)
                           || item.CommandCategory.Contains("BaudRate", StringComparison.OrdinalIgnoreCase)
                           || item.CommandCategory.Contains("Port Config", StringComparison.OrdinalIgnoreCase);
            if (!isModemUsb) return false;
        }
        else if (StageFilterMode == "Radar")
        {
            if (item.Stage != SentinelStage.PortAndDeviceRadar && item.Stage != SentinelStage.LocalFilePreparation)
                return false;
        }
        else if (StageFilterMode == "RamModules")
        {
            if (item.Stage != SentinelStage.RamUnpackOrModuleLoad)
                return false;
        }
        else if (StageFilterMode == "PipesShell")
        {
            bool isPipeOrShell = item.CommandCategory.Contains("Pipe", StringComparison.OrdinalIgnoreCase)
                              || item.CommandCategory.Contains("Shell", StringComparison.OrdinalIgnoreCase)
                              || item.TargetResource.Contains("pipe", StringComparison.OrdinalIgnoreCase);
            if (!isPipeOrShell) return false;
        }

        // فلترة حسب نص البحث
        if (!string.IsNullOrWhiteSpace(_searchText))
        {
            string q = _searchText.Trim();
            bool textMatches = item.DecodedCommandText.Contains(q, StringComparison.OrdinalIgnoreCase)
                            || item.TargetResource.Contains(q, StringComparison.OrdinalIgnoreCase)
                            || item.CallerModuleOrigin.Contains(q, StringComparison.OrdinalIgnoreCase)
                            || item.CommandCategory.Contains(q, StringComparison.OrdinalIgnoreCase)
                            || item.HookedApiName.Contains(q, StringComparison.OrdinalIgnoreCase);
            if (!textMatches) return false;
        }

        return true;
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
            bool ok = _orchestrator.LaunchAndInterceptTool(ofd.FileName);
            if (ok)
            {
                StatusMessage = $"الأداة تعمل الآن تحت المراقبة الجنائية المباشرة من المصدر: {Path.GetFileName(ofd.FileName)}";
            }
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
        var okBtn = new System.Windows.Controls.Button
        {
            Content = "ارتباط (Attach)",
            Width = 100,
            Height = 28,
            Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(2, 132, 199)),
            Foreground = System.Windows.Media.Brushes.White,
            Margin = new Thickness(0, 0, 8, 0)
        };
        var cancelBtn = new System.Windows.Controls.Button
        {
            Content = "إلغاء",
            Width = 70,
            Height = 28,
            Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(30, 41, 59)),
            Foreground = System.Windows.Media.Brushes.White
        };

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
            StatusMessage = $"جاري الارتباط بالعملية PID {pid}...";
            bool ok = _orchestrator.AttachToRunningProcess(pid);
            if (ok)
            {
                StatusMessage = $"تم الارتباط بنجاح بالعملية PID {pid}";
            }
        }
    }

    private void ExecuteClearEvents()
    {
        lock (_lockObj)
        {
            LiveEvents.Clear();
            LoadedArtifacts.Clear();
            SelectedEvent = null;
            SelectedArtifact = null;
            RawCommandsCount = 0;
            RadarScansCount = 0;
            RamUnpacksCount = 0;
            NetworkEventsCount = 0;
            OnPropertyChanged(nameof(TotalEventsCount));
        }
        StatusMessage = "تم تنظيف قائمة الأحداث الحالية.";
    }

    private void ExecuteExportLogs()
    {
        _orchestrator.FlushAndExportSessionSnapshot();
        StatusMessage = $"تم حفظ وتصدير الجلسة إلى: {_orchestrator.SessionLogPath}";
        MessageBox.Show($"تم حفظ سجلات الجلسة بنجاح في:\n{_orchestrator.SessionLogPath}", "تصدير السجلات L24", MessageBoxButton.OK, MessageBoxImage.Information);
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
        catch (Exception ex)
        {
            MessageBox.Show($"تعذر فتح المجلد: {ex.Message}", "خطأ", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    // Inspector Helpers
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
                int length = bytes.Length;

                for (int i = 0; i < length; i += 16)
                {
                    sb.AppendFormat("{0:X4}: ", i);
                    int chunk = Math.Min(16, length - i);

                    for (int j = 0; j < 16; j++)
                    {
                        if (j < chunk)
                            sb.AppendFormat("{0:X2} ", bytes[i + j]);
                        else
                            sb.Append("   ");
                        if (j == 7) sb.Append(" ");
                    }

                    sb.Append(" | ");
                    for (int j = 0; j < chunk; j++)
                    {
                        byte b = bytes[i + j];
                        sb.Append(b >= 32 && b <= 126 ? (char)b : '.');
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

    public string SelectedEventAsciiText
    {
        get
        {
            if (SelectedEvent == null) return "";
            if (!string.IsNullOrWhiteSpace(SelectedEvent.DecodedCommandText))
                return SelectedEvent.DecodedCommandText;
            return SelectedEventHexDump;
        }
    }

    public string SelectedEventDetails
    {
        get
        {
            if (SelectedEvent == null) return "اختر حدثاً من الجدول لعرض التفاصيل الجنائية الدقيقة.";
            return $"معرف الحدث: {SelectedEvent.EventId}\n" +
                   $"التوقيت: {SelectedEvent.Timestamp:yyyy-MM-dd HH:mm:ss.fff} UTC\n" +
                   $"العملية/المسار: PID {SelectedEvent.ProcessId} | TID {SelectedEvent.ThreadId}\n" +
                   $"المرحلة: {SelectedEvent.StageBadge}\n" +
                   $"الدالة المعترضة: {SelectedEvent.HookedApiName}\n" +
                   $"المصدر المسؤول (Origin): {SelectedEvent.CallerModuleOrigin}\n" +
                   $"المورد المستهدف: {SelectedEvent.TargetResource}\n" +
                   $"التصنيف: {SelectedEvent.CommandCategory}\n" +
                   $"حجم الحمولة: {SelectedEvent.PayloadSize} بايت";
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? propName = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propName));

    public void Dispose()
    {
        _orchestrator.Dispose();
    }

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
