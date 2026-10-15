using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Data;
using System.Windows.Input;
using PhoenixGSM.OmniTrace.ToolSourceInterception;

namespace PhoenixGSM.MonitoringStudio.ViewModels;

public partial class MainViewModel
{
    // ══════════════════════════════════════════════════════════════
    // TOOL-SOURCE COMMAND INTERCEPTION LAYER (TSCI) STATE & COLLECTIONS
    // ══════════════════════════════════════════════════════════════

    public ObservableCollection<ToolSourceCommandRecord> ToolSourceRecords { get; } = [];
    public ICollectionView FilteredToolSourceRecords { get; private set; } = null!;

    private ToolSourceCommandRecord? _selectedToolSourceRecord;
    public ToolSourceCommandRecord? SelectedToolSourceRecord
    {
        get => _selectedToolSourceRecord;
        set { _selectedToolSourceRecord = value; OnPropertyChanged(); }
    }

    private bool _isToolSourceInterceptionViewActive = false;
    public bool IsToolSourceInterceptionViewActive
    {
        get => _isToolSourceInterceptionViewActive;
        set
        {
            if (_isToolSourceInterceptionViewActive != value)
            {
                _isToolSourceInterceptionViewActive = value;
                if (value)
                {
                    _isTechnicianAuditViewActive = false;
                    OnPropertyChanged(nameof(IsTechnicianAuditViewActive));
                }
                OnPropertyChanged();
                OnPropertyChanged(nameof(IsGeneralForensicViewActive));
            }
        }
    }

    private string _toolSourceSearchText = "";
    public string ToolSourceSearchText
    {
        get => _toolSourceSearchText;
        set
        {
            if (_toolSourceSearchText != value)
            {
                _toolSourceSearchText = value;
                OnPropertyChanged();
                FilteredToolSourceRecords.Refresh();
            }
        }
    }

    private string _toolSourceSelectedMode = "ALL";
    public string ToolSourceSelectedMode
    {
        get => _toolSourceSelectedMode;
        set
        {
            if (_toolSourceSelectedMode != value)
            {
                _toolSourceSelectedMode = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(IsToolSourceAllSelected));
                OnPropertyChanged(nameof(IsToolSourceMtpSelected));
                OnPropertyChanged(nameof(IsToolSourceMtkSelected));
                OnPropertyChanged(nameof(IsToolSourceOdinSelected));
                OnPropertyChanged(nameof(IsToolSourcePortSelected));
                OnPropertyChanged(nameof(IsToolSourceEdlSelected));
                OnPropertyChanged(nameof(IsToolSourceSpdSelected));
                FilteredToolSourceRecords.Refresh();
            }
        }
    }

    public bool IsToolSourceAllSelected => ToolSourceSelectedMode == "ALL";
    public bool IsToolSourceMtpSelected => ToolSourceSelectedMode == "MTP";
    public bool IsToolSourceMtkSelected => ToolSourceSelectedMode == "MTK";
    public bool IsToolSourceOdinSelected => ToolSourceSelectedMode == "ODIN";
    public bool IsToolSourcePortSelected => ToolSourceSelectedMode == "PORT";
    public bool IsToolSourceEdlSelected => ToolSourceSelectedMode == "EDL";
    public bool IsToolSourceSpdSelected => ToolSourceSelectedMode == "SPD";

    // ══════════════════════════════════════════════════════════════
    // REAL-TIME STATISTICAL COUNTERS (TSCI)
    // ══════════════════════════════════════════════════════════════
    private int _toolSourceTotalCount = 0;
    public int ToolSourceTotalCount
    {
        get => _toolSourceTotalCount;
        set { _toolSourceTotalCount = value; OnPropertyChanged(); }
    }

    private int _toolSourceMtpCount = 0;
    public int ToolSourceMtpCount
    {
        get => _toolSourceMtpCount;
        set { _toolSourceMtpCount = value; OnPropertyChanged(); }
    }

    private int _toolSourceMtkCount = 0;
    public int ToolSourceMtkCount
    {
        get => _toolSourceMtkCount;
        set { _toolSourceMtkCount = value; OnPropertyChanged(); }
    }

    private int _toolSourceOdinCount = 0;
    public int ToolSourceOdinCount
    {
        get => _toolSourceOdinCount;
        set { _toolSourceOdinCount = value; OnPropertyChanged(); }
    }

    private int _toolSourcePortCount = 0;
    public int ToolSourcePortCount
    {
        get => _toolSourcePortCount;
        set { _toolSourcePortCount = value; OnPropertyChanged(); }
    }

    public string ToolSourceAutoSavePathDisplay =>
        _engine.ToolSourceOrchestrator != null
            ? _engine.ToolSourceOrchestrator.AutoLogger.LogDirectory
            : "Initializing...";

    // ══════════════════════════════════════════════════════════════
    // COMMANDS
    // ══════════════════════════════════════════════════════════════
    public ICommand SwitchToToolSourceViewCommand { get; private set; } = null!;
    public ICommand SelectToolSourceModeCommand { get; private set; } = null!;
    public ICommand ClearToolSourceCommand { get; private set; } = null!;
    public ICommand ExportToolSourceCommand { get; private set; } = null!;
    public ICommand OpenToolSourceLogFolderCommand { get; private set; } = null!;
    public ICommand CopyToolSourceCommandTextCommand { get; private set; } = null!;

    public event Action? RequestToolSourceScrollToBottom;

    private void InitializeToolSourceInterceptionLayer()
    {
        FilteredToolSourceRecords = CollectionViewSource.GetDefaultView(ToolSourceRecords);
        FilteredToolSourceRecords.Filter = FilterToolSourcePredicate;

        SwitchToToolSourceViewCommand = new RelayCommand(_ =>
        {
            IsTechnicianAuditViewActive = false;
            IsToolSourceInterceptionViewActive = true;
        });

        SelectToolSourceModeCommand = new RelayCommand(m => ToolSourceSelectedMode = m?.ToString() ?? "ALL");

        ClearToolSourceCommand = new RelayCommand(_ =>
        {
            ToolSourceRecords.Clear();
            SelectedToolSourceRecord = null;
            ToolSourceTotalCount = 0;
            ToolSourceMtpCount = 0;
            ToolSourceMtkCount = 0;
            ToolSourceOdinCount = 0;
            ToolSourcePortCount = 0;
        });

        ExportToolSourceCommand = new RelayCommand(_ => ExportToolSourceRecords());

        OpenToolSourceLogFolderCommand = new RelayCommand(_ =>
        {
            try
            {
                string dir = ToolSourceAutoSavePathDisplay;
                if (Directory.Exists(dir))
                {
                    Process.Start(new ProcessStartInfo("explorer.exe", dir) { UseShellExecute = true });
                }
            }
            catch { }
        });

        CopyToolSourceCommandTextCommand = new RelayCommand(_ =>
        {
            if (SelectedToolSourceRecord != null && !string.IsNullOrEmpty(SelectedToolSourceRecord.PureCommand))
            {
                Clipboard.SetText(SelectedToolSourceRecord.PureCommand);
                MessageBox.Show("تم نسخ أمر الأداة إلى الحافظة بنجاح!", "نسخ البيانات", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        });

        // Wire engine event
        _engine.OnToolSourceCommandCaptured += HandleToolSourceCommandReceived;
    }

    private void HandleToolSourceCommandReceived(ToolSourceCommandRecord record)
    {
        _dispatcher.InvokeAsync(() =>
        {
            if (ToolSourceRecords.Count >= 10000)
            {
                ToolSourceRecords.RemoveAt(0);
            }

            ToolSourceRecords.Add(record);
            ToolSourceTotalCount++;

            switch (record.Mode)
            {
                case ToolSourceMode.Mtp: ToolSourceMtpCount++; break;
                case ToolSourceMode.MtkBrom: ToolSourceMtkCount++; break;
                case ToolSourceMode.SamsungOdin: ToolSourceOdinCount++; break;
                case ToolSourceMode.SerialPort: ToolSourcePortCount++; break;
            }

            if (SelectedToolSourceRecord == null)
            {
                SelectedToolSourceRecord = record;
            }

            if (AutoScroll)
            {
                RequestToolSourceScrollToBottom?.Invoke();
            }
        });
    }

    private bool FilterToolSourcePredicate(object obj)
    {
        if (obj is not ToolSourceCommandRecord record) return false;

        // 1. Mode Chip Filter
        if (ToolSourceSelectedMode != "ALL")
        {
            bool matchesMode = ToolSourceSelectedMode switch
            {
                "MTP" => record.Mode == ToolSourceMode.Mtp,
                "MTK" => record.Mode == ToolSourceMode.MtkBrom,
                "ODIN" => record.Mode == ToolSourceMode.SamsungOdin,
                "PORT" => record.Mode == ToolSourceMode.SerialPort,
                "EDL" => record.Mode == ToolSourceMode.QualcommEdl,
                "SPD" => record.Mode == ToolSourceMode.UnisocSpd,
                _ => true
            };
            if (!matchesMode) return false;
        }

        // 2. Search Text
        if (!string.IsNullOrWhiteSpace(ToolSourceSearchText))
        {
            string q = ToolSourceSearchText.Trim().ToLowerInvariant();
            bool matchesSearch =
                record.PureCommand.ToLowerInvariant().Contains(q) ||
                record.RawCommand.ToLowerInvariant().Contains(q) ||
                record.ToolName.ToLowerInvariant().Contains(q) ||
                record.TargetEndpoint.ToLowerInvariant().Contains(q) ||
                record.InterceptMechanism.ToLowerInvariant().Contains(q) ||
                record.ModeName.ToLowerInvariant().Contains(q) ||
                record.TechnicalDetails.ToLowerInvariant().Contains(q);

            if (!matchesSearch) return false;
        }

        return true;
    }

    private void ExportToolSourceRecords()
    {
        try
        {
            var visibleRecords = FilteredToolSourceRecords.Cast<ToolSourceCommandRecord>().ToList();
            if (visibleRecords.Count == 0)
            {
                MessageBox.Show("لا توجد سجلات مطابقة للتصدير حالياً.", "تصدير أوامر الأدوات", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Title = "تصدير أوامر الأدوات الملتقطة من المصدر",
                FileName = $"Tool_Source_Commands_{DateTime.Now:yyyyMMdd_HHmmss}",
                Filter = "Clean Commands Text (*.txt)|*.txt|Forensic JSON (*.json)|*.json|All Files (*.*)|*.*",
                DefaultExt = ".txt"
            };

            if (dialog.ShowDialog() == true)
            {
                if (dialog.FileName.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
                {
                    string json = JsonSerializer.Serialize(visibleRecords, new JsonSerializerOptions { WriteIndented = true });
                    File.WriteAllText(dialog.FileName, json, Encoding.UTF8);
                }
                else
                {
                    var sb = new StringBuilder();
                    sb.AppendLine("================================================================================");
                    sb.AppendLine("     PHOENIX GSM — TOOL-SOURCE COMMAND INTERCEPTION AUDIT REPORT                ");
                    sb.AppendLine($" Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss} | Total Interceptions: {visibleRecords.Count}");
                    sb.AppendLine("================================================================================");
                    sb.AppendLine();

                    foreach (var r in visibleRecords)
                    {
                        sb.AppendLine($"[{r.TimeFormatted}] [{r.ModeName,-10}] [{r.ToolName} (PID {r.ProcessId})] [{r.InterceptMechanism}] -> {r.TargetEndpoint}");
                        sb.AppendLine($"  Command: {r.PureCommand}");
                        if (!string.IsNullOrWhiteSpace(r.TechnicalDetails))
                        {
                            sb.AppendLine($"  Details: {r.TechnicalDetails.Replace("\n", "\n  ")}");
                        }
                        sb.AppendLine(new string('-', 80));
                    }

                    File.WriteAllText(dialog.FileName, sb.ToString(), Encoding.UTF8);
                }

                MessageBox.Show($"تم تصدير {visibleRecords.Count:N0} سجلاً بنجاح إلى:\n{dialog.FileName}", "اكتمل التصدير", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"حدث خطأ أثناء تصدير السجلات:\n{ex.Message}", "خطأ في التصدير", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}
