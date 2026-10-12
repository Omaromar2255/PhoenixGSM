using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Data;
using System.Windows.Input;
using PhoenixGSM.OmniTrace.TechnicianAudit;

namespace PhoenixGSM.MonitoringStudio.ViewModels;

public partial class MainViewModel
{
    // ══════════════════════════════════════════════════════════════
    // DEDICATED TECHNICIAN COMMAND AUDIT LAYER STATE & COLLECTIONS
    // ══════════════════════════════════════════════════════════════

    public ObservableCollection<TechnicianAuditRecord> TechnicianAuditRecords { get; } = [];
    public ICollectionView FilteredTechnicianAuditRecords { get; private set; } = null!;

    private TechnicianAuditRecord? _selectedTechnicianRecord;
    public TechnicianAuditRecord? SelectedTechnicianRecord
    {
        get => _selectedTechnicianRecord;
        set { _selectedTechnicianRecord = value; OnPropertyChanged(); }
    }

    private bool _isTechnicianAuditViewActive = false;
    public bool IsTechnicianAuditViewActive
    {
        get => _isTechnicianAuditViewActive;
        set
        {
            if (_isTechnicianAuditViewActive != value)
            {
                _isTechnicianAuditViewActive = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(IsGeneralForensicViewActive));
            }
        }
    }
    public bool IsGeneralForensicViewActive => !IsTechnicianAuditViewActive;

    private string _techAuditSearchText = "";
    public string TechAuditSearchText
    {
        get => _techAuditSearchText;
        set
        {
            if (_techAuditSearchText != value)
            {
                _techAuditSearchText = value;
                OnPropertyChanged();
                FilteredTechnicianAuditRecords.Refresh();
            }
        }
    }

    private string _techAuditSelectedProtocol = "ALL";
    public string TechAuditSelectedProtocol
    {
        get => _techAuditSelectedProtocol;
        set
        {
            if (_techAuditSelectedProtocol != value)
            {
                _techAuditSelectedProtocol = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(IsTechAuditAllSelected));
                OnPropertyChanged(nameof(IsTechAuditAdbSelected));
                OnPropertyChanged(nameof(IsTechAuditAtSelected));
                OnPropertyChanged(nameof(IsTechAuditMtkSelected));
                OnPropertyChanged(nameof(IsTechAuditEdlSelected));
                OnPropertyChanged(nameof(IsTechAuditSpdSelected));
                OnPropertyChanged(nameof(IsTechAuditAppleSelected));
                OnPropertyChanged(nameof(IsTechAuditFastbootSelected));
                FilteredTechnicianAuditRecords.Refresh();
            }
        }
    }

    public bool IsTechAuditAllSelected => TechAuditSelectedProtocol == "ALL";
    public bool IsTechAuditAdbSelected => TechAuditSelectedProtocol == "ADB";
    public bool IsTechAuditAtSelected => TechAuditSelectedProtocol == "AT";
    public bool IsTechAuditMtkSelected => TechAuditSelectedProtocol == "MTK";
    public bool IsTechAuditEdlSelected => TechAuditSelectedProtocol == "EDL";
    public bool IsTechAuditSpdSelected => TechAuditSelectedProtocol == "SPD";
    public bool IsTechAuditAppleSelected => TechAuditSelectedProtocol == "APPLE";
    public bool IsTechAuditFastbootSelected => TechAuditSelectedProtocol == "FASTBOOT";

    // ══════════════════════════════════════════════════════════════
    // DEVICE RESPONSE INTERCEPTION TOGGLE & DIRECTION FILTERS
    // ══════════════════════════════════════════════════════════════
    private bool _isCaptureDeviceResponsesEnabled = false;
    public bool IsCaptureDeviceResponsesEnabled
    {
        get => _isCaptureDeviceResponsesEnabled;
        set
        {
            if (_isCaptureDeviceResponsesEnabled != value)
            {
                _isCaptureDeviceResponsesEnabled = value;
                _engine.CaptureDeviceResponses = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(DeviceResponseToggleLabel));
                OnPropertyChanged(nameof(DeviceResponseToggleTooltip));
                OnPropertyChanged(nameof(DeviceResponseStatusIcon));
                OnPropertyChanged(nameof(DeviceResponseToggleStatusText));
                OnPropertyChanged(nameof(DeviceResponseToggleStatusColor));
                OnPropertyChanged(nameof(DeviceResponseToggleForeground));
                OnPropertyChanged(nameof(DeviceResponseToggleBackground));
                OnPropertyChanged(nameof(DeviceResponseToggleBorder));
                FilteredTechnicianAuditRecords.Refresh();
            }
        }
    }

    public string DeviceResponseStatusIcon => IsCaptureDeviceResponsesEnabled ? "🟢" : "⚪";
    public string DeviceResponseToggleStatusText => IsCaptureDeviceResponsesEnabled ? "مفعّل 🟢" : "معطل ⚪";
    public string DeviceResponseToggleStatusColor => IsCaptureDeviceResponsesEnabled ? "#00FF9D" : "#8E9AA8";
    public string DeviceResponseToggleLabel => IsCaptureDeviceResponsesEnabled ? "التقاط رد الهاتف: مفعّل (أمر + رد)" : "التقاط رد الهاتف: معطل (أوامر فقط)";
    public string DeviceResponseToggleTooltip => IsCaptureDeviceResponsesEnabled 
        ? "إلغاء تفعيل التقاط ردود الهاتف الواردة والاكتفاء بالأوامر الصادرة فقط" 
        : "تفعيل التقاط وتسجيل ردود الهاتف الواردة (Device ➔ Host) جنباً إلى جنب مع الأوامر الصادرة مباشرة في السجلات والجدول";
    public string DeviceResponseToggleForeground => IsCaptureDeviceResponsesEnabled ? "#00FFC2" : "#8E9AA8";
    public string DeviceResponseToggleBackground => IsCaptureDeviceResponsesEnabled ? "#0B2B20" : "#151A24";
    public string DeviceResponseToggleBorder => IsCaptureDeviceResponsesEnabled ? "#00FF9D" : "#2A3347";

    private string _techAuditDirectionFilter = "ALL";
    public string TechAuditDirectionFilter
    {
        get => _techAuditDirectionFilter;
        set
        {
            if (_techAuditDirectionFilter != value)
            {
                _techAuditDirectionFilter = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(IsTechAuditDirAllSelected));
                OnPropertyChanged(nameof(IsTechAuditDirCmdsSelected));
                OnPropertyChanged(nameof(IsTechAuditDirResponsesSelected));
                FilteredTechnicianAuditRecords.Refresh();
            }
        }
    }

    public bool IsTechAuditDirAllSelected => TechAuditDirectionFilter == "ALL";
    public bool IsTechAuditDirCmdsSelected => TechAuditDirectionFilter == "COMMANDS";
    public bool IsTechAuditDirResponsesSelected => TechAuditDirectionFilter == "RESPONSES";

    // ══════════════════════════════════════════════════════════════
    // DEDICATED REAL-TIME STATISTICAL COUNTERS
    // ══════════════════════════════════════════════════════════════
    private int _techAuditTotalCount = 0;
    public int TechAuditTotalCount
    {
        get => _techAuditTotalCount;
        set { _techAuditTotalCount = value; OnPropertyChanged(); }
    }

    private int _techAuditOutboundCount = 0;
    public int TechAuditOutboundCount
    {
        get => _techAuditOutboundCount;
        set { _techAuditOutboundCount = value; OnPropertyChanged(); }
    }

    private int _techAuditInboundCount = 0;
    public int TechAuditInboundCount
    {
        get => _techAuditInboundCount;
        set { _techAuditInboundCount = value; OnPropertyChanged(); }
    }

    private int _techAuditAdbCount = 0;
    public int TechAuditAdbCount
    {
        get => _techAuditAdbCount;
        set { _techAuditAdbCount = value; OnPropertyChanged(); }
    }

    private int _techAuditAtCount = 0;
    public int TechAuditAtCount
    {
        get => _techAuditAtCount;
        set { _techAuditAtCount = value; OnPropertyChanged(); }
    }

    private int _techAuditMtkCount = 0;
    public int TechAuditMtkCount
    {
        get => _techAuditMtkCount;
        set { _techAuditMtkCount = value; OnPropertyChanged(); }
    }

    private int _techAuditEdlCount = 0;
    public int TechAuditEdlCount
    {
        get => _techAuditEdlCount;
        set { _techAuditEdlCount = value; OnPropertyChanged(); }
    }

    private int _techAuditSpdCount = 0;
    public int TechAuditSpdCount
    {
        get => _techAuditSpdCount;
        set { _techAuditSpdCount = value; OnPropertyChanged(); }
    }

    private int _techAuditAppleCount = 0;
    public int TechAuditAppleCount
    {
        get => _techAuditAppleCount;
        set { _techAuditAppleCount = value; OnPropertyChanged(); }
    }

    private int _techAuditFastbootCount = 0;
    public int TechAuditFastbootCount
    {
        get => _techAuditFastbootCount;
        set { _techAuditFastbootCount = value; OnPropertyChanged(); }
    }

    public string AutoSaveLogPathDisplay => _engine.TechnicianAuditLayer?.Store.CurrentJsonlPath ?? "Active -> Logs\\TechnicianAudit\\";

    // ══════════════════════════════════════════════════════════════
    // COMMANDS
    // ══════════════════════════════════════════════════════════════
    public ICommand SwitchToGeneralViewCommand { get; private set; } = null!;
    public ICommand SwitchToTechnicianAuditViewCommand { get; private set; } = null!;
    public ICommand SelectTechAuditProtocolCommand { get; private set; } = null!;
    public ICommand SelectTechAuditDirectionCommand { get; private set; } = null!;
    public ICommand ToggleDeviceResponseCaptureCommand { get; private set; } = null!;
    public ICommand ClearTechnicianAuditCommand { get; private set; } = null!;
    public ICommand ExportTechnicianAuditCommand { get; private set; } = null!;
    public ICommand OpenTechnicianAuditFolderCommand { get; private set; } = null!;
    public ICommand CopyTechnicianCommandTextCommand { get; private set; } = null!;
    public ICommand OpenTechnicianAuditWindowCommand { get; private set; } = null!;

    private void InitializeTechnicianAuditLayer()
    {
        FilteredTechnicianAuditRecords = CollectionViewSource.GetDefaultView(TechnicianAuditRecords);
        FilteredTechnicianAuditRecords.Filter = FilterTechnicianAuditPredicate;

        SwitchToGeneralViewCommand = new RelayCommand(_ => IsTechnicianAuditViewActive = false);
        SwitchToTechnicianAuditViewCommand = new RelayCommand(_ => IsTechnicianAuditViewActive = true);
        SelectTechAuditProtocolCommand = new RelayCommand(p => TechAuditSelectedProtocol = p?.ToString() ?? "ALL");
        SelectTechAuditDirectionCommand = new RelayCommand(d => TechAuditDirectionFilter = d?.ToString() ?? "ALL");
        ToggleDeviceResponseCaptureCommand = new RelayCommand(_ =>
        {
            IsCaptureDeviceResponsesEnabled = !IsCaptureDeviceResponsesEnabled;
        });

        ClearTechnicianAuditCommand = new RelayCommand(_ =>
        {
            TechnicianAuditRecords.Clear();
            SelectedTechnicianRecord = null;
            TechAuditTotalCount = 0;
            TechAuditOutboundCount = 0;
            TechAuditInboundCount = 0;
            TechAuditAdbCount = 0;
            TechAuditAtCount = 0;
            TechAuditMtkCount = 0;
            TechAuditEdlCount = 0;
            TechAuditSpdCount = 0;
            TechAuditAppleCount = 0;
            TechAuditFastbootCount = 0;
        });

        ExportTechnicianAuditCommand = new RelayCommand(_ => ExportTechnicianAuditRecords());
        OpenTechnicianAuditFolderCommand = new RelayCommand(_ =>
        {
            _engine.TechnicianAuditLayer?.Store.OpenLogFolder();
        });

        CopyTechnicianCommandTextCommand = new RelayCommand(_ =>
        {
            if (SelectedTechnicianRecord != null && !string.IsNullOrEmpty(SelectedTechnicianRecord.PureCommand))
            {
                Clipboard.SetText(SelectedTechnicianRecord.PureCommand);
                MessageBox.Show("تم نسخ النص النقي إلى الحافظة بنجاح!", "نسخ البيانات", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        });

        OpenTechnicianAuditWindowCommand = new RelayCommand(_ =>
        {
            var win = new Views.TechnicianAuditWindow
            {
                DataContext = this,
                Owner = Application.Current.MainWindow
            };
            win.Show();
        });

        _engine.OnTechnicianAuditCaptured += HandleTechnicianAuditCaptured;
    }

    private void HandleTechnicianAuditCaptured(TechnicianAuditRecord record)
    {
        _dispatcher.InvokeAsync(() =>
        {
            if (TechnicianAuditRecords.Count >= 10000)
            {
                TechnicianAuditRecords.RemoveAt(0);
            }

            TechnicianAuditRecords.Add(record);
            TechAuditTotalCount++;

            if (record.IsResponse)
                TechAuditInboundCount++;
            else
                TechAuditOutboundCount++;

            string p = record.Protocol.ToUpperInvariant();
            if (p.Contains("ADB") || p.Contains("SHELL")) TechAuditAdbCount++;
            else if (p.Contains("AT")) TechAuditAtCount++;
            else if (p.Contains("MTK")) TechAuditMtkCount++;
            else if (p.Contains("EDL") || p.Contains("QCOM") || p.Contains("FIREHOSE") || p.Contains("SAHARA")) TechAuditEdlCount++;
            else if (p.Contains("SPD") || p.Contains("FDL")) TechAuditSpdCount++;
            else if (p.Contains("APPLE")) TechAuditAppleCount++;
            else if (p.Contains("FASTBOOT")) TechAuditFastbootCount++;

            if (SelectedTechnicianRecord == null)
            {
                SelectedTechnicianRecord = record;
            }

            if (AutoScroll)
            {
                RequestTechAuditScrollToBottom?.Invoke();
            }
        });
    }

    private bool FilterTechnicianAuditPredicate(object obj)
    {
        if (obj is not TechnicianAuditRecord record) return false;

        // 0. Response capture toggle: if disabled, hide responses
        if (!IsCaptureDeviceResponsesEnabled && record.IsResponse)
        {
            return false;
        }

        // 1. Direction Filter (ALL, COMMANDS, RESPONSES)
        if (TechAuditDirectionFilter == "COMMANDS" && record.IsResponse) return false;
        if (TechAuditDirectionFilter == "RESPONSES" && !record.IsResponse) return false;

        // 2. Protocol Chip Filter
        if (TechAuditSelectedProtocol != "ALL")
        {
            string p = record.Protocol.ToUpperInvariant();
            bool matchesProtocol = TechAuditSelectedProtocol switch
            {
                "ADB" => p.Contains("ADB") || p.Contains("SHELL"),
                "AT" => p.Contains("AT"),
                "MTK" => p.Contains("MTK"),
                "EDL" => p.Contains("EDL") || p.Contains("QCOM") || p.Contains("FIREHOSE") || p.Contains("SAHARA"),
                "SPD" => p.Contains("SPD") || p.Contains("FDL"),
                "APPLE" => p.Contains("APPLE"),
                "FASTBOOT" => p.Contains("FASTBOOT"),
                _ => true
            };
            if (!matchesProtocol) return false;
        }

        // 3. Search Text
        if (!string.IsNullOrWhiteSpace(TechAuditSearchText))
        {
            string q = TechAuditSearchText.Trim().ToLowerInvariant();
            bool matchesSearch =
                record.PureCommand.ToLowerInvariant().Contains(q) ||
                record.RawCommand.ToLowerInvariant().Contains(q) ||
                (record.DeviceResponse != null && record.DeviceResponse.ToLowerInvariant().Contains(q)) ||
                (record.RelatedCommandText != null && record.RelatedCommandText.ToLowerInvariant().Contains(q)) ||
                record.TargetDeviceOrPort.ToLowerInvariant().Contains(q) ||
                record.TechnicianTool.ToLowerInvariant().Contains(q) ||
                record.Protocol.ToLowerInvariant().Contains(q) ||
                record.Mode.ToLowerInvariant().Contains(q) ||
                record.Direction.ToLowerInvariant().Contains(q) ||
                record.Sha256Hash.ToLowerInvariant().Contains(q);

            if (!matchesSearch) return false;
        }

        return true;
    }

    private void ExportTechnicianAuditRecords()
    {
        try
        {
            var visibleRecords = FilteredTechnicianAuditRecords.Cast<TechnicianAuditRecord>().ToList();
            if (visibleRecords.Count == 0)
            {
                MessageBox.Show("لا توجد سجلات مطابقة للتصدير حالياً.", "تصدير أوامر وردود الهاتف", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Title = "تصدير سجل أوامر وردود هاتف العميل",
                FileName = $"Technician_Commands_And_Replies_{DateTime.Now:yyyyMMdd_HHmmss}",
                Filter = "Clean Commands & Replies (*.txt)|*.txt|Forensic JSON (*.json)|*.json|All Files (*.*)|*.*",
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
                    sb.AppendLine("     PHOENIX GSM — TECHNICIAN COMMANDS & CLIENT PHONE REPLIES REPORT            ");
                    sb.AppendLine($" Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss} | Total Interceptions: {visibleRecords.Count}");
                    sb.AppendLine("================================================================================");
                    sb.AppendLine();

                    foreach (var r in visibleRecords)
                    {
                        sb.AppendLine($"[{r.TimeFormatted}] [{r.Protocol}] [{r.Mode}] [{r.Direction}] [{r.TechnicianTool}:{r.TechnicianProcessId}] [{r.TargetDeviceOrPort}]");
                        string sym = r.IsResponse ? "<<" : ">>";
                        string label = r.IsResponse ? "PHONE REPLY" : "COMMAND    ";
                        sb.AppendLine($"  {sym} {label}: {r.PureCommand}");
                        if (!string.IsNullOrEmpty(r.DeviceResponse))
                        {
                            sb.AppendLine($"  << PHONE REPLY: {r.DeviceResponse}");
                        }
                        sb.AppendLine($"  >> SHA256     : {r.Sha256Hash}");
                        sb.AppendLine(new string('-', 80));
                    }

                    File.WriteAllText(dialog.FileName, sb.ToString(), Encoding.UTF8);
                }

                MessageBox.Show($"تم تصدير {visibleRecords.Count} سجلاً بنجاح إلى:\n{dialog.FileName}", "اكتمل التصدير", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"فشل التصدير: {ex.Message}", "خطأ", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}
