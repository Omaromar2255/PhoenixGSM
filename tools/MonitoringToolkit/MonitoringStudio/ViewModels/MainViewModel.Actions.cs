using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using PhoenixGSM.MonitoringStudio.Models;
using PhoenixGSM.OmniTrace.Commands;

namespace PhoenixGSM.MonitoringStudio.ViewModels;

public partial class MainViewModel
{
    private void ToggleMonitoring()
    {
        if (IsMonitoring)
        {
            _engine.Stop();
            if (IsFilterMonitoringEnabled)
            {
                SetFilterMonitoring(false);
            }
            IsMonitoring = false;
        }
        else
        {
            _engine.Start();
            IsMonitoring = true;
        }
    }

    public void ToggleFilterMonitoring()
    {
        SetFilterMonitoring(!IsFilterMonitoringEnabled);
    }

    public void SetFilterMonitoring(bool enable)
    {
        try
        {
            if (enable)
            {
                bool ok = PhoenixGSM.UsbMonitor.DriverManager.ConfigurePortAndModemFilters(restartDevices: true);
                IsFilterMonitoringEnabled = ok;

                _dispatcher.Invoke(() =>
                {
                    Events.Add(new LiveEventItem
                    {
                        Category = EventSourceCategory.SerialPort,
                        SourceTag = "FILTER",
                        Direction = "SYS",
                        EndpointOrTarget = "MODEM/PORTS",
                        Protocol = "KERNEL-FILTER",
                        Command = "FILTER ACTIVATED",
                        Summary = "🟢 تم تفعيل مراقبة الفلتر لمنافذ المودم والـ COM بنجاح. الفلتر نشط الآن لاعتراض الأوامر.",
                        AdditionalDetails = "UpperFilters registered on Modem ({4D36E96D-E325-11CE-BFC1-08002BE10318}) and Ports ({4D36E978-E325-11CE-BFC1-08002BE10318}). Connected devices restarted."
                    });
                    TotalEventsCount++;
                });

                InitializeSystemStatus();
            }
            else
            {
                PhoenixGSM.UsbMonitor.DriverManager.RemovePortAndModemFilters(restartDevices: true);
                PhoenixGSM.UsbMonitor.DriverManager.RestoreStockWindowsConfiguration();
                IsFilterMonitoringEnabled = false;

                _dispatcher.Invoke(() =>
                {
                    Events.Add(new LiveEventItem
                    {
                        Category = EventSourceCategory.SerialPort,
                        SourceTag = "FILTER",
                        Direction = "SYS",
                        EndpointOrTarget = "MODEM/PORTS",
                        Protocol = "STOCK-MODE",
                        Command = "FILTER DEACTIVATED",
                        Summary = "⚪ تم إيقاف الفلتر واستعادة وضع ويندوز الطبيعي بالكامل (Stock Native Drivers). تم تنظيف الريجستري وإعادة تشغيل الأجهزة.",
                        AdditionalDetails = "Removed UpperFilters & LowerFilters from Modem and Ports. Connected devices restarted to reload original vendor drivers. Zero conflict with external GSM tools."
                    });
                    TotalEventsCount++;
                });

                InitializeSystemStatus();
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"خطأ في ضبط الفلتر: {ex.Message}", "تنبيه الفلتر", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async Task SimulateTrafficAsync()
    {
        await _engine.SimulateTrafficAsync();
    }

    private async Task QueryPhoneLiveAsync()
    {
        var ports = _engine.GetAvailableComPorts();
        if (ports.Length > 0)
        {
            string targetPort = ports[0];
            string targetDesc = _engine.GetPortDescription(targetPort) ?? "Serial Port";
            foreach (var p in ports)
            {
                var d = _engine.GetPortDescription(p) ?? "";
                if (d.Contains("modem", StringComparison.OrdinalIgnoreCase) ||
                    d.Contains("samsung", StringComparison.OrdinalIgnoreCase) ||
                    d.Contains("qualcomm", StringComparison.OrdinalIgnoreCase) ||
                    d.Contains("mediatek", StringComparison.OrdinalIgnoreCase))
                {
                    targetPort = p;
                    targetDesc = d;
                    break;
                }
            }

            _dispatcher.Invoke(() =>
            {
                Events.Add(new LiveEventItem
                {
                    Category = EventSourceCategory.SerialPort,
                    SourceTag = "SERIAL",
                    Direction = "SYS",
                    EndpointOrTarget = targetPort,
                    Protocol = "SERIAL-AT",
                    Command = "PHONE INTERROGATION",
                    Summary = $"Initiating AT interrogation on {targetPort} ({targetDesc})...",
                    AdditionalDetails = $"Selected Port: {targetPort}\nDescription: {targetDesc}\nAvailable Ports: {string.Join(", ", ports)}"
                });
                SerialCount++;
                TotalEventsCount++;
            });

            string[] atCommands =
            [
                "AT\r",
                "ATI\r",
                "AT+CGMI\r",
                "AT+CGMM\r",
                "AT+CGMR\r",
                "AT+CGSN\r",
                "AT+DEVINFO\r",
                "AT+CSQ\r"
            ];

            bool anySent = false;
            string lastError = "";

            foreach (var cmd in atCommands)
            {
                bool sent = _engine.SendAtCommandToPort(targetPort, cmd, out string err);
                if (!sent)
                {
                    sent = _engine.SendAtCommandToAnyPort(cmd, out err);
                }
                if (sent)
                {
                    anySent = true;
                }
                else
                {
                    lastError = err;
                }
                await Task.Delay(300);
            }

            if (!anySent)
            {
                _dispatcher.Invoke(() =>
                {
                    Events.Add(new LiveEventItem
                    {
                        Category = EventSourceCategory.SerialPort,
                        SourceTag = "SERIAL",
                        Direction = "SYS",
                        EndpointOrTarget = targetPort,
                        Protocol = "SERIAL-AT",
                        Command = "QUERY FAILED",
                        Summary = $"Failed to send AT commands to {targetPort}: {lastError}",
                        AdditionalDetails = $"Error details: {lastError}\nPort: {targetPort} ({targetDesc})\nTip: Ensure no other GSM tool is locking {targetPort} exclusively."
                    });
                    SerialCount++;
                    TotalEventsCount++;
                });
            }
        }
        else
        {
            _dispatcher.Invoke(() =>
            {
                Events.Add(new LiveEventItem
                {
                    Category = EventSourceCategory.SerialPort,
                    SourceTag = "SERIAL",
                    Direction = "SYS",
                    EndpointOrTarget = "SCAN",
                    Protocol = "SERIAL-AT",
                    Command = "PORT QUERY",
                    Summary = "No active COM/Modem port detected. Connect device in AT Modem / USB DIAG mode.",
                    AdditionalDetails = "Plug in phone with USB Debugging / Modem mode enabled (e.g. *#0808# -> DM+MODEM+ADB)."
                });
                SerialCount++;
                TotalEventsCount++;
            });
        }
    }

    private void OpenFilterManager()
    {
        try
        {
            var win = new Views.UsbFilterManagerWindow
            {
                Owner = Application.Current?.MainWindow
            };
            win.ShowDialog();
            InitializeSystemStatus();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Failed to open USB Filter Manager: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    /// <summary>
    /// Builds a structured, deduplicated list of (CommandType, PureCommand, PhoneResponse, Timestamp)
    /// from a list of LiveEventItems.
    /// Format guarantees:
    /// 1. Command Type (e.g. ADB-SHELL, ADB-AT-RIL, MODEM-AT, MTK-BROM, ADB-PUSH)
    /// 2. Pure Command starting cleanly at the beginning of the line
    /// 3. Phone Response (paired immediately under the command if enabled or present)
    /// </summary>
    public static string BuildStructuredCommandsExportText(
        IReadOnlyList<LiveEventItem> sourceEvents,
        bool includeDeviceResponses,
        out int exportedCommandsCount)
    {
        int count = 0;
        var sb = new StringBuilder();

        string? lastCommandText = null;
        string? lastCommandType = null;
        DateTime lastCommandTime = DateTime.MinValue;
        var currentResponses = new List<string>();

        void FlushPendingCommand()
        {
            if (string.IsNullOrWhiteSpace(lastCommandText)) return;

            sb.AppendLine($"[{lastCommandType}]");
            sb.AppendLine(lastCommandText);

            if (includeDeviceResponses && currentResponses.Count > 0)
            {
                string combinedReply = string.Join(" | ", currentResponses.Distinct());
                sb.AppendLine($"رد الهاتف: {combinedReply}");
            }

            sb.AppendLine(new string('-', 45));
            count++;

            lastCommandText = null;
            lastCommandType = null;
            currentResponses.Clear();
        }

        foreach (var ev in sourceEvents)
        {
            if (ev == null) continue;

            // 1. Check if this event is a phone-directed command
            string? pureCmd = ExtractPurePhoneCommand(ev);
            if (!string.IsNullOrWhiteSpace(pureCmd))
            {
                string cmdType = PhoneCommandClassifier.ClassifyCommandTypeTag(
                    ev.Command, ev.Protocol, ev.Category.ToString(), ev.Summary);

                // Deduplicate identical consecutive commands emitted within 250ms (e.g. KernelDriver + OmniTraceBus)
                if (lastCommandText != null &&
                     string.Equals(lastCommandText, pureCmd, StringComparison.Ordinal) &&
                    Math.Abs((ev.Timestamp - lastCommandTime).TotalMilliseconds) < 250)
                {
                    continue;
                }

                // Flush previous command along with any collected phone responses
                FlushPendingCommand();

                lastCommandType = cmdType;
                lastCommandText = pureCmd;
                lastCommandTime = ev.Timestamp;
                continue;
            }

            // 2. Check if this event is a phone response (attached to the current command)
            if (includeDeviceResponses && lastCommandText != null)
            {
                string? pureResp = ExtractPurePhoneResponse(ev);
                if (!string.IsNullOrWhiteSpace(pureResp))
                {
                    currentResponses.Add(pureResp);
                }
            }
        }

        // Flush final command
        FlushPendingCommand();

        exportedCommandsCount = count;
        return sb.ToString();
    }

    /// <summary>
    /// Builds a comprehensive, human-readable forensic text log of all events.
    /// Includes timestamps, categories, source tags, direction, target/port, protocol, command, summary, payloads, and technical details.
    /// </summary>
    public static string BuildFullEventsExportText(
        IReadOnlyList<LiveEventItem> sourceEvents,
        string categoryName,
        bool includeResponses)
    {
        var sb = new StringBuilder();
        sb.AppendLine("================================================================================");
        sb.AppendLine("         PHOENIX GSM MONITORING STUDIO — COMPREHENSIVE FORENSIC LOG             ");
        sb.AppendLine("================================================================================");
        sb.AppendLine($" التاريخ / Export Date      : {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($" إجمالي السجلات / Records    : {sourceEvents.Count}");
        sb.AppendLine($" التصنيف المحدد / Category   : {categoryName}");
        sb.AppendLine($" تضمين الردود / Phone Replies: {(includeResponses ? "مفعّل (Enabled)" : "معطّل (Disabled)")}");
        sb.AppendLine("================================================================================");
        sb.AppendLine();

        for (int i = 0; i < sourceEvents.Count; i++)
        {
            var ev = sourceEvents[i];
            if (ev == null) continue;

            sb.AppendLine($"#{i + 1:D5} [{ev.TimeFormatted}] [{ev.Category}] [{ev.SourceTag}] [{ev.Direction}] [{ev.Protocol}]");
            sb.AppendLine($"  Target / Port : {ev.EndpointOrTarget}");
            sb.AppendLine($"  Command       : {ev.Command}");
            if (!string.IsNullOrWhiteSpace(ev.Summary))
            {
                sb.AppendLine($"  Summary       : {ev.Summary}");
            }
            if (!string.IsNullOrWhiteSpace(ev.PayloadAscii))
            {
                sb.AppendLine($"  ASCII Payload : {ev.PayloadAscii}");
            }
            if (!string.IsNullOrWhiteSpace(ev.PayloadHex) && ev.PayloadHex != "(Empty Payload)")
            {
                sb.AppendLine($"  HEX Payload   : {ev.PayloadHex}");
            }
            if (!string.IsNullOrWhiteSpace(ev.AdditionalDetails))
            {
                sb.AppendLine($"  Details       : {ev.AdditionalDetails.Replace("\n", "\n                  ")}");
            }
            sb.AppendLine(new string('-', 80));
        }

        return sb.ToString();
    }

    /// <summary>
    /// Builds a comma-separated values (CSV) representation of all events, compatible with Excel.
    /// </summary>
    public static string BuildEventsCsv(IReadOnlyList<LiveEventItem> sourceEvents)
    {
        var sb = new StringBuilder();
        sb.AppendLine("ID,Time,Category,SourceTag,Direction,EndpointOrTarget,Protocol,Command,Summary,AdditionalDetails,PayloadHex");

        for (int i = 0; i < sourceEvents.Count; i++)
        {
            var ev = sourceEvents[i];
            if (ev == null) continue;

            sb.AppendLine(string.Join(",",
                EscapeCsv(ev.Id.ToString()),
                EscapeCsv(ev.TimeFormatted),
                EscapeCsv(ev.Category.ToString()),
                EscapeCsv(ev.SourceTag),
                EscapeCsv(ev.Direction),
                EscapeCsv(ev.EndpointOrTarget),
                EscapeCsv(ev.Protocol),
                EscapeCsv(ev.Command),
                EscapeCsv(ev.Summary),
                EscapeCsv(ev.AdditionalDetails),
                EscapeCsv(ev.PayloadHex)
            ));
        }

        return sb.ToString();
    }

    private static string EscapeCsv(string? field)
    {
        if (string.IsNullOrEmpty(field)) return "\"\"";
        string clean = field.Replace("\"", "\"\"").Replace("\r", " ").Replace("\n", " ");
        return $"\"{clean}\"";
    }

    private void ExportLogs()
    {
        // 1. If currently in the dedicated Technician-to-Phone Audit tab, export its records
        if (IsTechnicianAuditViewActive)
        {
            ExportTechnicianAuditRecords();
            return;
        }

        // 2. If currently in the dedicated Tool-Source Interception tab, export its records
        if (IsToolSourceInterceptionViewActive)
        {
            ExportToolSourceRecords();
            return;
        }

        // 3. We are in the General Forensic Stream
        var visibleEvents = FilteredEvents.Cast<LiveEventItem>().ToList();
        if (visibleEvents.Count == 0)
        {
            MessageBox.Show(
                "لا توجد سجلات مطابقة للعرض حالياً للتصدير.\n(قد تكون جميع السجلات مستثناة ومخفية أو لا تطابق البحث المحدد).",
                "تصدير السجلات",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            return;
        }

        string timeStr = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        string desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        bool isPhoneCommandsCategory = (SelectedCategory == EventSourceCategory.PhoneCommands);

        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            InitialDirectory = Directory.Exists(desktopPath) ? desktopPath : string.Empty,
            DefaultExt = ".txt"
        };

        if (isPhoneCommandsCategory)
        {
            dialog.Title = "تصدير أوامر الهاتف المنظمة (Phone Commands Export)";
            dialog.FileName = $"Phone_Commands_Structured_{timeStr}";
            dialog.Filter = "أوامر الهاتف الصافية المنظمة (*.txt)|*.txt|سجل جنائي للأوامر مفصل (*.json)|*.json|جدول بيانات إكسل (*.csv)|*.csv|جميع الملفات (*.*)|*.*";
        }
        else
        {
            string categoryLabel = SelectedCategory == EventSourceCategory.All ? "All_Logs" : $"{SelectedCategory}_Logs";
            string titleArabic = SelectedCategory == EventSourceCategory.All 
                ? "تصدير السجلات الشاملة (All Forensic Events)" 
                : $"تصدير سجلات التصنيف ({SelectedCategory})";

            dialog.Title = titleArabic;
            dialog.FileName = $"PhoenixGSM_{categoryLabel}_{timeStr}";
            dialog.Filter = "سجل نصي شامل لكافة الأحداث والسجلات (*.txt)|*.txt|جدول بيانات إكسل (*.csv)|*.csv|ملف بيانات جنائي كامل مفصل (*.json)|*.json|أوامر الهاتف المنظمة فقط (*.txt)|*.txt|جميع الملفات (*.*)|*.*";
        }

        if (dialog.ShowDialog() != true)
            return;

        string targetFile = dialog.FileName;
        bool includeReplies = IsCaptureDeviceResponsesEnabled || visibleEvents.Any(IsPhoneDeviceResponse);

        try
        {
            if (isPhoneCommandsCategory)
            {
                if (targetFile.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
                {
                    string json = JsonSerializer.Serialize(visibleEvents, new JsonSerializerOptions { WriteIndented = true });
                    File.WriteAllText(targetFile, json, Encoding.UTF8);
                }
                else if (targetFile.EndsWith(".csv", StringComparison.OrdinalIgnoreCase))
                {
                    string csv = BuildEventsCsv(visibleEvents);
                    File.WriteAllText(targetFile, csv, Encoding.UTF8);
                }
                else
                {
                    string structuredBody = BuildStructuredCommandsExportText(
                        visibleEvents,
                        includeDeviceResponses: includeReplies,
                        out int exportedCmdCount);

                    var sb = new StringBuilder();
                    sb.AppendLine("=== سجل أوامر الهاتف المنظم (Structured Phone Commands Log) ===");
                    sb.AppendLine($"تاريخ التصدير: {DateTime.Now}");
                    sb.AppendLine($"إجمالي الأوامر الصافية المصدرة: {exportedCmdCount}");
                    sb.AppendLine($"حالة تضمين رد الهاتف: {(includeReplies ? "مفعّل (ON)" : "معطّل (OFF)")}");
                    sb.AppendLine(new string('=', 60));
                    sb.AppendLine();
                    sb.Append(structuredBody);

                    File.WriteAllText(targetFile, sb.ToString(), Encoding.UTF8);

                    try
                    {
                        Clipboard.SetText(structuredBody);
                    }
                    catch { }
                }
            }
            else
            {
                // In "All" tab (الكل) or sensor categories
                if (dialog.FilterIndex == 4)
                {
                    // User explicitly chose "أوامر الهاتف المنظمة فقط (*.txt)"
                    string structuredBody = BuildStructuredCommandsExportText(
                        visibleEvents,
                        includeDeviceResponses: includeReplies,
                        out int exportedCmdCount);

                    var sb = new StringBuilder();
                    sb.AppendLine("=== سجل أوامر الهاتف المنظم (Phone Commands Extracted from All Events) ===");
                    sb.AppendLine($"تاريخ التصدير: {DateTime.Now}");
                    sb.AppendLine($"إجمالي الأوامر المصدرة: {exportedCmdCount}");
                    sb.AppendLine($"حالة تضمين رد الهاتف: {(includeReplies ? "مفعّل (ON)" : "معطّل (OFF)")}");
                    sb.AppendLine(new string('=', 60));
                    sb.AppendLine();
                    sb.Append(structuredBody);

                    File.WriteAllText(targetFile, sb.ToString(), Encoding.UTF8);
                }
                else if (targetFile.EndsWith(".json", StringComparison.OrdinalIgnoreCase) || dialog.FilterIndex == 3)
                {
                    string json = JsonSerializer.Serialize(visibleEvents, new JsonSerializerOptions { WriteIndented = true });
                    File.WriteAllText(targetFile, json, Encoding.UTF8);
                }
                else if (targetFile.EndsWith(".csv", StringComparison.OrdinalIgnoreCase) || dialog.FilterIndex == 2)
                {
                    string csv = BuildEventsCsv(visibleEvents);
                    File.WriteAllText(targetFile, csv, Encoding.UTF8);
                }
                else
                {
                    // Default .txt (FilterIndex 1): Comprehensive forensic text log of ALL events
                    string catDisplay = SelectedCategory == EventSourceCategory.All ? "الكل (All Forensic Events)" : SelectedCategory.ToString();
                    string fullText = BuildFullEventsExportText(visibleEvents, catDisplay, includeReplies);
                    File.WriteAllText(targetFile, fullText, Encoding.UTF8);
                }
            }

            // Save backup in Reports folder
            try
            {
                var reportDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "PhoenixGSM", "Reports");
                Directory.CreateDirectory(reportDir);
                string backupPath = Path.Combine(reportDir, Path.GetFileName(targetFile));
                if (!string.Equals(targetFile, backupPath, StringComparison.OrdinalIgnoreCase))
                {
                    File.Copy(targetFile, backupPath, overwrite: true);
                }
            }
            catch { }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"تعذر إتمام عملية التصدير: {ex.Message}", "خطأ في التصدير", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        string exportSummary = $"✅ تم تصدير {visibleEvents.Count} سجلاً بنجاح إلى:\n{targetFile}\n\nهل تريد فتح الملف الآن؟";

        var res = MessageBox.Show(
            exportSummary,
            "اكتمل التصدير بنجاح",
            MessageBoxButton.YesNo,
            MessageBoxImage.Information);

        if (res == MessageBoxResult.Yes)
        {
            try
            {
                Process.Start(new ProcessStartInfo { FileName = targetFile, UseShellExecute = true });
            }
            catch { }
        }
    }

    /// <summary>
    /// Exports organized phone commands (Command Type -> Command from start of line -> Phone Response if enabled).
    /// Also copies the organized output to Windows Clipboard for instant paste.
    /// </summary>
    public void ExportPurePhoneCommandsOnly()
    {
        string structuredContent = BuildStructuredCommandsExportText(
            Events.ToList(),
            includeDeviceResponses: IsCaptureDeviceResponsesEnabled,
            out int cmdCount);

        if (cmdCount == 0)
        {
            MessageBox.Show(
                "لم يتم التقاط أي أوامر موجهة للهاتف حتى الآن في الجلسة الحالية.\nتأكد من توصيل الهاتف وبدء العملية في الأداة.",
                "تصدير أوامر الهاتف المنظمة",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            return;
        }

        try
        {
            Clipboard.SetText(structuredContent);
        }
        catch { }

        string timeStr = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        string desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        string filePath = Path.Combine(desktopPath, $"phone_commands_structured_{timeStr}.txt");

        try
        {
            File.WriteAllText(filePath, structuredContent, Encoding.UTF8);

            var reportDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "PhoenixGSM", "Reports");
            Directory.CreateDirectory(reportDir);
            File.WriteAllText(Path.Combine(reportDir, $"phone_commands_structured_{timeStr}.txt"), structuredContent, Encoding.UTF8);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"تعذر حفظ الملف: {ex.Message}", "خطأ في التصدير", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        var res = MessageBox.Show(
            $"✅ تم استخراج وتصدير {cmdCount} أمراً منظماً موجهاً للهاتف بنجاح!\n\n" +
            $"📁 مسار الملف: {filePath}\n" +
            $"📋 تم نسخ جميع الأوامر تلقائياً إلى الحافظة (Clipboard).\n\n" +
            $"هل تريد فتح ملف الأوامر الآن؟",
            "اكتمل تصدير أوامر الهاتف المنظمة",
            MessageBoxButton.YesNo,
            MessageBoxImage.Information);

        if (res == MessageBoxResult.Yes)
        {
            try
            {
                Process.Start(new ProcessStartInfo { FileName = filePath, UseShellExecute = true });
            }
            catch { }
        }
    }

    private async Task AnalyzeWithAiAsync()
    {
        string analyzerPath = Path.GetFullPath(Path.Combine(
            AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "..",
            "CommandAnalyzer", "bin", "Debug", "net8.0", "CommandAnalyzer.exe"));

        if (!File.Exists(analyzerPath))
        {
            MessageBox.Show(
                "CommandAnalyzer.exe not found at:\n" + analyzerPath,
                "Command Analyzer", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        try
        {
            await Task.Run(() =>
            {
                var psi = new ProcessStartInfo
                {
                    FileName = analyzerPath,
                    Arguments = "--analyze",
                    UseShellExecute = true,
                    CreateNoWindow = false
                };
                Process.Start(psi);
            });
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Failed to launch analyzer: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}
