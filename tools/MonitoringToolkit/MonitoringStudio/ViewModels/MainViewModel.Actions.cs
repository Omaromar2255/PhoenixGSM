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

    private void ExportLogs()
    {
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

        if (SelectedCategory == EventSourceCategory.PhoneCommands)
        {
            var phoneChoice = MessageBox.Show(
                "أنت حالياً في تبويب أوامر الهاتف (Phone Cmds).\n\n" +
                "- اختر 'Yes' لتصدير الأوامر المنظمة (نوع الأمر + الأمر من بداية السطر + رد الهاتف إن كان مفعلاً).\n" +
                "- اختر 'No' لتصدير السجل الكامل بملف JSON.\n" +
                "- اختر 'Cancel' للإلغاء.",
                "خيارات تصدير أوامر الهاتف",
                MessageBoxButton.YesNoCancel,
                MessageBoxImage.Question);

            if (phoneChoice == MessageBoxResult.Yes)
            {
                ExportPurePhoneCommandsOnly();
                return;
            }
            if (phoneChoice == MessageBoxResult.Cancel)
            {
                return;
            }
        }

        int totalCount = Events.Count;
        int excludedCount = totalCount - visibleEvents.Count;

        string exclusionMsg = excludedCount > 0 
            ? $"\n\nملاحظة: سيتم استثناء وتخطي {excludedCount} سجلاً مستبعداً ومخفياً بناءً على فلاتر الاستثناء المحددة."
            : "";

        var resType = MessageBox.Show(
            $"هل تريد تصدير الأوامر المنظمة (ملف نصي TXT) أم السجلات الكاملة (ملف JSON)؟{exclusionMsg}\n\n- اختر 'Yes' لتصدير الأوامر بشكل منظم (نوع الأمر -> الأمر من بداية السطر -> رد الهاتف).\n- اختر 'No' لتصدير السجلات كاملة (ملف JSON مفصل).\n- اختر 'Cancel' للإلغاء.",
            "خيارات التصدير المنظم",
            MessageBoxButton.YesNoCancel,
            MessageBoxImage.Question);

        if (resType == MessageBoxResult.Cancel)
            return;

        var reportDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "PhoenixGSM", "Reports");
        Directory.CreateDirectory(reportDir);

        var timeStr = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
        string filePath;

        if (resType == MessageBoxResult.Yes)
        {
            filePath = Path.Combine(reportDir, $"commands_export_{timeStr}.txt");
            bool includeReplies = IsCaptureDeviceResponsesEnabled ||
                                  visibleEvents.Any(IsPhoneDeviceResponse);

            string structuredBody = BuildStructuredCommandsExportText(
                visibleEvents,
                includeDeviceResponses: includeReplies,
                out int exportedCmdCount);

            var sb = new StringBuilder();
            sb.AppendLine("=== سجل الأوامر المنظم (Structured Phone Commands Log) ===");
            sb.AppendLine($"تاريخ التصدير: {DateTime.Now}");
            sb.AppendLine($"إجمالي الأوامر الصافية المصدرة: {exportedCmdCount}");
            sb.AppendLine($"حالة تضمين رد الهاتف: {(includeReplies ? "مفعّل (ON)" : "معطّل (OFF)")}");
            sb.AppendLine(new string('=', 60));
            sb.AppendLine();
            sb.Append(structuredBody);

            File.WriteAllText(filePath, sb.ToString(), Encoding.UTF8);
        }
        else
        {
            filePath = Path.Combine(reportDir, $"gui_export_{timeStr}.json");
            var json = JsonSerializer.Serialize(visibleEvents, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(filePath, json, Encoding.UTF8);
        }

        string exportSummary = $"تم تصدير السجلات بشكل منظم بنجاح إلى:\n{filePath}\n\nهل تريد فتح الملف الآن؟";

        var res = MessageBox.Show(
            exportSummary,
            "اكتمل التصدير بنجاح",
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
