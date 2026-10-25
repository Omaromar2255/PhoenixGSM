using System;
using System.IO;
using System.Windows;
using System.Windows.Input;
using Microsoft.Win32;
using PhoenixOmniTrace.L24_SourceSentinel.Models;

namespace PhoenixOmniTrace.L24_SourceSentinel.UI;

public sealed partial class SourceSentinelViewModel
{
    public ICommand ToggleRamHunterCommand { get; }
    public ICommand CaptureIdleBaselineCommand { get; }
    public ICommand ResetIdleBaselineCommand { get; }
    public ICommand ToggleL24MasterCommand { get; }
    public ICommand StartL24Command { get; }
    public ICommand StopL24Command { get; }
    public ICommand LaunchToolCommand { get; }
    public ICommand AttachProcessCommand { get; }
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
