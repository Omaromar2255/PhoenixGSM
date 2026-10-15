using System;
using System.IO;
using System.Windows;
using System.Windows.Threading;

namespace PhoenixGSM.MonitoringStudio;

public partial class App : Application
{
    private static readonly string LogFile = @"C:\Users\pc5\softwer\PhoenixGSM\gui_debug.log";

    public App()
    {
        AppDomain.CurrentDomain.UnhandledException += (s, e) =>
        {
            File.AppendAllText(LogFile, $"[AppDomain Unhandled] {DateTime.Now}: {e.ExceptionObject}\n");
        };

        DispatcherUnhandledException += (s, e) =>
        {
            try
            {
                File.AppendAllText(LogFile, $"[Dispatcher Unhandled] {DateTime.Now}: {e.Exception}\n");
            }
            catch { }

            // If MainWindow failed during initialization or is null, do not hang silently in RAM
            if (MainWindow == null || !MainWindow.IsLoaded)
            {
                e.Handled = true;
                try
                {
                    MessageBox.Show(
                        $"فشل بدء تشغيل واجهة النظام (PhoenixGSM Studio):\n\n{e.Exception.Message}\n\nيرجى مراجعة سجل الأخطاء في:\n{LogFile}",
                        "PhoenixGSM Studio - خطأ في بدء التشغيل",
                        MessageBoxButton.OK,
                        MessageBoxImage.Error);
                }
                catch { }
                Shutdown(-1);
                return;
            }

            e.Handled = true;
        };
        AppDomain.CurrentDomain.ProcessExit += (_, _) =>
        {
            EnsureStockWindowsConfiguration();
        };
    }

    private PhoenixGSM.OmniTrace.Service.ProcessGuardian? _guardian;

    protected override void OnStartup(StartupEventArgs e)
    {
        File.AppendAllText(LogFile, $"[OnStartup] {DateTime.Now}: Starting up...\n");
        
        try
        {
            _guardian = new PhoenixGSM.OmniTrace.Service.ProcessGuardian();
            _guardian.Activate();
            File.AppendAllText(LogFile, $"[ProcessGuardian] {DateTime.Now}: Shield activated (Protected={_guardian.IsProtected})\n");
        }
        catch (Exception ex)
        {
            File.AppendAllText(LogFile, $"[ProcessGuardian] {DateTime.Now}: Activation exception: {ex.Message}\n");
        }

        // Do NOT automatically attach kernel filters to Modem or Ports.
        // Instead, ensure Windows starts in clean stock state without lingering filters from prior crashes.
        System.Threading.Tasks.Task.Run(() =>
        {
            try
            {
                if (PhoenixGSM.UsbMonitor.DriverManager.IsPortAndModemFilterConfigured())
                {
                    File.AppendAllText(LogFile, $"[OnStartup] {DateTime.Now}: Detected leftover filter on Modem/Ports. Reverting to stock Windows state...\n");
                    EnsureStockWindowsConfiguration();
                }
            }
            catch (Exception ex)
            {
                File.AppendAllText(LogFile, $"[OnStartup] {DateTime.Now}: Cleanup check exception: {ex.Message}\n");
            }
        });

        base.OnStartup(e);
        File.AppendAllText(LogFile, $"[OnStartup] {DateTime.Now}: Startup completed successfully.\n");
    }

    protected override void OnExit(ExitEventArgs e)
    {
        try
        {
            _guardian?.Dispose();
            _guardian = null;

            // Guaranteed restoration of 100% stock Windows drivers upon exit
            EnsureStockWindowsConfiguration();
        }
        catch { }
        base.OnExit(e);
    }

    public static void EnsureStockWindowsConfiguration()
    {
        try
        {
            PhoenixGSM.UsbMonitor.DriverManager.RemovePortAndModemFilters(restartDevices: true);
            PhoenixGSM.UsbMonitor.DriverManager.RestoreStockWindowsConfiguration();
        }
        catch { }
    }
}
