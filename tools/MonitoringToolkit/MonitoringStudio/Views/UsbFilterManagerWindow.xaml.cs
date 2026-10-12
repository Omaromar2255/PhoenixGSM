using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using Microsoft.Win32;
using PhoenixGSM.UsbMonitor;
using PhoenixGSM.UsbMonitorDiscovery;

namespace PhoenixGSM.MonitoringStudio.Views;

public partial class UsbFilterManagerWindow : Window
{
    private readonly UsbScanner _scanner = new();
    public ObservableCollection<UsbDeviceViewItem> DeviceItems { get; } = [];

    public UsbFilterManagerWindow()
    {
        InitializeComponent();
        GridDevices.ItemsSource = DeviceItems;
        Loaded += (_, _) => RefreshAll();
    }

    public void RefreshAll()
    {
        UpdateEnvironmentStatus();
        RefreshDevicesList();
        UpdateActiveFiltersSummary();
    }

    private void UpdateEnvironmentStatus()
    {
        bool testSigning = DriverManager.IsTestSigningEnabled();
        TxtTestSigning.Text = testSigning ? "🟢 Enabled" : "🔴 Disabled";
        TxtTestSigning.Foreground = testSigning ? System.Windows.Media.Brushes.LightGreen : System.Windows.Media.Brushes.Tomato;

        string svcStatus = DriverManager.GetServiceStatus();
        TxtServiceStatus.Text = svcStatus;
        TxtServiceStatus.Foreground = svcStatus switch
        {
            "Running" => System.Windows.Media.Brushes.LightGreen,
            "Stopped" => System.Windows.Media.Brushes.Orange,
            _ => System.Windows.Media.Brushes.Tomato
        };
    }

    private void RefreshDevicesList()
    {
        DeviceItems.Clear();
        var rawDevices = _scanner.ScanAllDevices();

        foreach (var dev in rawDevices)
        {
            bool attached = IsDeviceFilterAttached(dev.InstanceId);
            DeviceItems.Add(new UsbDeviceViewItem
            {
                DeviceName = string.IsNullOrWhiteSpace(dev.DeviceName) ? $"USB Device [{dev.VidHex}:{dev.PidHex}]" : dev.DeviceName,
                VidPidHex = $"{dev.VidHex}:{dev.PidHex}",
                Driver = string.IsNullOrWhiteSpace(dev.Driver) ? "winusb" : dev.Driver,
                InstanceId = dev.InstanceId,
                IsAttached = attached
            });
        }
    }

    private static bool IsDeviceFilterAttached(string? instanceId)
    {
        if (string.IsNullOrWhiteSpace(instanceId)) return false;
        try
        {
            string regPath = @"SYSTEM\CurrentControlSet\Enum\" + instanceId.TrimStart('\\');
            using var key = Registry.LocalMachine.OpenSubKey(regPath, false);
            if (key == null) return false;

            return CheckFilterValue(key.GetValue("LowerFilters")) || CheckFilterValue(key.GetValue("UpperFilters"));
        }
        catch
        {
            return false;
        }
    }

    private static bool CheckFilterValue(object? val)
    {
        if (val is string[] arr)
        {
            return arr.Any(x => x.Equals(DriverManager.ServiceName, StringComparison.OrdinalIgnoreCase));
        }
        if (val is string s)
        {
            return s.Equals(DriverManager.ServiceName, StringComparison.OrdinalIgnoreCase);
        }
        return false;
    }

    private void UpdateActiveFiltersSummary()
    {
        var active = DriverManager.GetActiveFilterAttachments();
        if (active.Count == 0)
        {
            TxtActiveFilters.Text = "لا توجد فلاتر نشطة حالياً في النظام.";
            TxtActiveFilters.Foreground = System.Windows.Media.Brushes.Gray;
        }
        else
        {
            TxtActiveFilters.Text = string.Join("\n", active);
            TxtActiveFilters.Foreground = System.Windows.Media.Brushes.LightGreen;
        }
    }

    private void BtnRefreshDevices_Click(object sender, RoutedEventArgs e)
    {
        RefreshAll();
    }

    private void BtnAttachDevice_Click(object sender, RoutedEventArgs e)
    {
        if (GridDevices.SelectedItem is not UsbDeviceViewItem selected)
        {
            MessageBox.Show("يرجى اختيار جهاز من الجدول أولاً.", "تنبيه", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (string.IsNullOrWhiteSpace(selected.InstanceId))
        {
            MessageBox.Show("معرّف الجهاز (Instance ID) غير متوفر لهذا الجهاز.", "تنبيه", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        // Smart Guidance for Virtual COM Ports
        if (selected.DeviceName.Contains("(COM", StringComparison.OrdinalIgnoreCase) || 
            selected.Driver.Equals("usbser", StringComparison.OrdinalIgnoreCase) ||
            selected.InstanceId.Contains("DIAGSERD", StringComparison.OrdinalIgnoreCase))
        {
            var choice = MessageBox.Show(
                "تنبيه ذكي لمنافذ السيريال (COM Ports):\n\n" +
                "هذا الجهاز هو منفذ سيريال فرعي (Virtual COM Port).\n" +
                "💡 لمراقبته بأمان تام وسرعة، يوصى بالاعتماد على أداة Serial Sniffer المدمجة في الواجهة (مستوى User-Mode 100%).\n" +
                "أو إذا كنت تريد حزم الـ USB الأصلية (Raw Packets)، يفضل ربط الفلتر بجهاز الـ USB الأب (Composite Device).\n\n" +
                "هل ترغب بالاستمرار في ربط الفلتر بهذا المنفذ؟",
                "توجيه لمنافذ السيريال",
                MessageBoxButton.YesNo,
                MessageBoxImage.Information);

            if (choice != MessageBoxResult.Yes) return;
        }

        bool isSerialOrModem = selected.DeviceName.Contains("(COM", StringComparison.OrdinalIgnoreCase) || 
                               selected.DeviceName.Contains("Modem", StringComparison.OrdinalIgnoreCase) ||
                               selected.DeviceName.Contains("PC UI", StringComparison.OrdinalIgnoreCase) ||
                               selected.DeviceName.Contains("Serial", StringComparison.OrdinalIgnoreCase) ||
                               selected.Driver.Contains("modem", StringComparison.OrdinalIgnoreCase) ||
                               selected.Driver.Contains("usbser", StringComparison.OrdinalIgnoreCase) ||
                               selected.Driver.Contains("ser", StringComparison.OrdinalIgnoreCase) ||
                               selected.InstanceId.Contains("MODEM", StringComparison.OrdinalIgnoreCase) ||
                               selected.InstanceId.Contains("DIAG", StringComparison.OrdinalIgnoreCase) ||
                               selected.InstanceId.Contains("PORTS", StringComparison.OrdinalIgnoreCase);

        bool ok = isSerialOrModem 
            ? DriverManager.AttachDeviceUpperFilter(selected.InstanceId, restartDevice: true)
            : DriverManager.AttachDeviceLowerFilter(selected.InstanceId, restartDevice: true);

        if (ok)
        {
            string filterType = isSerialOrModem ? "UpperFilter (AT/Serial/Modem)" : "LowerFilter (USB/WinUSB)";
            MessageBox.Show($"تم ربط الفلتر [{filterType}] بالجهاز بنجاح وإعادة تشغيل تعريفه:\n{selected.DeviceName}\n({selected.InstanceId})", "نجاح", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        RefreshAll();
    }

    private void BtnDetachDevice_Click(object sender, RoutedEventArgs e)
    {
        if (GridDevices.SelectedItem is not UsbDeviceViewItem selected)
        {
            MessageBox.Show("يرجى اختيار جهاز من الجدول أولاً.", "تنبيه", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (string.IsNullOrWhiteSpace(selected.InstanceId)) return;

        DriverManager.DetachDeviceUpperFilter(selected.InstanceId, restartDevice: false);
        bool ok = DriverManager.DetachDeviceLowerFilter(selected.InstanceId, restartDevice: true);
        if (ok)
        {
            MessageBox.Show($"تم إلغاء ربط الفلتر من الجهاز:\n{selected.DeviceName}", "نجاح", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        RefreshAll();
    }

    private void BtnRestartDevice_Click(object sender, RoutedEventArgs e)
    {
        if (GridDevices.SelectedItem is not UsbDeviceViewItem selected || string.IsNullOrWhiteSpace(selected.InstanceId))
        {
            MessageBox.Show("يرجى اختيار جهاز من الجدول لإعادة تشغيل تعريفه.", "تنبيه", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        DriverManager.RestartDevice(selected.InstanceId);
        RefreshAll();
    }

    private void BtnAttachWinUsb_Click(object sender, RoutedEventArgs e)
    {
        DriverManager.ConfigureLowerFilter("winusb");
        RefreshAll();
    }

    private void BtnDetachWinUsb_Click(object sender, RoutedEventArgs e)
    {
        DriverManager.RemoveLowerFilter("winusb");
        RefreshAll();
    }

    private void BtnAttachPorts_Click(object sender, RoutedEventArgs e)
    {
        DriverManager.ConfigureUpperFilter("ports", restartDevices: true);
        RefreshAll();
    }

    private void BtnDetachPorts_Click(object sender, RoutedEventArgs e)
    {
        DriverManager.RemoveUpperFilter("ports", restartDevices: true);
        DriverManager.RemoveLowerFilter("ports");
        RefreshAll();
    }

    private void BtnAttachModem_Click(object sender, RoutedEventArgs e)
    {
        DriverManager.ConfigureUpperFilter("modem", restartDevices: true);
        RefreshAll();
    }

    private void BtnDetachModem_Click(object sender, RoutedEventArgs e)
    {
        DriverManager.RemoveUpperFilter("modem", restartDevices: true);
        DriverManager.RemoveLowerFilter("modem");
        RefreshAll();
    }

    private void BtnAttachModemAndPorts_Click(object sender, RoutedEventArgs e)
    {
        DriverManager.ConfigurePortAndModemFilters(restartDevices: true);
        RefreshAll();
        MessageBox.Show("تم ربط UpperFilter بفئات Modem و COM Ports وإعادة تشغيل الأجهزة النشطة بنجاح.\nالفلتر نشط الآن ويلتقط أوامر AT وحزم المودم مباشرة وبدون تعارض مع أدوات التفليش.", "نجاح", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void BtnDetachModemAndPorts_Click(object sender, RoutedEventArgs e)
    {
        DriverManager.RemovePortAndModemFilters(restartDevices: true);
        RefreshAll();
        MessageBox.Show("تمت إزالة الفلتر عن فئات Modem و COM Ports وإعادة تشغيل الأجهزة النشطة بنجاح.", "نجاح", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void BtnAttachAndroid_Click(object sender, RoutedEventArgs e)
    {
        DriverManager.ConfigureLowerFilter("android");
        RefreshAll();
    }

    private void BtnDetachAndroid_Click(object sender, RoutedEventArgs e)
    {
        DriverManager.RemoveLowerFilter("android");
        RefreshAll();
    }

    private void BtnAttachUsb_Click(object sender, RoutedEventArgs e)
    {
        DriverManager.ConfigureLowerFilter("usb");
        RefreshAll();
    }

    private void BtnDetachUsb_Click(object sender, RoutedEventArgs e)
    {
        DriverManager.RemoveLowerFilter("usb");
        RefreshAll();
    }

    private void BtnAttachCustomGuid_Click(object sender, RoutedEventArgs e)
    {
        string guid = TxtCustomGuid.Text.Trim();
        if (string.IsNullOrWhiteSpace(guid))
        {
            MessageBox.Show("يرجى إدخال Class GUID صحيح.", "تنبيه", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        DriverManager.ConfigureLowerFilter(guid);
        RefreshAll();
    }

    private void BtnDetachCustomGuid_Click(object sender, RoutedEventArgs e)
    {
        string guid = TxtCustomGuid.Text.Trim();
        if (string.IsNullOrWhiteSpace(guid)) return;
        DriverManager.RemoveLowerFilter(guid);
        RefreshAll();
    }

    private void BtnRollback_Click(object sender, RoutedEventArgs e)
    {
        var res = MessageBox.Show(
            "هل أنت متأكد من رغبتك في إزالة جميع فلاتر PhoenixUsbMonitor من جميع الأجهزة وفئات التعريف في النظام؟\n\nسيتم استرجاع النظام بالكامل إلى وضعه الأصلي.",
            "تأكيد الاسترجاع الشامل (System Rollback)",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (res == MessageBoxResult.Yes)
        {
            DriverManager.RestoreStockWindowsConfiguration();
            MessageBox.Show("تم فحص النظام بالكامل، وإزالة جميع ارتباطات الفلتر، وإيقاف الخدمة، واستعادة تعاريف الويندوز الأصلية بنجاح.", "اكتمل الاسترجاع الشامل", MessageBoxButton.OK, MessageBoxImage.Information);
            RefreshAll();
        }
    }

    private void BtnStartService_Click(object sender, RoutedEventArgs e)
    {
        DriverManager.StartService();
        RefreshAll();
    }

    private void BtnStopService_Click(object sender, RoutedEventArgs e)
    {
        DriverManager.StopService();
        RefreshAll();
    }

    private void BtnInstallService_Click(object sender, RoutedEventArgs e)
    {
        DriverManager.InstallService();
        RefreshAll();
    }
}

public class UsbDeviceViewItem
{
    public string DeviceName { get; set; } = "";
    public string VidPidHex { get; set; } = "";
    public string Driver { get; set; } = "";
    public string InstanceId { get; set; } = "";
    public bool IsAttached { get; set; }

    public string FilterStatusText => IsAttached ? "🟢 ATTACHED" : "⚪ READY";
    public string StatusBgColor => IsAttached ? "#1C382F" : "#1A1D2B";
    public string StatusFgColor => IsAttached ? "#00FF9D" : "#8E9AA8";
}
