using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace PhoenixGSM.MonitoringStudio.Services;

public partial class MonitoringEngine
{
    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern IntPtr FindWindow(string? lpClassName, string? lpWindowName);

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern IntPtr FindWindowEx(IntPtr hwndParent, IntPtr hwndChildAfter, string? lpszClass, string? lpszWindow);

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    private static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    private static extern bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

    private const uint WM_COMMAND = 0x0111;
    private const uint BM_CLICK = 0x00F5;
    private const int IDIGNORE = 5;

    /// <summary>
    /// Automatically detects and clicks "Ignore" (IDIGNORE = 5) on any "MinGW Runtime Assertion" popup
    /// (such as adb_winusb_interface.cpp Line 42: INVALID_HANDLE_VALUE == usb_device_handle_) within < 100ms.
    /// </summary>
    private static async Task AutoDismissMinGwAssertionLoopAsync(CancellationToken token)
    {
        string[] assertionTitles =
        [
            "MinGW Runtime Assertion",
            "Microsoft Visual C++ Runtime Library"
        ];

        string[] ignoreButtonLabels =
        [
            "&Ignore",
            "Ignore",
            "تجاهل"
        ];

        while (!token.IsCancellationRequested)
        {
            try
            {
                foreach (string title in assertionTitles)
                {
                    IntPtr hDlg = FindWindow("#32770", title);
                    if (hDlg == IntPtr.Zero)
                    {
                        hDlg = FindWindow(null, title);
                    }

                    if (hDlg != IntPtr.Zero)
                    {
                        foreach (string btnText in ignoreButtonLabels)
                        {
                            IntPtr hBtn = FindWindowEx(hDlg, IntPtr.Zero, "Button", btnText);
                            if (hBtn != IntPtr.Zero)
                            {
                                SendMessage(hBtn, BM_CLICK, IntPtr.Zero, IntPtr.Zero);
                                break;
                            }
                        }

                        // Standard Win32 MessageBox IDIGNORE command (ID = 5)
                        PostMessage(hDlg, WM_COMMAND, (IntPtr)IDIGNORE, IntPtr.Zero);
                    }
                }
            }
            catch { }

            await Task.Delay(120, token).ConfigureAwait(false);
        }
    }
}
