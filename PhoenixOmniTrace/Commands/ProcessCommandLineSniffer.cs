using System;
using System.Diagnostics;
using System.Management;
using System.Text;
using System.Text.RegularExpressions;

namespace PhoenixGSM.OmniTrace.Commands;

/// <summary>
/// Event arguments for captured command lines.
/// معلومات الأوامر الملتقطة
/// </summary>
public class CapturedCommandInfo : EventArgs
{
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public string CommandLine { get; set; } = string.Empty;
    public string DecodedArguments { get; set; } = string.Empty;
}

/// <summary>
/// Sniffs process command lines including hidden arguments and decodes PowerShell Base64.
/// مراقب سطر الأوامر للعمليات مع فك تشفير PowerShell
/// </summary>
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public class ProcessCommandLineSniffer : IDisposable
{
    private ManagementEventWatcher? _watcher;
    private bool _isRunning;

    // Event emitted when a command is captured / حدث عند التقاط أمر
    public event EventHandler<CapturedCommandInfo>? OnProcessCommandCaptured;

    public ProcessCommandLineSniffer()
    {
    }

    /// <summary>
    /// Starts the command line sniffer.
    /// بدء المراقبة
    /// </summary>
    public void Start()
    {
        if (_isRunning) return;

        try
        {
            // WMI Query for Process Creation
            // استعلام WMI لإنشاء العمليات
            var query = new WqlEventQuery("SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'");
            _watcher = new ManagementEventWatcher(query);
            _watcher.EventArrived += Watcher_EventArrived;
            _watcher.Start();
            _isRunning = true;
        }
        catch (Exception ex)
        {
            // Fail-open: log and continue / استمرار عند الفشل
            Debug.WriteLine($"[ProcessCommandLineSniffer] Start failed: {ex.Message}");
        }
    }

    private void Watcher_EventArrived(object sender, EventArrivedEventArgs e)
    {
        try
        {
            var targetInstance = (ManagementBaseObject)e.NewEvent["TargetInstance"];
            var processId = Convert.ToInt32(targetInstance["ProcessId"]);
            var processName = targetInstance["Name"]?.ToString() ?? string.Empty;
            var commandLine = targetInstance["CommandLine"]?.ToString() ?? string.Empty;

            var cmdInfo = new CapturedCommandInfo
            {
                ProcessId = processId,
                ProcessName = processName,
                CommandLine = commandLine
            };

            // Decode PowerShell Base64 if detected
            // فك تشفير Base64 الخاص بـ PowerShell
            if (processName.Equals("powershell.exe", StringComparison.OrdinalIgnoreCase) ||
                processName.Equals("pwsh.exe", StringComparison.OrdinalIgnoreCase))
            {
                cmdInfo.DecodedArguments = DecodePowerShellArguments(commandLine);
            }

            OnProcessCommandCaptured?.Invoke(this, cmdInfo);
        }
        catch (Exception ex)
        {
            // Fail-open: log and continue / استمرار عند الفشل
            Debug.WriteLine($"[ProcessCommandLineSniffer] Event processing failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Decodes Base64 encoded PowerShell arguments.
    /// فك تشفير معاملات PowerShell
    /// </summary>
    private string DecodePowerShellArguments(string commandLine)
    {
        try
        {
            var match = Regex.Match(commandLine, @"-(?:enc|EncodedCommand)\s+([A-Za-z0-9+/=]+)", RegexOptions.IgnoreCase);
            if (match.Success && match.Groups.Count > 1)
            {
                string base64 = match.Groups[1].Value;
                byte[] data = Convert.FromBase64String(base64);
                // PowerShell encoded commands are typically UTF-16LE
                // أوامر PowerShell المشفرة عادة ما تكون UTF-16LE
                return Encoding.Unicode.GetString(data);
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[ProcessCommandLineSniffer] Decode failed: {ex.Message}");
        }
        return string.Empty;
    }

    /// <summary>
    /// Stops the command line sniffer.
    /// إيقاف المراقبة
    /// </summary>
    public void Stop()
    {
        if (!_isRunning) return;

        try
        {
            if (_watcher != null)
            {
                _watcher.EventArrived -= Watcher_EventArrived;
                _watcher.Stop();
                _watcher.Dispose();
                _watcher = null;
            }
            _isRunning = false;
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[ProcessCommandLineSniffer] Stop failed: {ex.Message}");
        }
    }

    public void Dispose()
    {
        Stop();
        GC.SuppressFinalize(this);
    }
}
