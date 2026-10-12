using System;
using System.IO;
using System.Text.Json;
using PhoenixGSM.UsbMonitor.Models;

namespace PhoenixGSM.UsbMonitor;

public class UsbLogger
{
    private readonly string _logDir;
    private readonly string _currentLogFile;
    private readonly object _fileLock = new();

    public string LogDirectory => _logDir;
    public string CurrentLogFile => _currentLogFile;

    public UsbLogger(string? customLogDir = null)
    {
        _logDir = customLogDir ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "PhoenixGSM", "Logs", "USB");

        Directory.CreateDirectory(_logDir);

        var dateStr = DateTime.UtcNow.ToString("yyyy-MM-dd");
        _currentLogFile = Path.Combine(_logDir, $"usb_log_{dateStr}.jsonl");
    }

    public void LogFrame(AdbUsbFrame frame)
    {
        try
        {
            var line = JsonSerializer.Serialize(frame);
            lock (_fileLock)
            {
                File.AppendAllText(_currentLogFile, line + Environment.NewLine);
            }
        }
        catch { }
    }

    public IEnumerable<AdbUsbFrame> ReadAllLogs()
    {
        if (!Directory.Exists(_logDir)) yield break;

        var files = Directory.GetFiles(_logDir, "usb_log_*.jsonl").OrderBy(f => f);
        foreach (var file in files)
        {
            foreach (var line in File.ReadLines(file))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                AdbUsbFrame? frame = null;
                try
                {
                    frame = JsonSerializer.Deserialize<AdbUsbFrame>(line);
                }
                catch { }

                if (frame != null) yield return frame;
            }
        }
    }
}
