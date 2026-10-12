namespace PhoenixGSM.CommandAnalyzer;

using System.Text.Json;

/// <summary>
/// قارئ ومحلل ملفات السجلات من جميع أدوات المراقبة
/// Log file reader and parser for all monitoring tools
/// </summary>
public class LogParser
{
    private readonly string _logBaseDirectory;

    public LogParser(string logBaseDirectory)
    {
        _logBaseDirectory = logBaseDirectory;
    }

    /// <summary>
    /// قراءة جميع سجلات ADB
    /// Read all ADB logs
    /// </summary>
    public async Task<List<JsonElement>> ReadAdbLogsAsync(string? dateFilter = null)
    {
        var adbDir = Path.Combine(_logBaseDirectory, "ADB");
        return await ReadJsonlFilesAsync(adbDir, "adb_log_", dateFilter);
    }

    /// <summary>
    /// قراءة جميع سجلات Serial
    /// Read all Serial logs
    /// </summary>
    public async Task<List<JsonElement>> ReadSerialLogsAsync(string? dateFilter = null)
    {
        var serialDir = Path.Combine(_logBaseDirectory, "Serial");
        return await ReadJsonlFilesAsync(serialDir, "serial_log_", dateFilter);
    }

    /// <summary>
    /// قراءة جميع سجلات Process
    /// Read all Process logs
    /// </summary>
    public async Task<List<JsonElement>> ReadProcessLogsAsync(string? processFilter = null)
    {
        var processDir = Path.Combine(_logBaseDirectory, "Process");
        return await ReadJsonlFilesAsync(processDir, "process_log_", processFilter);
    }

    /// <summary>
    /// قراءة جميع سجلات USB
    /// Read all USB logs
    /// </summary>
    public async Task<List<JsonElement>> ReadUsbLogsAsync(string? dateFilter = null)
    {
        var usbDir = Path.Combine(_logBaseDirectory, "USB");
        return await ReadJsonlFilesAsync(usbDir, "usb_log_", dateFilter);
    }

    /// <summary>
    /// قراءة ملفات JSONL من مجلد
    /// Read JSONL files from directory
    /// </summary>
    private static async Task<List<JsonElement>> ReadJsonlFilesAsync(
        string directory, string prefix, string? filter = null)
    {
        var results = new List<JsonElement>();

        if (!Directory.Exists(directory))
            return results;

        var files = Directory.GetFiles(directory, $"{prefix}*.jsonl");

        if (!string.IsNullOrEmpty(filter))
            files = files.Where(f => f.Contains(filter, StringComparison.OrdinalIgnoreCase)).ToArray();

        foreach (var file in files.OrderBy(f => f))
        {
            await foreach (var line in File.ReadLinesAsync(file))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                try
                {
                    var element = JsonSerializer.Deserialize<JsonElement>(line);
                    results.Add(element);
                }
                catch { }
            }
        }

        return results;
    }

    /// <summary>
    /// الحصول على ملخص سريع للسجلات المتاحة
    /// Get quick summary of available logs
    /// </summary>
    public Dictionary<string, LogSummary> GetAvailableLogsSummary()
    {
        var summaries = new Dictionary<string, LogSummary>();

        string[] subDirs = ["ADB", "Serial", "Process", "USB"];
        foreach (var sub in subDirs)
        {
            var dir = Path.Combine(_logBaseDirectory, sub);
            if (!Directory.Exists(dir)) continue;

            var files = Directory.GetFiles(dir, "*.jsonl");
            if (files.Length == 0) continue;

            var totalLines = 0;
            long totalSize = 0;
            DateTime? earliest = null;
            DateTime? latest = null;

            foreach (var file in files)
            {
                var info = new FileInfo(file);
                totalSize += info.Length;
                totalLines += File.ReadLines(file).Count();

                if (earliest == null || info.CreationTime < earliest)
                    earliest = info.CreationTime;
                if (latest == null || info.LastWriteTime > latest)
                    latest = info.LastWriteTime;
            }

            summaries[sub] = new LogSummary
            {
                Category = sub,
                FileCount = files.Length,
                TotalEntries = totalLines,
                TotalSizeKB = totalSize / 1024.0,
                EarliestEntry = earliest,
                LatestEntry = latest
            };
        }

        return summaries;
    }
}

public class LogSummary
{
    public string Category { get; set; } = "";
    public int FileCount { get; set; }
    public int TotalEntries { get; set; }
    public double TotalSizeKB { get; set; }
    public DateTime? EarliestEntry { get; set; }
    public DateTime? LatestEntry { get; set; }
}
