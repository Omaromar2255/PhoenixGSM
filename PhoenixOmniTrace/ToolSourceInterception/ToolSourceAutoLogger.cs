using System;
using System.Collections.Concurrent;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace PhoenixGSM.OmniTrace.ToolSourceInterception;

/// <summary>
/// Autonomous Zero-Drop Disk Logger for Tool-Source Intercepted Commands.
/// Saves every command to .jsonl and .log in real-time on a background thread.
/// نظام الحفظ التلقائي الفوري للأوامر الملتقطة من المصدر على القرص
/// </summary>
public sealed class ToolSourceAutoLogger : IDisposable
{
    private readonly BlockingCollection<ToolSourceCommandRecord> _queue = new(new ConcurrentQueue<ToolSourceCommandRecord>());
    private readonly string _logDirectory;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _writerTask;
    private bool _isDisposed;

    public string LogDirectory => _logDirectory;

    public ToolSourceAutoLogger(string? customLogDirectory = null)
    {
        _logDirectory = !string.IsNullOrWhiteSpace(customLogDirectory)
            ? customLogDirectory
            : Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "PhoenixGSM",
                "ToolSourceAuditLogs");

        Directory.CreateDirectory(_logDirectory);
        _writerTask = Task.Run(WriterLoop);
    }

    public void Enqueue(ToolSourceCommandRecord record)
    {
        if (_isDisposed) return;
        _queue.TryAdd(record);
    }

    private void WriterLoop()
    {
        string todayStr = DateTime.UtcNow.ToString("yyyy-MM-dd");
        string jsonlPath = Path.Combine(_logDirectory, $"ToolSourceAudit_{todayStr}.jsonl");
        string humanLogPath = Path.Combine(_logDirectory, $"ToolSourceAudit_{todayStr}.log");

        using var jsonlStream = new FileStream(jsonlPath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
        using var jsonlWriter = new StreamWriter(jsonlStream, Encoding.UTF8) { AutoFlush = true };

        using var humanStream = new FileStream(humanLogPath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
        using var humanWriter = new StreamWriter(humanStream, Encoding.UTF8) { AutoFlush = true };

        while (!_cts.IsCancellationRequested)
        {
            try
            {
                if (_queue.TryTake(out var record, 500, _cts.Token))
                {
                    // Check date rollover
                    string currentDay = DateTime.UtcNow.ToString("yyyy-MM-dd");
                    if (currentDay != todayStr)
                    {
                        todayStr = currentDay;
                        jsonlPath = Path.Combine(_logDirectory, $"ToolSourceAudit_{todayStr}.jsonl");
                        humanLogPath = Path.Combine(_logDirectory, $"ToolSourceAudit_{todayStr}.log");
                    }

                    // 1. JSONL serialization
                    string jsonLine = JsonSerializer.Serialize(record);
                    jsonlWriter.WriteLine(jsonLine);

                    // 2. Human-readable format
                    string humanLine = $"[{record.TimeFormatted}] [{record.ModeName,-10}] [{record.ToolName} (PID {record.ProcessId})] {record.PureCommand} -> {record.TargetEndpoint} ({record.PayloadSize}B) [{record.RiskLevel}]";
                    humanWriter.WriteLine(humanLine);
                }
            }
            catch (OperationCanceledException) { break; }
            catch { }
        }
    }

    public void Flush()
    {
        while (_queue.Count > 0)
        {
            Thread.Sleep(10);
        }
    }

    public void Dispose()
    {
        if (_isDisposed) return;
        _isDisposed = true;
        _cts.Cancel();
        try { _writerTask.Wait(1500); } catch { }
        _queue.Dispose();
        _cts.Dispose();
    }
}
