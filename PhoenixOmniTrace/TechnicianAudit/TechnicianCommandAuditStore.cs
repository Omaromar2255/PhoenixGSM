using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace PhoenixGSM.OmniTrace.TechnicianAudit;

/// <summary>
/// High-speed, zero-loss persistence store for commands sent from the technician to the client's phone.
/// Writes to both JSONL (for forensic data ingestion) and readable .log (for immediate human auditing)
/// with real-time flushing to prevent data loss on unexpected exits.
/// </summary>
public sealed class TechnicianCommandAuditStore : IDisposable
{
    private readonly string _logDirectory;
    private readonly BlockingCollection<TechnicianAuditRecord> _writeQueue = new(new ConcurrentQueue<TechnicianAuditRecord>());
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _writerTask;
    private readonly object _fileLock = new();
    private bool _isDisposed;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = false,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    public string LogDirectoryPath => _logDirectory;

    public string CurrentJsonlPath => Path.Combine(_logDirectory, $"TechnicianAudit_{DateTime.UtcNow:yyyyMMdd}.jsonl");
    public string CurrentLogPath => Path.Combine(_logDirectory, $"TechnicianAudit_{DateTime.UtcNow:yyyyMMdd}.log");

    public TechnicianCommandAuditStore(string? customDirectory = null)
    {
        if (!string.IsNullOrWhiteSpace(customDirectory))
        {
            _logDirectory = customDirectory;
        }
        else
        {
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            _logDirectory = Path.Combine(baseDir, "Logs", "TechnicianAudit");
        }

        try
        {
            if (!Directory.Exists(_logDirectory))
            {
                Directory.CreateDirectory(_logDirectory);
            }
        }
        catch
        {
            // Fallback to local AppData if Program Files or baseDir is read-only
            _logDirectory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "PhoenixGSM", "TechnicianAudit");
            Directory.CreateDirectory(_logDirectory);
        }

        _writerTask = Task.Factory.StartNew(ProcessQueueLoop, TaskCreationOptions.LongRunning);
    }

    /// <summary>
    /// Enqueues a command record for immediate background persistence.
    /// </summary>
    public void SaveRecord(TechnicianAuditRecord record)
    {
        if (_isDisposed || _writeQueue.IsAddingCompleted) return;

        try
        {
            _writeQueue.Add(record);
        }
        catch (InvalidOperationException) { }
    }

    private void ProcessQueueLoop()
    {
        var token = _cts.Token;
        while (!token.IsCancellationRequested)
        {
            try
            {
                if (_writeQueue.TryTake(out var record, 100, token))
                {
                    WriteRecordToDisk(record);

                    // Drain all remaining items in burst
                    while (_writeQueue.TryTake(out var extraRecord))
                    {
                        WriteRecordToDisk(extraRecord);
                    }
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[TechnicianCommandAuditStore] Writer error: {ex.Message}");
            }
        }

        // Flush any remaining records on shutdown
        while (_writeQueue.TryTake(out var lastRecord))
        {
            try { WriteRecordToDisk(lastRecord); } catch { }
        }
    }

    private void WriteRecordToDisk(TechnicianAuditRecord record)
    {
        lock (_fileLock)
        {
            for (int attempt = 0; attempt < 5; attempt++)
            {
                try
                {
                    string jsonlFile = CurrentJsonlPath;
                    string logFile = CurrentLogPath;

                    // 1. Write structured JSONL
                    string jsonLine = JsonSerializer.Serialize(record, JsonOptions);
                    File.AppendAllText(jsonlFile, jsonLine + Environment.NewLine, Encoding.UTF8);

                    // 2. Write Human-Readable Audit Log
                    string toolInfo = !string.IsNullOrEmpty(record.TechnicianTool) && record.TechnicianProcessId > 0
                        ? $"{record.TechnicianTool}:{record.TechnicianProcessId}"
                        : record.TechnicianTool;

                    string target = !string.IsNullOrEmpty(record.TargetDeviceOrPort)
                        ? record.TargetDeviceOrPort
                        : "DEV";
                    string dirSym = record.IsResponse ? "<<" : ">>";

                    string pairedInfo = !string.IsNullOrEmpty(record.DeviceResponse)
                        ? $" [Reply: {record.DeviceResponse.Replace("\r", " ").Replace("\n", " ").Trim()}]"
                        : (record.RelatedCommandId.HasValue && !string.IsNullOrEmpty(record.RelatedCommandText)
                            ? $" [In Response To #{record.RelatedCommandId}: {record.RelatedCommandText.Replace("\r", " ").Replace("\n", " ").Trim()}]"
                            : "");

                    string humanLine = $"[{record.Timestamp:yyyy-MM-dd HH:mm:ss.fff}] " +
                                       $"[{record.Protocol}] [{record.Mode}] [{record.Direction}] [{toolInfo}] [{target}] " +
                                       $"{dirSym} {record.PureCommand} " +
                                       $"[Hash:{record.Sha256Hash[..Math.Min(8, record.Sha256Hash.Length)]}]" +
                                       pairedInfo +
                                       Environment.NewLine;

                    File.AppendAllText(logFile, humanLine, Encoding.UTF8);
                    break;
                }
                catch (IOException)
                {
                    Thread.Sleep(10);
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[TechnicianCommandAuditStore] Failed to write record to disk: {ex.Message}");
                    break;
                }
            }
        }
    }

    /// <summary>
    /// Opens the audit log directory in Windows Explorer.
    /// </summary>
    public void OpenLogFolder()
    {
        try
        {
            if (Directory.Exists(_logDirectory))
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "explorer.exe",
                    Arguments = $"\"{_logDirectory}\"",
                    UseShellExecute = true
                });
            }
        }
        catch { }
    }

    /// <summary>
    /// Reads records from today's JSONL file.
    /// </summary>
    public List<TechnicianAuditRecord> ReadTodayRecords()
    {
        var list = new List<TechnicianAuditRecord>();
        try
        {
            string jsonlFile = CurrentJsonlPath;
            if (File.Exists(jsonlFile))
            {
                foreach (string line in File.ReadLines(jsonlFile, Encoding.UTF8))
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    try
                    {
                        var item = JsonSerializer.Deserialize<TechnicianAuditRecord>(line, JsonOptions);
                        if (item != null) list.Add(item);
                    }
                    catch { }
                }
            }
        }
        catch { }
        return list;
    }

    public void Flush()
    {
        while (_writeQueue.Count > 0)
        {
            if (_writeQueue.TryTake(out var record))
            {
                WriteRecordToDisk(record);
            }
        }
    }

    public void Dispose()
    {
        if (_isDisposed) return;
        _isDisposed = true;

        try
        {
            _writeQueue.CompleteAdding();
            _cts.Cancel();
            _writerTask.Wait(1000);
            _writeQueue.Dispose();
            _cts.Dispose();
        }
        catch { }
    }
}
