using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading;
using PhoenixOmniTrace.L24_SourceSentinel.Models;

namespace PhoenixOmniTrace.L24_SourceSentinel.Core;

public sealed partial class SourceSentinelOrchestrator
{
    private static string ResolveDefaultLogDirectory()
    {
        string localProjLogs = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Logs", "L24_SourceSentinel");
        if (Directory.Exists(Path.GetDirectoryName(localProjLogs)))
            return localProjLogs;

        return Path.Combine(Directory.GetCurrentDirectory(), "Logs", "L24_SourceSentinel");
    }

    private void RecordUnfilteredRawEvent(SourceTelemetryEvent evt)
    {
        if (!_isActive || !_isUnfilteredRawLoggingEnabled || _isDisposed || evt == null) return;
        try
        {
            if (_excludeUrlsFromRawLog && (evt.CommandGroup == L24CommandGroup.ServerCloudLogin || L24CommandClassifier.IsUrlOrNetworkOrAuth(evt)))
                return;
            string rawKey = $"{evt.HookedApiName}|{evt.CommandCategory}|{evt.TargetResource}|{evt.DecodedCommandText}";
            DateTime now = DateTime.UtcNow;

            if (_rawStreamMicroDebounce.TryGetValue(rawKey, out var lastSeen) && (now - lastSeen).TotalSeconds < 1.5)
                return;
            _rawStreamMicroDebounce[rawKey] = now;

            var rawCopy = new SourceTelemetryEvent
            {
                EventId = Guid.NewGuid(),
                Timestamp = evt.Timestamp,
                ProcessId = evt.ProcessId,
                ThreadId = evt.ThreadId,
                Stage = evt.Stage,
                MemoryAddress = evt.MemoryAddress,
                HookedApiName = evt.HookedApiName,
                CallerModuleOrigin = evt.CallerModuleOrigin,
                TargetResource = evt.TargetResource,
                CommandCategory = evt.CommandCategory,
                DecodedCommandText = evt.DecodedCommandText,
                PureCommandText = evt.PureCommandText,
                SavedFilePath = evt.SavedFilePath,
                RawPayloadHex = evt.RawPayloadHex,
                PayloadSize = evt.PayloadSize
            };

            _unfilteredRawEvents.Enqueue(rawCopy);
            _unfilteredRawDiskQueue.TryAdd(rawCopy);
            OnUnfilteredRawEventCaptured?.Invoke(rawCopy);
        }
        catch { }
    }

    private void DiskLoggerLoop(CancellationToken token)
    {
        var options = new JsonSerializerOptions
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            WriteIndented = false
        };

        try
        {
            using var jsonlStream = new FileStream(_sessionJsonlPath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
            using var writer = new StreamWriter(jsonlStream, Encoding.UTF8) { AutoFlush = true };

            while (!token.IsCancellationRequested && !_isDisposed && _isActive)
            {
                try
                {
                    if (_diskLogQueue.TryTake(out var evt, 500, token))
                    {
                        writer.WriteLine(JsonSerializer.Serialize(evt, options));
                    }
                }
                catch (OperationCanceledException) { break; }
                catch { }
            }
        }
        catch { }
    }

    private void UnfilteredRawDiskLoggerLoop(CancellationToken token)
    {
        var options = new JsonSerializerOptions
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            WriteIndented = false
        };

        try
        {
            using var txtStream = new FileStream(_unfilteredRawTxtPath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
            using var txtWriter = new StreamWriter(txtStream, Encoding.UTF8) { AutoFlush = true };

            using var jsonlStream = new FileStream(_unfilteredRawJsonlPath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
            using var jsonlWriter = new StreamWriter(jsonlStream, Encoding.UTF8) { AutoFlush = true };

            txtWriter.WriteLine($"=== السجل الشامل الخام بدون فلترة (L24 Unfiltered Raw Stream) — بدأ في {DateTime.Now:yyyy-MM-dd HH:mm:ss} ===");
            txtWriter.WriteLine(new string('=', 95));

            while (!token.IsCancellationRequested && !_isDisposed && _isActive)
            {
                try
                {
                    if (_unfilteredRawDiskQueue.TryTake(out var evt, 500, token))
                    {
                        jsonlWriter.WriteLine(JsonSerializer.Serialize(evt, options));

                        string savedInfo = !string.IsNullOrWhiteSpace(evt.SavedFilePath) ? $" | SavedFile: {evt.SavedFilePath}" : "";
                        txtWriter.WriteLine($"[{evt.FormattedTimestamp}] [PID:{evt.ProcessId}] [{evt.StageBadge}] [{evt.CommandCategory}] Origin: {evt.CallerModuleOrigin} | Target: {evt.TargetResource}{savedInfo}");
                        txtWriter.WriteLine($"  -> الأمر الصافي : {evt.PureCommandText}");
                        txtWriter.WriteLine($"  -> التفاصيل    : {evt.DecodedCommandText}");
                        txtWriter.WriteLine(new string('-', 80));
                    }
                }
                catch (OperationCanceledException) { break; }
                catch { }
            }
        }
        catch { }
    }

    public IReadOnlyList<SourceTelemetryEvent> GetSessionEvents() => _sessionEvents.ToArray();
    public IReadOnlyList<SourceTelemetryEvent> GetUnfilteredRawEvents() => _unfilteredRawEvents.ToArray();

    public void ClearUnfilteredRawEvents()
    {
        while (_unfilteredRawEvents.TryDequeue(out _)) { }
        while (_unfilteredRawDiskQueue.TryTake(out _)) { }
        _rawStreamMicroDebounce.Clear();
    }

    public void FlushAndExportSessionSnapshot()
    {
        try
        {
            var options = new JsonSerializerOptions
            {
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                WriteIndented = true
            };

            var snapshot = _sessionEvents.ToArray();
            string json = JsonSerializer.Serialize(snapshot, options);
            File.WriteAllText(_sessionLogPath, json, Encoding.UTF8);
            OnLogMessage?.Invoke($"[L24 SourceSentinel] تم حفظ الجلسة المنظمة ({snapshot.Length} حدث) والسجل الخام في: {_logDirectory}");
        }
        catch (Exception ex)
        {
            OnLogMessage?.Invoke($"[خطأ تصدير الجلسة]: {ex.Message}");
        }
    }
}
