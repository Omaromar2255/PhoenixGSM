using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using PhoenixOmniTrace.L24_SourceSentinel.Models;

namespace PhoenixOmniTrace.L24_SourceSentinel.Core;

public sealed class PortAndFileRadar : IDisposable
{
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly ConcurrentDictionary<string, DateTime> _recentFileEvents = new(StringComparer.OrdinalIgnoreCase);
    private readonly CancellationTokenSource _cts = new();
    private bool _isDisposed;

    public event Action<SourceTelemetryEvent>? OnRadarActivity;

    public int CurrentMonitoredPid { get; set; } = 0;
    public string CurrentMonitoredProcessName { get; set; } = "ReconnaissanceRadar";

    public void StartMonitoring(string? targetDirectory = null)
    {
        if (_isDisposed) return;

        AddDirectoryWatcher(Path.GetTempPath());

        if (!string.IsNullOrWhiteSpace(targetDirectory) && Directory.Exists(targetDirectory))
        {
            L24FileArchiver.RegisterToolDirectory(targetDirectory);
            AddDirectoryWatcher(targetDirectory);
        }

        if (Directory.Exists(@"C:\UnlockTool"))
        {
            L24FileArchiver.RegisterToolDirectory(@"C:\UnlockTool");
            AddDirectoryWatcher(@"C:\UnlockTool");
        }
    }

    public void AddDirectoryWatcher(string directoryPath)
    {
        if (_isDisposed || string.IsNullOrWhiteSpace(directoryPath) || !Directory.Exists(directoryPath))
            return;

        try
        {
            var watcher = new FileSystemWatcher(directoryPath)
            {
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime,
                IncludeSubdirectories = true,
                EnableRaisingEvents = true
            };

            watcher.Created += OnFileDiscovered;
            watcher.Changed += OnFileDiscovered;
            watcher.Renamed += (s, e) => OnFileDiscovered(s, e);
            _watchers.Add(watcher);
        }
        catch { }
    }

    private void OnFileDiscovered(object sender, FileSystemEventArgs e)
    {
        if (_isDisposed || string.IsNullOrWhiteSpace(e.FullPath)) return;

        try
        {
            if (e.FullPath.Contains("L24_SourceSentinel", StringComparison.OrdinalIgnoreCase) ||
                e.FullPath.Contains("CapturedFiles", StringComparison.OrdinalIgnoreCase) ||
                e.FullPath.Contains("CapturedArtifacts", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            string ext = Path.GetExtension(e.FullPath).ToLowerInvariant();
            string fileName = Path.GetFileName(e.FullPath).ToLowerInvariant();

            bool isInteresting =
                ext is ".bin" or ".da" or ".elf" or ".mbn" or ".xml" or ".auth" or ".sca" or ".pit"
                    or ".qcn" or ".xqcn" or ".pac" or ".ofp" or ".ops" or ".tar" or ".md5" or ".7z"
                    or ".zip" or ".lz4" or ".img" or ".exe" or ".dll" or ".sys" or ".inf" or ".dat"
                    or ".sh" or ".bat" or ".cmd" or ".py" or ".json" or ".plist" or ".shsh2" or ".im4p" or ".img4"
                || fileName.Contains("da") || fileName.Contains("loader") || fileName.Contains("firehose")
                || fileName.Contains("preloader") || fileName.Contains("scatter") || fileName.Contains("rawprogram")
                || fileName.Contains("patch") || fileName.Contains("auth") || fileName.Contains("fastboot")
                || fileName.Contains("adb") || fileName.Contains("shield") || fileName.Contains("at");

            if (!isInteresting) return;

            DateTime now = DateTime.UtcNow;
            if (_recentFileEvents.TryGetValue(e.FullPath, out var prevTime) && (now - prevTime).TotalMilliseconds < 900)
                return;
            _recentFileEvents[e.FullPath] = now;

            long size = 0;
            string rawHex = string.Empty;
            string asciiPreview = string.Empty;
            string savedCopyPath = string.Empty;
            string sha256 = string.Empty;

            if (File.Exists(e.FullPath))
            {
                // 1. حفظ نسخة فعلية كاملة من الملف المكتشف فوراً عبر L24FileArchiver قبل أن تحذفه الأداة!
                if (L24FileArchiver.TryArchiveDiscoveredFile(
                    e.FullPath,
                    $"PortAndFileRadar ({CurrentMonitoredProcessName})",
                    out string archivedPath,
                    out long archivedSize,
                    out string hash))
                {
                    savedCopyPath = archivedPath;
                    size = archivedSize;
                    sha256 = hash;
                }

                // 2. قراءة عينة للعرض السريع في جدول الـ Hex Inspector
                try
                {
                    using var fs = new FileStream(e.FullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                    if (size == 0) size = fs.Length;
                    int previewLen = (int)Math.Min(fs.Length, 4096L);
                    if (previewLen > 0)
                    {
                        byte[] buf = new byte[previewLen];
                        int got = fs.Read(buf, 0, previewLen);
                        if (got > 0)
                        {
                            rawHex = Convert.ToHexString(buf.AsSpan(0, Math.Min(got, 512)));
                            string extractedAscii = Decoders.RawPayloadClassifier.TryExtractPrintableAscii(buf.AsSpan(0, got));
                            if (!string.IsNullOrWhiteSpace(extractedAscii))
                            {
                                asciiPreview = extractedAscii.Trim();
                                if (asciiPreview.Length > 160)
                                    asciiPreview = asciiPreview[..160] + "...";
                            }
                        }
                    }
                }
                catch { }
            }

            string sizeStr = size >= 1024 * 1024
                ? $"{size / (1024.0 * 1024.0):F2} MB"
                : (size >= 1024 ? $"{size / 1024.0:F1} KB" : $"{size} B");

            string savedBadge = !string.IsNullOrWhiteSpace(savedCopyPath)
                ? $" | 💾 تم حفظ نسخة كاملة في: [{Path.GetFileName(savedCopyPath)}] (SHA256: {sha256[..Math.Min(12, sha256.Length)]})"
                : " | ⚠️ (الملف قيد الكتابة أو مغلق حصرياً)";

            string desc = $"📁 اكتشاف وحفظ ملف بالأداة: [{Path.GetFileName(e.FullPath)}] (الحجم: {sizeStr}) المسار الأصلي: {e.FullPath}{savedBadge}";
            if (!string.IsNullOrWhiteSpace(asciiPreview))
            {
                desc += $" | محتوى نصي: {asciiPreview}";
            }

            OnRadarActivity?.Invoke(new SourceTelemetryEvent
            {
                ProcessId = CurrentMonitoredPid,
                ThreadId = 0,
                Stage = SentinelStage.LocalFilePreparation,
                HookedApiName = "FileSystemWatcher / AutoArchiver",
                CallerModuleOrigin = string.IsNullOrWhiteSpace(CurrentMonitoredProcessName) ? "ReconnaissanceRadar" : CurrentMonitoredProcessName,
                TargetResource = !string.IsNullOrWhiteSpace(savedCopyPath) ? savedCopyPath : e.FullPath,
                CommandCategory = !string.IsNullOrWhiteSpace(savedCopyPath) ? "Archived Helper / Loader File" : "Helper File Preparation",
                DecodedCommandText = desc,
                PureCommandText = e.FullPath,
                SavedFilePath = savedCopyPath,
                RawPayloadHex = rawHex,
                PayloadSize = (int)Math.Min(size, int.MaxValue)
            });
        }
        catch { }
    }

    public void ReportPortScanEvent(int pid, int tid, string apiName, string callerOrigin, string queriedGuidOrPort, string description)
    {
        OnRadarActivity?.Invoke(new SourceTelemetryEvent
        {
            ProcessId = pid,
            ThreadId = tid,
            Stage = SentinelStage.PortAndDeviceRadar,
            HookedApiName = apiName,
            CallerModuleOrigin = callerOrigin,
            TargetResource = queriedGuidOrPort,
            CommandCategory = "Port / Device Scan",
            DecodedCommandText = description,
            PureCommandText = queriedGuidOrPort,
            PayloadSize = 0
        });
    }

    public void StopMonitoring()
    {
        foreach (var w in _watchers)
        {
            try
            {
                w.EnableRaisingEvents = false;
                w.Dispose();
            }
            catch { }
        }
        _watchers.Clear();
        _recentFileEvents.Clear();
    }

    public void Dispose()
    {
        if (_isDisposed) return;
        _isDisposed = true;
        StopMonitoring();
        try { _cts.Cancel(); _cts.Dispose(); } catch { }
    }
}
