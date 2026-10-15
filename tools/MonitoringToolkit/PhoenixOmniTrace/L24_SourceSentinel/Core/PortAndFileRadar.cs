using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using PhoenixOmniTrace.L24_SourceSentinel.Models;

namespace PhoenixOmniTrace.L24_SourceSentinel.Core;

public sealed class PortAndFileRadar : IDisposable
{
    private FileSystemWatcher? _tempWatcher;
    private readonly CancellationTokenSource _cts = new();
    private bool _isDisposed;

    public event Action<SourceTelemetryEvent>? OnRadarActivity;

    public void StartMonitoring(string? targetDirectory = null)
    {
        if (_isDisposed) return;

        try
        {
            string tempDir = !string.IsNullOrWhiteSpace(targetDirectory) && Directory.Exists(targetDirectory)
                ? targetDirectory
                : Path.GetTempPath();

            _tempWatcher = new FileSystemWatcher(tempDir)
            {
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime,
                IncludeSubdirectories = true,
                EnableRaisingEvents = true
            };

            _tempWatcher.Created += OnFileDiscovered;
            _tempWatcher.Changed += OnFileDiscovered;
        }
        catch { /* قد لا تتوفر صلاحيات مراقبة المجلد المؤقت في بعض البيئات */ }
    }

    public int CurrentMonitoredPid { get; set; } = 0;
    public string CurrentMonitoredProcessName { get; set; } = "ReconnaissanceRadar";

    private void OnFileDiscovered(object sender, FileSystemEventArgs e)
    {
        if (_isDisposed) return;
        try
        {
            string ext = Path.GetExtension(e.FullPath).ToLowerInvariant();
            string fileName = Path.GetFileName(e.FullPath).ToLowerInvariant();

            // فحص الملفات المساعدة الشائعة في أدوات الصيانة والفحص
            bool isInteresting = ext is ".bin" or ".da" or ".elf" or ".mbn" or ".xml" or ".exe" or ".dll" or ".sys" or ".inf" or ".dat"
                              || fileName.Contains("da") || fileName.Contains("loader") || fileName.Contains("firehose")
                              || fileName.Contains("auth") || fileName.Contains("fastboot") || fileName.Contains("adb")
                              || fileName.Contains("shield") || fileName.Contains("test");

            if (isInteresting)
            {
                long size = 0;
                string rawHex = string.Empty;
                string asciiPreview = string.Empty;

                try
                {
                    if (File.Exists(e.FullPath))
                    {
                        var fi = new FileInfo(e.FullPath);
                        size = fi.Length;

                        // إذا كان الحجم بين 1 بايت و 64 كيلوبايت، نقرأ المحتوى الفعلي للملف المساعد فورياً
                        if (size > 0 && size <= 65536)
                        {
                            byte[]? fileBytes = null;
                            for (int retry = 0; retry < 3; retry++)
                            {
                                try
                                {
                                    using var fs = new FileStream(e.FullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                                    int toRead = (int)Math.Min(fs.Length, 65536);
                                    if (toRead > 0)
                                    {
                                        fileBytes = new byte[toRead];
                                        int bytesRead = fs.Read(fileBytes, 0, toRead);
                                        if (bytesRead > 0)
                                        {
                                            if (bytesRead < toRead)
                                                Array.Resize(ref fileBytes, bytesRead);
                                            break;
                                        }
                                    }
                                }
                                catch (IOException)
                                {
                                    Thread.Sleep(30);
                                }
                            }

                            if (fileBytes != null && fileBytes.Length > 0)
                            {
                                size = fileBytes.Length;
                                rawHex = Convert.ToHexString(fileBytes);
                                string extractedAscii = Decoders.RawPayloadClassifier.TryExtractPrintableAscii(fileBytes);
                                if (!string.IsNullOrWhiteSpace(extractedAscii))
                                {
                                    asciiPreview = extractedAscii.Trim();
                                    if (asciiPreview.Length > 120)
                                        asciiPreview = asciiPreview.Substring(0, 120) + "...";
                                }
                            }
                        }
                    }
                }
                catch { }

                string sizeStr = size >= 1024 ? $"{size / 1024} KB" : $"{size} B";
                string desc = $"تجهيز/إنشاء ملف مساعد بالأداة قبل تنفيذ الأمر: [{Path.GetFileName(e.FullPath)}] (الحجم: {sizeStr}) المسار: {e.FullPath}";
                if (!string.IsNullOrWhiteSpace(asciiPreview))
                {
                    desc += $" [محتوى: {asciiPreview}]";
                }

                OnRadarActivity?.Invoke(new SourceTelemetryEvent
                {
                    ProcessId = CurrentMonitoredPid,
                    ThreadId = 0,
                    Stage = SentinelStage.LocalFilePreparation,
                    HookedApiName = "FileSystemWatcher / FileDiscovery",
                    CallerModuleOrigin = string.IsNullOrWhiteSpace(CurrentMonitoredProcessName) ? "ReconnaissanceRadar" : CurrentMonitoredProcessName,
                    TargetResource = e.FullPath,
                    CommandCategory = "Helper File Preparation",
                    DecodedCommandText = desc,
                    RawPayloadHex = rawHex,
                    PayloadSize = (int)Math.Min(size, int.MaxValue)
                });
            }
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
            PayloadSize = 0
        });
    }

    public void Dispose()
    {
        if (_isDisposed) return;
        _isDisposed = true;
        _cts.Cancel();
        _cts.Dispose();
        if (_tempWatcher != null)
        {
            _tempWatcher.EnableRaisingEvents = false;
            _tempWatcher.Dispose();
            _tempWatcher = null;
        }
    }
}
