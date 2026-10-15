using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using PhoenixOmniTrace.L24_SourceSentinel.Models;

namespace PhoenixOmniTrace.L24_SourceSentinel.Core;

public sealed class KernelAndUsbEtwInterceptor : IDisposable
{
    private TraceEventSession? _etwSession;
    private ManagementEventWatcher? _processWatcher;
    private CancellationTokenSource? _cts;
    private readonly ConcurrentDictionary<int, string> _trackedPids = new();
    private readonly ConcurrentDictionary<string, bool> _seenKernelEvents = new(StringComparer.OrdinalIgnoreCase);
    private bool _isDisposed;

    public event Action<SourceTelemetryEvent>? OnKernelActivityDetected;

    public void StartMonitoring(int targetPid, string processName = "")
    {
        if (_isDisposed) return;

        string name = string.IsNullOrWhiteSpace(processName) ? $"PID_{targetPid}" : processName;
        _trackedPids[targetPid] = name;

        if (_cts != null) return; // تم تشغيل المراقبة الخلفية مسبقاً

        _cts = new CancellationTokenSource();
        var token = _cts.Token;

        // 1. مراقب العمليات الفرعية عبر WMI لضمان التقاط CommandLine حتى بدون صلاحيات أدمن كاملة
        Task.Run(() => StartWmiProcessWatcher(token), token);

        // 2. جلسة كيرنل ETW إذا توفرت الصلاحيات لالتقاط أحداث الملفات وعمليات النواة
        Task.Run(() => StartEtwKernelSession(token), token);
    }

    private void StartWmiProcessWatcher(CancellationToken token)
    {
        try
        {
            if (!OperatingSystem.IsWindows()) return;

            var query = new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace");
            _processWatcher = new ManagementEventWatcher(query);
            _processWatcher.EventArrived += (s, e) =>
            {
                try
                {
                    int parentPid = Convert.ToInt32(e.NewEvent.Properties["ParentProcessID"]?.Value ?? 0);
                    int childPid = Convert.ToInt32(e.NewEvent.Properties["ProcessID"]?.Value ?? 0);
                    string procName = e.NewEvent.Properties["ProcessName"]?.Value?.ToString() ?? "";

                    if (parentPid != 0 && (_trackedPids.ContainsKey(parentPid) || IsKnownToolChild(procName)))
                    {
                        string parentName = _trackedPids.TryGetValue(parentPid, out var pn) ? pn : $"ParentPID_{parentPid}";
                        _trackedPids[childPid] = procName;

                        string cmdLine = GetProcessCommandLine(childPid);
                        string key = $"PROC:{childPid}:{cmdLine}";
                        if (_seenKernelEvents.TryAdd(key, true))
                        {
                            OnKernelActivityDetected?.Invoke(new SourceTelemetryEvent
                            {
                                ProcessId = childPid,
                                ThreadId = 0,
                                Stage = SentinelStage.RawCommandExecution,
                                HookedApiName = "NtCreateUserProcess / Win32_ProcessStart",
                                CallerModuleOrigin = $"{parentName} -> {procName}",
                                TargetResource = string.IsNullOrWhiteSpace(cmdLine) ? procName : cmdLine,
                                CommandCategory = "Child Process Execution",
                                DecodedCommandText = $"تشغيل عملية فرعية من الأداة: [{procName}] سطر الأوامر: {(string.IsNullOrWhiteSpace(cmdLine) ? procName : cmdLine)}",
                                PayloadSize = cmdLine.Length
                            });
                        }
                    }
                }
                catch { }
            };

            _processWatcher.Start();
            token.WaitHandle.WaitOne();
        }
        catch { }
    }

    private static bool IsKnownToolChild(string procName)
    {
        string lower = procName.ToLowerInvariant();
        return lower is "adb.exe" or "fastboot.exe" or "7z.exe" or "7za.exe" or "unzip.exe" or "tar.exe"
            or "simg2img.exe" or "make_ext4fs.exe" or "python.exe" or "cmd.exe" or "powershell.exe"
            or "conhost.exe" or "scrcpy.exe";
    }

    private static string GetProcessCommandLine(int pid)
    {
        try
        {
            if (!OperatingSystem.IsWindows()) return string.Empty;
            using var searcher = new ManagementObjectSearcher($"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
            using var objects = searcher.Get();
            foreach (ManagementObject obj in objects)
            {
                return obj["CommandLine"]?.ToString() ?? string.Empty;
            }
        }
        catch { }
        return string.Empty;
    }

    private void StartEtwKernelSession(CancellationToken token)
    {
        try
        {
            if (!OperatingSystem.IsWindows()) return;
            if (TraceEventSession.IsElevated() != true) return;

            string sessionName = $"PhoenixOmniTrace_L24_Kernel_{Process.GetCurrentProcess().Id}";

            try
            {
                var existing = TraceEventSession.GetActiveSession(sessionName);
                if (existing != null)
                {
                    existing.Stop();
                    existing.Dispose();
                }
            }
            catch { }

            _etwSession = new TraceEventSession(sessionName)
            {
                BufferSizeMB = 16,
                CircularBufferMB = 16
            };

            _etwSession.EnableKernelProvider(
                KernelTraceEventParser.Keywords.FileIO |
                KernelTraceEventParser.Keywords.FileIOInit |
                KernelTraceEventParser.Keywords.Process
            );

            // 1. مراقبة العمليات المنطلقة مع سطر الأوامر لحظياً
            _etwSession.Source.Kernel.ProcessStart += data =>
            {
                try
                {
                    int parentPid = data.ParentID;
                    int childPid = data.ProcessID;
                    string procName = data.ImageFileName;
                    string cmdLine = data.CommandLine;

                    if (parentPid != 0 && (_trackedPids.ContainsKey(parentPid) || IsKnownToolChild(procName)))
                    {
                        string parentName = _trackedPids.TryGetValue(parentPid, out var pn) ? pn : $"ParentPID_{parentPid}";
                        _trackedPids[childPid] = procName;

                        string key = $"ETW_PROC:{childPid}:{cmdLine}";
                        if (_seenKernelEvents.TryAdd(key, true))
                        {
                            OnKernelActivityDetected?.Invoke(new SourceTelemetryEvent
                            {
                                ProcessId = childPid,
                                ThreadId = 0,
                                Stage = SentinelStage.RawCommandExecution,
                                HookedApiName = "ETW_ProcessStart",
                                CallerModuleOrigin = $"{parentName} -> {procName}",
                                TargetResource = cmdLine,
                                CommandCategory = "Child Process Execution",
                                DecodedCommandText = $"تشغيل عملية فرعية بنواة ويندوز: [{procName}] سطر الأوامر: {cmdLine}",
                                PayloadSize = cmdLine.Length
                            });
                        }
                    }
                }
                catch { }
            };

            // 2. مراقبة ملفات البوت واللودر واستخراج الأرشيفات عند إنشاء أو قراءة الملفات في النواة
            _etwSession.Source.Kernel.FileIOCreate += data => ProcessKernelFileEvent(data.ProcessID, data.FileName ?? "");
            _etwSession.Source.Kernel.FileIORead += data => ProcessKernelFileEvent(data.ProcessID, data.FileName ?? "");
            _etwSession.Source.Kernel.FileIOWrite += data => ProcessKernelFileEvent(data.ProcessID, data.FileName ?? "");

            _etwSession.Source.Process();
        }
        catch { }
    }

    private void ProcessKernelFileEvent(int pid, string fileName)
    {
        try
        {
            if (!_trackedPids.ContainsKey(pid)) return;
            if (string.IsNullOrWhiteSpace(fileName)) return;

            if (IsBootOrLoaderOrArchiveFile(fileName))
            {
                string key = $"FILEIO:{pid}:{fileName}";
                if (_seenKernelEvents.TryAdd(key, true))
                {
                    string procName = _trackedPids.TryGetValue(pid, out var pn) ? pn : $"PID_{pid}";
                    string ext = Path.GetExtension(fileName).ToLowerInvariant();
                    string category = ext is ".zip" or ".7z" or ".tar" or ".lz4"
                        ? "Firmware / Archive Extraction"
                        : "Boot Loader / Firmware File Access";

                    OnKernelActivityDetected?.Invoke(new SourceTelemetryEvent
                    {
                        ProcessId = pid,
                        ThreadId = 0,
                        Stage = SentinelStage.LocalFilePreparation,
                        HookedApiName = "NtCreateFile / NtReadFile (ETW Kernel)",
                        CallerModuleOrigin = procName,
                        TargetResource = fileName,
                        CommandCategory = category,
                        DecodedCommandText = $"رصد وصول كيرنلي لملف بوت/لودر/فلاش: [{Path.GetFileName(fileName)}] المسار: {fileName}",
                        PayloadSize = fileName.Length
                    });
                }
            }
            else if (fileName.Contains("COM", StringComparison.OrdinalIgnoreCase) ||
                     fileName.Contains("USB", StringComparison.OrdinalIgnoreCase) ||
                     fileName.Contains("cdcacm", StringComparison.OrdinalIgnoreCase) ||
                     fileName.Contains("ssudmdm", StringComparison.OrdinalIgnoreCase) ||
                     fileName.Contains("QCUSB", StringComparison.OrdinalIgnoreCase))
            {
                string key = $"DEVIO:{pid}:{fileName}";
                if (_seenKernelEvents.TryAdd(key, true))
                {
                    string procName = _trackedPids.TryGetValue(pid, out var pn) ? pn : $"PID_{pid}";
                    OnKernelActivityDetected?.Invoke(new SourceTelemetryEvent
                    {
                        ProcessId = pid,
                        ThreadId = 0,
                        Stage = SentinelStage.PortAndDeviceRadar,
                        HookedApiName = "DeviceFileIO (ETW Kernel)",
                        CallerModuleOrigin = procName,
                        TargetResource = fileName,
                        CommandCategory = "Kernel Device Handle Activity",
                        DecodedCommandText = $"نشاط كيرنلي على مقبض جهاز/بورت: {fileName}",
                        PayloadSize = fileName.Length
                    });
                }
            }
        }
        catch { }
    }

    private static bool IsBootOrLoaderOrArchiveFile(string path)
    {
        string ext = Path.GetExtension(path).ToLowerInvariant();
        string name = Path.GetFileName(path).ToLowerInvariant();

        return ext is ".mbn" or ".elf" or ".bin" or ".auth" or ".sca" or ".pit" or ".qcn" or ".xqcn"
                   or ".pac" or ".ofp" or ".ops" or ".tar" or ".md5" or ".7z" or ".zip" or ".lz4"
            || name.Contains("scatter") || name.Contains("firehose") || name.Contains("rawprogram")
            || name.Contains("patch") || name.Contains("preloader") || name.Contains("da_")
            || name.Contains("prog_") || name.Contains("gpt_main") || name.Contains("gpt_backup");
    }

    public void ReportSyntheticKernelEvent(int pid, SentinelStage stage, string apiName, string callerOrigin, string targetResource, string category, string description)
    {
        OnKernelActivityDetected?.Invoke(new SourceTelemetryEvent
        {
            ProcessId = pid,
            ThreadId = 0,
            Stage = stage,
            HookedApiName = apiName,
            CallerModuleOrigin = callerOrigin,
            TargetResource = targetResource,
            CommandCategory = category,
            DecodedCommandText = description,
            PayloadSize = targetResource.Length
        });
    }

    public void Dispose()
    {
        if (_isDisposed) return;
        _isDisposed = true;

        _cts?.Cancel();
        _cts?.Dispose();

        try
        {
            if (_processWatcher != null)
            {
                _processWatcher.Stop();
                _processWatcher.Dispose();
                _processWatcher = null;
            }
        }
        catch { }

        try
        {
            if (_etwSession != null)
            {
                _etwSession.Stop();
                _etwSession.Dispose();
                _etwSession = null;
            }
        }
        catch { }

        _trackedPids.Clear();
    }
}
