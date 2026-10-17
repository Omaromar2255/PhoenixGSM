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
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using PhoenixOmniTrace.L24_SourceSentinel.Decoders;
using PhoenixOmniTrace.L24_SourceSentinel.Models;

namespace PhoenixOmniTrace.L24_SourceSentinel.Core;

public sealed class KernelAndUsbEtwInterceptor : IDisposable
{
    public static readonly Guid XhciProviderGuid = new("30E1D284-5D88-459C-83FD-6345B39B19EC");
    public static readonly Guid SerialClassExtensionV2Guid = new("EEE173EF-7ED2-45DE-9877-01C70A852FBD");
    public static readonly Guid SerialClassExtensionGuid = new("47BC9477-A8BA-452E-B951-4F2ED3593CF9");

    private TraceEventSession? _etwSession;
    private ManagementEventWatcher? _processWatcher;
    private CancellationTokenSource? _cts;
    private readonly ConcurrentDictionary<int, string> _trackedPids = new();
    private readonly ConcurrentDictionary<string, DateTime> _seenKernelEvents = new(StringComparer.OrdinalIgnoreCase);
    private bool _isDisposed;

    public event Action<SourceTelemetryEvent>? OnKernelActivityDetected;

    public bool IsWinUsbOrChildAdbActive { get; set; }

    public event Action<int, string>? OnChildAdbOrWinUsbDetected;

    public void StartMonitoring(int targetPid, string processName = "")
    {
        if (_isDisposed) return;

        if (targetPid > 0)
        {
            string name = string.IsNullOrWhiteSpace(processName) ? $"PID_{targetPid}" : processName;
            _trackedPids[targetPid] = name;
        }

        if (_cts != null) return;

        _cts = new CancellationTokenSource();
        var token = _cts.Token;

        // 1. مراقب العمليات الفرعية عبر WMI لضمان التقاط CommandLine حتى بدون صلاحيات أدمن كاملة
        Task.Run(() => StartWmiProcessWatcher(token), token);

        // 2. جلسة كيرنل و USB/Serial ETW لالتقاط أحداث الملفات، العمليات، وحزم USB/COM مباشرة من النواة
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

                        if (string.Equals(procName, "adb.exe", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(procName, "fastboot.exe", StringComparison.OrdinalIgnoreCase) ||
                            procName.StartsWith("filter-", StringComparison.OrdinalIgnoreCase) ||
                            procName.Equals("devcon.exe", StringComparison.OrdinalIgnoreCase))
                        {
                            IsWinUsbOrChildAdbActive = true;
                            OnChildAdbOrWinUsbDetected?.Invoke(childPid, procName);
                        }

                        string cmdLine = GetProcessCommandLine(childPid);
                        string key = $"PROC:{childPid}:{cmdLine}";
                        if (TryRecordTimedEvent(key, 2.0))
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
            or "scrcpy.exe" or "filter-x64.exe" or "filter-x86.exe" or "devcon.exe"
            or "inf-wizard.exe" or "fh_loader.exe" or "qsahara_server.exe" or "spd_dump.exe";
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
                BufferSizeMB = 32,
                CircularBufferMB = 32
            };

            _etwSession.EnableKernelProvider(
                KernelTraceEventParser.Keywords.FileIO |
                KernelTraceEventParser.Keywords.FileIOInit |
                KernelTraceEventParser.Keywords.Process
            );

            // تفعيل مزودات USB xHCI و Serial Class Extension في نفس الجلسة لالتقاط بايتات البورت والمودم و MTK
            try
            {
                ulong xhciKeywords = 0x40000000000385D5UL | 0x8000000000000000UL;
                ulong serialKeywords = 0x40000000000007E0UL | 0x8000000000000000UL;
                _etwSession.EnableProvider(XhciProviderGuid, TraceEventLevel.Verbose, matchAnyKeywords: xhciKeywords);
                _etwSession.EnableProvider(SerialClassExtensionV2Guid, TraceEventLevel.Verbose, matchAnyKeywords: serialKeywords);
                _etwSession.EnableProvider(SerialClassExtensionGuid, TraceEventLevel.Verbose, matchAnyKeywords: 0xC000000000000000UL);
            }
            catch { }

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

                        if (string.Equals(procName, "adb.exe", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(procName, "fastboot.exe", StringComparison.OrdinalIgnoreCase) ||
                            procName.StartsWith("filter-", StringComparison.OrdinalIgnoreCase) ||
                            procName.Equals("devcon.exe", StringComparison.OrdinalIgnoreCase))
                        {
                            IsWinUsbOrChildAdbActive = true;
                            OnChildAdbOrWinUsbDetected?.Invoke(childPid, procName);
                        }

                        string key = $"ETW_PROC:{childPid}:{cmdLine}";
                        if (TryRecordTimedEvent(key, 2.0))
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

            // 2. مراقبة ملفات البوت واللودر ونشاط البورتات في النواة
            _etwSession.Source.Kernel.FileIOCreate += data => ProcessKernelFileEvent(data.ProcessID, data.FileName ?? "", "Create/Open", 0);
            _etwSession.Source.Kernel.FileIORead += data => ProcessKernelFileEvent(data.ProcessID, data.FileName ?? "", "Read", data.IoSize);
            _etwSession.Source.Kernel.FileIOWrite += data => ProcessKernelFileEvent(data.ProcessID, data.FileName ?? "", "Write", data.IoSize);

            // 3. مراقبة الحزم الخام المرسلة عبر مزودي USB xHCI و Serial ETW
            _etwSession.Source.Dynamic.All += ProcessDynamicUsbAndSerialEtwEvent;

            _etwSession.Source.Process();
        }
        catch { }
    }

    private void ProcessDynamicUsbAndSerialEtwEvent(TraceEvent data)
    {
        try
        {
            if (data.ProviderGuid != XhciProviderGuid &&
                data.ProviderGuid != SerialClassExtensionV2Guid &&
                data.ProviderGuid != SerialClassExtensionGuid)
            {
                return;
            }

            byte[]? payload = null;
            string targetRes = data.ProviderGuid == XhciProviderGuid ? "USB_xHCI_Endpoint" : "COM_Serial_Endpoint";

            foreach (string name in data.PayloadNames)
            {
                object? val = data.PayloadByName(name);
                if (val == null) continue;

                if (payload == null && val is byte[] rawBytes && rawBytes.Length > 0)
                {
                    payload = rawBytes;
                }
                else if (val is string sVal && (sVal.Contains("VID_", StringComparison.OrdinalIgnoreCase) || sVal.Contains("COM", StringComparison.OrdinalIgnoreCase)))
                {
                    targetRes = sVal;
                }
            }

            if (payload == null || payload.Length == 0) return;

            var (cat, decoded) = RawPayloadClassifier.Classify("ETW_UsbSerialPayload", targetRes, 0, payload);
            if (cat == "Raw Binary / I/O Stream" || cat == "Control Operation") return;

            int pid = data.ProcessID;
            string procName = _trackedPids.TryGetValue(pid, out var pn) ? pn : (data.ProcessName ?? $"PID_{pid}");
            string dedupeKey = $"ETW_PAYLOAD:{cat}:{decoded}";

            if (TryRecordTimedEvent(dedupeKey, 1.0))
            {
                OnKernelActivityDetected?.Invoke(new SourceTelemetryEvent
                {
                    ProcessId = pid,
                    ThreadId = data.ThreadID,
                    Stage = SentinelStage.RawCommandExecution,
                    HookedApiName = "ETW_UsbSerialPayload",
                    CallerModuleOrigin = procName,
                    TargetResource = targetRes,
                    CommandCategory = cat,
                    DecodedCommandText = $"[{cat}] عبر ETW Kernel ({targetRes}): {decoded}",
                    RawPayloadHex = Convert.ToHexString(payload.AsSpan(0, Math.Min(payload.Length, 256))),
                    PayloadSize = payload.Length
                });
            }
        }
        catch { }
    }

    private void ProcessKernelFileEvent(int pid, string fileName, string ioOp, int ioSize)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(fileName)) return;
            bool isTracked = _trackedPids.ContainsKey(pid);

            if (isTracked && IsBootOrLoaderOrArchiveFile(fileName))
            {
                string key = $"FILEIO:{pid}:{fileName}";
                if (TryRecordTimedEvent(key, 5.0))
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
                        HookedApiName = $"Nt{ioOp}File (ETW Kernel)",
                        CallerModuleOrigin = procName,
                        TargetResource = fileName,
                        CommandCategory = category,
                        DecodedCommandText = $"رصد وصول كيرنلي ({ioOp}) لملف بوت/لودر/فلاش: [{Path.GetFileName(fileName)}] المسار: {fileName}",
                        PayloadSize = ioSize > 0 ? ioSize : fileName.Length
                    });
                }
            }
            else if (fileName.Contains("COM", StringComparison.OrdinalIgnoreCase) ||
                     fileName.Contains("cdcacm", StringComparison.OrdinalIgnoreCase) ||
                     fileName.Contains("ssudmdm", StringComparison.OrdinalIgnoreCase) ||
                     fileName.Contains("QCUSB", StringComparison.OrdinalIgnoreCase) ||
                     fileName.Contains("USBSER", StringComparison.OrdinalIgnoreCase) ||
                     fileName.Contains("vcom", StringComparison.OrdinalIgnoreCase) ||
                     (isTracked && fileName.Contains("USB", StringComparison.OrdinalIgnoreCase)))
            {
                if (fileName.Contains("WinUSB", StringComparison.OrdinalIgnoreCase) ||
                    fileName.Contains("AdbWinUsb", StringComparison.OrdinalIgnoreCase))
                {
                    IsWinUsbOrChildAdbActive = true;
                    OnChildAdbOrWinUsbDetected?.Invoke(pid, "WinUSB");
                }

                // السماح بتسجيل عمليات الكتابة (Write) الفعلية على البورتات مع نافذة منع تكرار قصيرة (1.5 ثانية)
                string key = ioOp == "Write"
                    ? $"DEVWRITE:{pid}:{fileName}:{ioSize}"
                    : $"DEVIO:{pid}:{fileName}";
                double windowSec = ioOp == "Write" ? 1.5 : 10.0;

                if (TryRecordTimedEvent(key, windowSec))
                {
                    string procName = _trackedPids.TryGetValue(pid, out var pn) ? pn : $"PID_{pid}";
                    string cat = ioOp == "Write" ? "Port / Modem I/O Write" : "Kernel Device Handle Activity";
                    string desc = ioOp == "Write"
                        ? $"إرسال بيانات كيرنلي ({ioSize} بايت) من [{procName}] إلى البورت/المقبض: {fileName}"
                        : $"نشاط كيرنلي ({ioOp}) على مقبض جهاز/بورت: {fileName}";

                    OnKernelActivityDetected?.Invoke(new SourceTelemetryEvent
                    {
                        ProcessId = pid,
                        ThreadId = 0,
                        Stage = ioOp == "Write" ? SentinelStage.RawCommandExecution : SentinelStage.PortAndDeviceRadar,
                        HookedApiName = $"KernelFileIO_{ioOp}",
                        CallerModuleOrigin = procName,
                        TargetResource = fileName,
                        CommandCategory = cat,
                        DecodedCommandText = desc,
                        PayloadSize = ioSize > 0 ? ioSize : fileName.Length
                    });
                }
            }
        }
        catch { }
    }

    private bool TryRecordTimedEvent(string key, double cooldownSeconds)
    {
        DateTime now = DateTime.UtcNow;
        if (_seenKernelEvents.TryGetValue(key, out var prev) && (now - prev).TotalSeconds < cooldownSeconds)
        {
            return false;
        }
        _seenKernelEvents[key] = now;
        return true;
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
