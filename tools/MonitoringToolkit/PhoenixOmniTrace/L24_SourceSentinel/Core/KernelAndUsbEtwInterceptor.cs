using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
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

    // جدول ربط FileObject / FileKey باسم الملف الحقيقي في الكيرنل لالتقاط ملفات البوت واللودر في أحداث FileIORead و FileIOWrite حتى لو كان FileName فارغاً
    private readonly ConcurrentDictionary<ulong, string> _fileObjectToNameMap = new();
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

        Task.Run(() => StartWmiProcessWatcher(token), token);
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
                        string effectiveCmd = string.IsNullOrWhiteSpace(cmdLine) ? procName : cmdLine;
                        string key = $"PROC:{childPid}:{effectiveCmd}";
                        if (TryRecordTimedEvent(key, 1.5))
                        {
                            string cat = ClassifyChildProcessCategory(procName, effectiveCmd);
                            OnKernelActivityDetected?.Invoke(new SourceTelemetryEvent
                            {
                                ProcessId = childPid,
                                ThreadId = 0,
                                Stage = SentinelStage.RawCommandExecution,
                                HookedApiName = "NtCreateUserProcess / Win32_ProcessStart",
                                CallerModuleOrigin = $"{parentName} -> {procName}",
                                TargetResource = effectiveCmd,
                                CommandCategory = cat,
                                DecodedCommandText = $"تشغيل عملية فرعية من الأداة: [{procName}] سطر الأوامر: {effectiveCmd}",
                                PureCommandText = effectiveCmd,
                                PayloadSize = effectiveCmd.Length
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

    private static string ClassifyChildProcessCategory(string procName, string cmdLine)
    {
        string combined = $"{procName} {cmdLine}".ToLowerInvariant();
        if (combined.Contains("0e8d") || combined.Contains("mtk") || combined.Contains("brom") || combined.Contains("sp_flash"))
            return "MediaTek BROM / Filter Execution";
        if (combined.Contains("05c6") || combined.Contains("9008") || combined.Contains("fh_loader") || combined.Contains("qsahara"))
            return "Qualcomm EDL / Sahara Execution";
        if (combined.Contains("irecovery") || combined.Contains("idevice") || combined.Contains("iproxy") || combined.Contains("gaster"))
            return "Apple iOS CLI Execution";
        if (combined.Contains("7z") || combined.Contains("unzip") || combined.Contains("tar") || combined.Contains("lz4") || combined.Contains("simg2img"))
            return "Archive / Unpack Execution";
        if (combined.Contains("openssl") || combined.Contains("decrypt"))
            return "Crypto / Decryption Execution";
        return "Child Process Execution";
    }

    private static bool IsKnownToolChild(string procName)
    {
        string lower = procName.ToLowerInvariant();
        return lower is "adb.exe" or "fastboot.exe" or "7z.exe" or "7za.exe" or "unzip.exe" or "tar.exe"
            or "simg2img.exe" or "make_ext4fs.exe" or "python.exe" or "cmd.exe" or "powershell.exe"
            or "scrcpy.exe" or "filter-x64.exe" or "filter-x86.exe" or "devcon.exe"
            or "inf-wizard.exe" or "fh_loader.exe" or "qsahara_server.exe" or "spd_dump.exe"
            or "irecovery.exe" or "ideviceinfo.exe" or "ideviceactivation.exe" or "iproxy.exe"
            or "openssl.exe" or "curl.exe" or "wget.exe";
    }

    private static string GetProcessCommandLine(int pid)
    {
        try
        {
            if (!OperatingSystem.IsWindows()) return string.Empty;
            string? fastCmd = PhoenixGSM.OmniTrace.Sensors.SmartFilePushArchiver.TryGetProcessCommandLineFast(pid, out _);
            if (!string.IsNullOrWhiteSpace(fastCmd)) return fastCmd;

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
                KernelTraceEventParser.Keywords.DiskFileIO |
                KernelTraceEventParser.Keywords.Process
            );

            try
            {
                ulong xhciKeywords = 0x40000000000385D5UL | 0x8000000000000000UL;
                ulong serialKeywords = 0x40000000000007E0UL | 0x8000000000000000UL;
                _etwSession.EnableProvider(XhciProviderGuid, TraceEventLevel.Verbose, matchAnyKeywords: xhciKeywords);
                _etwSession.EnableProvider(SerialClassExtensionV2Guid, TraceEventLevel.Verbose, matchAnyKeywords: serialKeywords);
                _etwSession.EnableProvider(SerialClassExtensionGuid, TraceEventLevel.Verbose, matchAnyKeywords: 0xC000000000000000UL);
            }
            catch { }

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
                        if (TryRecordTimedEvent(key, 1.5))
                        {
                            string cat = ClassifyChildProcessCategory(procName, cmdLine);
                            OnKernelActivityDetected?.Invoke(new SourceTelemetryEvent
                            {
                                ProcessId = childPid,
                                ThreadId = 0,
                                Stage = SentinelStage.RawCommandExecution,
                                HookedApiName = "ETW_ProcessStart",
                                CallerModuleOrigin = $"{parentName} -> {procName}",
                                TargetResource = cmdLine,
                                CommandCategory = cat,
                                DecodedCommandText = $"تشغيل عملية فرعية بنواة ويندوز: [{procName}] سطر الأوامر: {cmdLine}",
                                PureCommandText = cmdLine,
                                PayloadSize = cmdLine.Length
                            });
                        }
                    }
                }
                catch { }
            };

            // حفظ العلاقة بين FileObject/FileKey واسم الملف الحقيقي في الكيرنل
            _etwSession.Source.Kernel.FileIOName += data =>
            {
                if (!string.IsNullOrWhiteSpace(data.FileName) && data.FileKey != 0)
                    _fileObjectToNameMap[data.FileKey] = data.FileName;
            };

            _etwSession.Source.Kernel.FileIOFileCreate += data =>
            {
                if (!string.IsNullOrWhiteSpace(data.FileName) && data.FileKey != 0)
                    _fileObjectToNameMap[data.FileKey] = data.FileName;
            };

            _etwSession.Source.Kernel.FileIOCreate += data =>
            {
                string fName = data.FileName ?? "";
                if (!string.IsNullOrWhiteSpace(fName) && data.FileObject != 0)
                    _fileObjectToNameMap[data.FileObject] = fName;
                ProcessKernelFileEvent(data.ProcessID, fName, "Create/Open", 0);
            };

            _etwSession.Source.Kernel.FileIORead += data =>
            {
                string fName = !string.IsNullOrWhiteSpace(data.FileName)
                    ? data.FileName
                    : (_fileObjectToNameMap.TryGetValue(data.FileObject, out var mapped) ? mapped : (_fileObjectToNameMap.TryGetValue(data.FileKey, out var mappedKey) ? mappedKey : ""));
                ProcessKernelFileEvent(data.ProcessID, fName, "Read", data.IoSize);
            };

            _etwSession.Source.Kernel.FileIOWrite += data =>
            {
                string fName = !string.IsNullOrWhiteSpace(data.FileName)
                    ? data.FileName
                    : (_fileObjectToNameMap.TryGetValue(data.FileObject, out var mapped) ? mapped : (_fileObjectToNameMap.TryGetValue(data.FileKey, out var mappedKey) ? mappedKey : ""));
                ProcessKernelFileEvent(data.ProcessID, fName, "Write", data.IoSize);
            };

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
                else if (val is string sVal &&
                         (sVal.Contains("VID_", StringComparison.OrdinalIgnoreCase) ||
                          sVal.Contains("COM", StringComparison.OrdinalIgnoreCase) ||
                          sVal.Contains("0E8D", StringComparison.OrdinalIgnoreCase)))
                {
                    targetRes = sVal;
                }
            }

            if (payload == null || payload.Length == 0) return;

            var (cat, decoded) = RawPayloadClassifier.Classify("ETW_UsbSerialPayload", targetRes, 0, payload);
            if (cat == "Control Operation") return;

            if (cat == "Raw Binary / I/O Stream" &&
                (targetRes.Contains("0E8D", StringComparison.OrdinalIgnoreCase) ||
                 targetRes.Contains("MTK", StringComparison.OrdinalIgnoreCase) ||
                 targetRes.Contains("cdcacm", StringComparison.OrdinalIgnoreCase)))
            {
                cat = "MediaTek USB / BROM Raw Stream";
            }
            else if (cat == "Raw Binary / I/O Stream")
            {
                return;
            }

            int pid = data.ProcessID;
            string procName = _trackedPids.TryGetValue(pid, out var pn) ? pn : (data.ProcessName ?? $"PID_{pid}");
            string dedupeKey = $"ETW_PAYLOAD:{cat}:{decoded}";

            if (TryRecordTimedEvent(dedupeKey, 0.8))
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
                    PureCommandText = decoded,
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
            bool isInToolOrTempFolder = fileName.Contains("UnlockTool", StringComparison.OrdinalIgnoreCase) ||
                                        fileName.Contains("\\Temp\\", StringComparison.OrdinalIgnoreCase) ||
                                        fileName.Contains("Chimera", StringComparison.OrdinalIgnoreCase) ||
                                        fileName.Contains("3uTools", StringComparison.OrdinalIgnoreCase);

            if ((isTracked || isInToolOrTempFolder) && IsBootOrLoaderOrArchiveFile(fileName))
            {
                string key = $"FILEIO:{pid}:{fileName}";
                if (TryRecordTimedEvent(key, 3.0))
                {
                    string procName = _trackedPids.TryGetValue(pid, out var pn) ? pn : $"PID_{pid}";
                    string ext = Path.GetExtension(fileName).ToLowerInvariant();
                    string category = ext is ".zip" or ".7z" or ".tar" or ".lz4"
                        ? "Firmware / Archive Extraction"
                        : "Boot Loader / Firmware File Access";

                    string savedFile = string.Empty;
                    long savedLen = 0;

                    // حفظ نسخة كاملة من ملف البوت/اللودر/الفيرموير تلقائياً عند وصول الكيرنل إليه!
                    if (L24FileArchiver.TryArchiveDiscoveredFile(fileName, $"KernelETW_{ioOp} ({procName})", out string sPath, out long sSize, out _))
                    {
                        savedFile = sPath;
                        savedLen = sSize;
                    }

                    string saveNote = !string.IsNullOrWhiteSpace(savedFile)
                        ? $" | 💾 تم حفظ نسخة في: [{Path.GetFileName(savedFile)}] ({savedLen:N0} بايت)"
                        : "";

                    OnKernelActivityDetected?.Invoke(new SourceTelemetryEvent
                    {
                        ProcessId = pid,
                        ThreadId = 0,
                        Stage = SentinelStage.LocalFilePreparation,
                        HookedApiName = $"Nt{ioOp}File (ETW Kernel)",
                        CallerModuleOrigin = procName,
                        TargetResource = !string.IsNullOrWhiteSpace(savedFile) ? savedFile : fileName,
                        CommandCategory = category,
                        DecodedCommandText = $"رصد وصول كيرنلي ({ioOp}) لملف بوت/لودر/فلاش: [{Path.GetFileName(fileName)}] المسار: {fileName}{saveNote}",
                        PureCommandText = fileName,
                        SavedFilePath = savedFile,
                        PayloadSize = (int)(savedLen > 0 ? Math.Min(savedLen, int.MaxValue) : (ioSize > 0 ? ioSize : fileName.Length))
                    });
                }
            }
            else if (fileName.Contains("COM", StringComparison.OrdinalIgnoreCase) ||
                     fileName.Contains("cdcacm", StringComparison.OrdinalIgnoreCase) ||
                     fileName.Contains("0e8d", StringComparison.OrdinalIgnoreCase) ||
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

                string key = ioOp == "Write"
                    ? $"DEVWRITE:{pid}:{fileName}:{ioSize}"
                    : $"DEVIO:{pid}:{fileName}";
                double windowSec = ioOp == "Write" ? 0.8 : 8.0;

                if (TryRecordTimedEvent(key, windowSec))
                {
                    string procName = _trackedPids.TryGetValue(pid, out var pn) ? pn : $"PID_{pid}";
                    bool isMtkHandle = fileName.Contains("cdcacm", StringComparison.OrdinalIgnoreCase) ||
                                       fileName.Contains("vcom", StringComparison.OrdinalIgnoreCase) ||
                                       fileName.Contains("0e8d", StringComparison.OrdinalIgnoreCase);

                    string cat = ioOp == "Write"
                        ? (isMtkHandle ? "MediaTek BROM / VCOM Port Write" : "Port / Modem I/O Write")
                        : (isMtkHandle ? "MediaTek BROM / VCOM Handle Activity" : "Kernel Device Handle Activity");

                    string desc = ioOp == "Write"
                        ? $"إرسال بيانات كيرنلي ({ioSize} بايت) من [{procName}] إلى المنفذ: {fileName}"
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
                        PureCommandText = $"{ioOp} {fileName} ({ioSize}B)",
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

        return ext is ".mbn" or ".elf" or ".bin" or ".da" or ".auth" or ".sca" or ".pit" or ".qcn" or ".xqcn"
                   or ".pac" or ".ofp" or ".ops" or ".tar" or ".md5" or ".7z" or ".zip" or ".lz4"
                   or ".img" or ".shsh2" or ".im4p" or ".img4" or ".plist"
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
            PureCommandText = targetResource,
            PayloadSize = targetResource.Length
        });
    }

    public void StopMonitoring()
    {
        try
        {
            _cts?.Cancel();
            _cts?.Dispose();
        }
        catch { }
        _cts = null;

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
        _seenKernelEvents.Clear();
        _fileObjectToNameMap.Clear();
    }

    public void Dispose()
    {
        if (_isDisposed) return;
        _isDisposed = true;
        StopMonitoring();
    }
}
