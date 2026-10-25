using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using PhoenixOmniTrace.L24_SourceSentinel.Models;

namespace PhoenixOmniTrace.L24_SourceSentinel.Core;

public sealed partial class LiveHeapCommandHunter : IDisposable
{
    private CancellationTokenSource? _cts;
    private readonly ConcurrentDictionary<int, string> _monitoredPids = new();
    private readonly ConcurrentDictionary<int, string> _childAdbPids = new();
    private readonly ConcurrentDictionary<string, DateTime> _localCooldown = new(StringComparer.OrdinalIgnoreCase);

    // 1. ذاكرة البصمة للقطع (Dirty-Chunk Hash Cache) لمنع إعادة فحص نفس الشريحة غير المتغيرة كل دورة
    private readonly ConcurrentDictionary<long, ulong> _chunkHashCache = new();

    // 2. قائمة النصوص الثابتة الأولية (Baseline Snapshot) لعزل أوامر وضع الخمول (Idle)
    private readonly ConcurrentDictionary<string, byte> _idleBaselineStrings = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<int, bool> _pidBaselineCompleted = new();
    private readonly ConcurrentDictionary<long, byte> _carvedLoaderAddresses = new();

    private volatile bool _isWinUsbOrChildAdbActive;
    private volatile bool _isRamHunterEnabled = true;
    private volatile bool _suppressIdleStaticBaseline = true;
    private volatile bool _scanDynamicHeapOnly = false;
    private volatile bool _enableInMemoryLoaderCarving = true;
    private volatile bool _isCapturingBaselineNow;
    private int _parentScanCycleCounter;

    public event Action<SourceTelemetryEvent>? OnCommandCaptured;

    public L24DiscoveryMode DiscoveryMode { get; set; } = L24DiscoveryMode.FullRamDiscovery;
    public Func<L24CommandGroup, bool>? IsCategoryEnabled { get; set; }
    public bool ExcludeUrls { get; set; } = false;

    public bool IsRamHunterEnabled
    {
        get => _isRamHunterEnabled;
        set => _isRamHunterEnabled = value;
    }

    public bool SuppressIdleStaticBaseline
    {
        get => _suppressIdleStaticBaseline;
        set
        {
            if (_suppressIdleStaticBaseline != value)
            {
                _suppressIdleStaticBaseline = value;
                _chunkHashCache.Clear();
            }
        }
    }

    public bool ScanDynamicHeapOnly
    {
        get => _scanDynamicHeapOnly;
        set
        {
            if (_scanDynamicHeapOnly != value)
            {
                _scanDynamicHeapOnly = value;
                _chunkHashCache.Clear();
            }
        }
    }

    public bool EnableInMemoryLoaderCarving
    {
        get => _enableInMemoryLoaderCarving;
        set => _enableInMemoryLoaderCarving = value;
    }

    public int BaselineStringsCount => _idleBaselineStrings.Count;

    public void CaptureCurrentRamAsIdleBaseline()
    {
        _isCapturingBaselineNow = true;
        _chunkHashCache.Clear();
        Task.Run(() =>
        {
            try
            {
                foreach (var target in _monitoredPids)
                {
                    ScanProcessHeapAndBuffers(target.Key, target.Value, CancellationToken.None, recordAsBaselineOnly: true);
                    _pidBaselineCompleted[target.Key] = true;
                }
            }
            catch { }
            finally
            {
                _isCapturingBaselineNow = false;
            }
        });
    }

    public void ClearIdleBaseline()
    {
        _idleBaselineStrings.Clear();
        _pidBaselineCompleted.Clear();
        _chunkHashCache.Clear();
    }

    public bool IsGroupEnabled(L24CommandGroup group)
    {
        return IsCategoryEnabled == null || IsCategoryEnabled(group);
    }

    public bool IsWinUsbOrChildAdbActive
    {
        get => _isWinUsbOrChildAdbActive;
        set => _isWinUsbOrChildAdbActive = value;
    }

    public void RegisterChildAdbProcess(int childPid, string processName)
    {
        _childAdbPids[childPid] = processName;
        _isWinUsbOrChildAdbActive = true;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint PROCESS_VM_READ = 0x0010;
    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_PRIVATE = 0x20000;
    private const uint MEM_IMAGE = 0x1000000;
    private const uint PAGE_READONLY = 0x02;
    private const uint PAGE_READWRITE = 0x04;
    private const uint PAGE_WRITECOPY = 0x08;
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_GUARD = 0x100;
    private const uint PAGE_NOACCESS = 0x01;

    public void StartHunting(int targetPid, string processName)
    {
        if (targetPid > 0)
        {
            _monitoredPids[targetPid] = processName;
        }

        if (_cts != null) return;
        _cts = new CancellationTokenSource();
        var token = _cts.Token;

        Task.Run(async () =>
        {
            while (!token.IsCancellationRequested)
            {
                if (!_isRamHunterEnabled || DiscoveryMode == L24DiscoveryMode.ExecutedOnly || _isCapturingBaselineNow)
                {
                    await Task.Delay(400, token).ConfigureAwait(false);
                    continue;
                }

                // 1. فحص العمليات الفرعية السريعة (adb.exe, fastboot.exe, cmd.exe, إلخ) فوراً
                foreach (var kvp in _childAdbPids)
                {
                    if (token.IsCancellationRequested) break;
                    try
                    {
                        using var proc = Process.GetProcessById(kvp.Key);
                        if (!proc.HasExited)
                            ScanProcessHeapAndBuffers(kvp.Key, kvp.Value, token, recordAsBaselineOnly: false);
                    }
                    catch
                    {
                        _childAdbPids.TryRemove(kvp.Key, out _);
                    }
                }

                // 2. فحص العملية الأم
                _parentScanCycleCounter++;
                foreach (var target in _monitoredPids)
                {
                    if (token.IsCancellationRequested) break;
                    try
                    {
                        using var proc = Process.GetProcessById(target.Key);
                        if (!proc.HasExited)
                        {
                            bool isFirstBaselinePass = _suppressIdleStaticBaseline && !_pidBaselineCompleted.ContainsKey(target.Key);
                            ScanProcessHeapAndBuffers(target.Key, target.Value, token, recordAsBaselineOnly: isFirstBaselinePass);
                            if (isFirstBaselinePass)
                            {
                                _pidBaselineCompleted[target.Key] = true;
                            }
                        }
                    }
                    catch
                    {
                        _monitoredPids.TryRemove(target.Key, out _);
                    }
                }

                await Task.Delay(350, token).ConfigureAwait(false);
            }
        }, token);
    }

    private void ScanProcessHeapAndBuffers(int pid, string processName, CancellationToken token, bool recordAsBaselineOnly)
    {
        if (pid <= 0 || (!_isRamHunterEnabled && !recordAsBaselineOnly) || DiscoveryMode == L24DiscoveryMode.ExecutedOnly) return;
        IntPtr hProc = IntPtr.Zero;
        try
        {
            hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
            if (hProc == IntPtr.Zero) return;

            long currentAddr = 0x10000;
            long maxAddr = Environment.Is64BitOperatingSystem ? 0x7FFFFFFEFFFFL : 0x7FFF0000L;
            uint mbiSize = (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();
            const int chunkSize = 65536;
            const int overlap = 512;
            byte[] buffer = ArrayPool<byte>.Shared.Rent(chunkSize + overlap);

            try
            {
                while (currentAddr < maxAddr && !token.IsCancellationRequested)
                {
                    if (VirtualQueryEx(hProc, (IntPtr)currentAddr, out var mbi, mbiSize) == 0)
                        break;

                    uint prot = mbi.Protect & 0xFF;
                    bool isExecutableCodeSection = (prot == PAGE_EXECUTE_READ) || (mbi.Type == MEM_IMAGE && prot == PAGE_READONLY);

                    bool isScannable;
                    if (_scanDynamicHeapOnly)
                    {
                        isScannable = mbi.State == MEM_COMMIT &&
                                      mbi.Type == MEM_PRIVATE &&
                                      (mbi.Protect & PAGE_GUARD) == 0 &&
                                      (prot == PAGE_READWRITE || prot == PAGE_EXECUTE_READWRITE || prot == PAGE_WRITECOPY);
                    }
                    else
                    {
                        isScannable = mbi.State == MEM_COMMIT &&
                                      (mbi.Protect & PAGE_GUARD) == 0 &&
                                      prot != PAGE_NOACCESS &&
                                      (prot == PAGE_READWRITE || prot == PAGE_EXECUTE_READWRITE ||
                                       prot == PAGE_WRITECOPY || prot == PAGE_READONLY ||
                                       (!_suppressIdleStaticBaseline && prot == PAGE_EXECUTE_READ));
                    }

                    long regionSize = mbi.RegionSize.ToInt64();
                    if (isScannable && regionSize > 0 && regionSize <= 64 * 1024 * 1024)
                    {
                        long offset = 0;
                        while (offset < regionSize && !token.IsCancellationRequested)
                        {
                            int toRead = (int)Math.Min(chunkSize + overlap, regionSize - offset);
                            long chunkAddr = currentAddr + offset;
                            if (ReadProcessMemory(hProc, (IntPtr)chunkAddr, buffer, toRead, out int bytesRead) && bytesRead > 0)
                            {
                                ulong chunkHash = ComputeFastFnv1a64(buffer, bytesRead);
                                long cacheKey = ((long)pid << 44) ^ chunkAddr;

                                if (!recordAsBaselineOnly && _chunkHashCache.TryGetValue(cacheKey, out ulong prevHash) && prevHash == chunkHash)
                                {
                                    offset += chunkSize;
                                    continue;
                                }
                                _chunkHashCache[cacheKey] = chunkHash;

                                InspectBinaryAndTextBuffer(pid, processName, chunkAddr, buffer, bytesRead, isExecutableCodeSection, recordAsBaselineOnly);
                            }
                            offset += chunkSize;
                        }
                    }

                    long nextAddr = mbi.BaseAddress.ToInt64() + Math.Max(regionSize, 4096);
                    if (nextAddr <= currentAddr) break;
                    currentAddr = nextAddr;
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }
        finally
        {
            if (hProc != IntPtr.Zero)
                CloseHandle(hProc);
        }
    }

    private static ulong ComputeFastFnv1a64(byte[] buf, int len)
    {
        ulong hash = 14695981039346656037UL;
        int step = len > 4096 ? 4 : 1;
        for (int i = 0; i < len; i += step)
        {
            hash ^= buf[i];
            hash *= 1099511628211UL;
        }
        return hash;
    }

    private void EmitDiscovered(
        int pid,
        string processName,
        long memAddress,
        SentinelStage stage,
        string category,
        string desc,
        string rawValue,
        string targetRes,
        bool isAlreadyHex = false,
        string savedFilePath = "")
    {
        string cooldownKey = $"{pid}:{category}:{rawValue}";
        DateTime now = DateTime.UtcNow;
        if (_localCooldown.TryGetValue(cooldownKey, out var lastSeen) && (now - lastSeen).TotalSeconds < 2.5)
            return;
        _localCooldown[cooldownKey] = now;

        byte[] rawBytes = Encoding.UTF8.GetBytes(rawValue);
        OnCommandCaptured?.Invoke(new SourceTelemetryEvent
        {
            ProcessId = pid,
            ThreadId = 0,
            Stage = stage,
            HookedApiName = "LiveRAM_UniversalInterceptor",
            CallerModuleOrigin = $"{processName} [RAM @ 0x{memAddress:X8}]",
            TargetResource = targetRes,
            CommandCategory = category,
            DecodedCommandText = desc,
            PureCommandText = rawValue,
            SavedFilePath = savedFilePath,
            MemoryAddress = memAddress,
            RawPayloadHex = isAlreadyHex ? rawValue : Convert.ToHexString(rawBytes),
            PayloadSize = rawBytes.Length
        });
    }

    public void StopHunting()
    {
        try
        {
            _cts?.Cancel();
            _cts?.Dispose();
        }
        catch { }
        _cts = null;
        _monitoredPids.Clear();
        _childAdbPids.Clear();
        _localCooldown.Clear();
        _chunkHashCache.Clear();
        _isWinUsbOrChildAdbActive = false;
    }

    public void Dispose() => StopHunting();
}
