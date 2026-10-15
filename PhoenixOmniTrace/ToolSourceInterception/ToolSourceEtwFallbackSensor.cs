using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace PhoenixGSM.OmniTrace.ToolSourceInterception;

/// <summary>
/// Non-intrusive ETW Kernel I/O Fallback Sensor.
/// Captures USB and Serial/COM I/O operations from target tool processes
/// without requiring DLL injection or modifying target memory.
/// حساس كيرنل ETW الاحتياطي الشامل للالتقاط بدون حقن
/// </summary>
public sealed class ToolSourceEtwFallbackSensor : IDisposable
{
    private readonly ToolSourceApiHookEngine _hookEngine;
    private readonly ConcurrentDictionary<int, string> _targetPids = new();
    private TraceEventSession? _session;
    private bool _isRunning;
    private long _eventsCaptured;

    public bool IsRunning => _isRunning;
    public long EventsCaptured => Interlocked.Read(ref _eventsCaptured);

    public ToolSourceEtwFallbackSensor(ToolSourceApiHookEngine hookEngine)
    {
        _hookEngine = hookEngine ?? throw new ArgumentNullException(nameof(hookEngine));
    }

    public void RegisterTargetPid(int pid, string toolName)
    {
        _targetPids[pid] = toolName;
    }

    public void UnregisterTargetPid(int pid)
    {
        _targetPids.TryRemove(pid, out _);
    }

    public void Start()
    {
        if (_isRunning) return;
        _isRunning = true;

        Task.Run(StartEtwSession);
    }

    public void Stop()
    {
        if (!_isRunning) return;
        _isRunning = false;

        try
        {
            if (_session != null)
            {
                _session.Stop();
                _session.Dispose();
                _session = null;
            }
        }
        catch { }

        _targetPids.Clear();
    }

    private void StartEtwSession()
    {
        try
        {
            if (TraceEventSession.IsElevated() != true)
            {
                Debug.WriteLine("[ToolSourceEtwFallbackSensor] Not running as administrator. Kernel ETW fallback skipped.");
                return;
            }

            string sessionName = $"PhoenixOmniTrace_ToolSource_ETW_{Process.GetCurrentProcess().Id}";
            _session = new TraceEventSession(sessionName)
            {
                BufferSizeMB = 8,
                CircularBufferMB = 8
            };
            
            // Enable File I/O keywords for COM/Serial handle write tracing
            _session.EnableKernelProvider(KernelTraceEventParser.Keywords.FileIO);

            _session.Source.Kernel.FileIOWrite += data =>
            {
                try
                {
                    if (_targetPids.IsEmpty) return;

                    int pid = data.ProcessID;
                    if (!_targetPids.TryGetValue(pid, out var toolName)) return;

                    string fileName = data.FileName ?? "";
                    if (string.IsNullOrWhiteSpace(fileName)) return;

                    // Check for serial/COM or USB device path targets
                    if (fileName.Contains("COM", StringComparison.OrdinalIgnoreCase) ||
                        fileName.Contains("USB", StringComparison.OrdinalIgnoreCase) ||
                        fileName.Contains("Modem", StringComparison.OrdinalIgnoreCase))
                    {
                        Interlocked.Increment(ref _eventsCaptured);

                        // Synthesize record from ETW file write event
                        byte[] syntheticPayload = Encoding.UTF8.GetBytes($"[ETW Write to {fileName} by PID {pid}]");
                        _hookEngine.IngestApiCall(pid, 0, toolName, "ETW_KernelIo", fileName, syntheticPayload);
                    }
                }
                catch { }
            };

            _session.Source.Process();
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[ToolSourceEtwFallbackSensor] ETW Session Startup: {ex.Message}");
            // Fail-open: continue operating via other interceptors
        }
    }

    public void Dispose()
    {
        Stop();
    }
}
