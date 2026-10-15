using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PhoenixGSM.OmniTrace.ToolSourceInterception;

/// <summary>
/// In-Process API Hook Coordinator and IPC Server for GSM servicing tools.
/// Captures DeviceIoControl, WriteFile, and libusb calls at the point of origin.
/// محرك إدارة واعتراض دوال Win32 API واستقبالها عبر IPC
/// </summary>
public sealed class ToolSourceApiHookEngine : IDisposable
{
    public const string DefaultPipeName = "PhoenixOmniTrace_ToolSourcePipe";

    private readonly ConcurrentDictionary<int, string> _hookedToolNames = new();
    private CancellationTokenSource? _cts;
    private Task? _pipeServerTask;
    private bool _isRunning;
    private long _callsCaptured;

    public bool IsRunning => _isRunning;
    public long CallsCaptured => Interlocked.Read(ref _callsCaptured);

    public event Action<ToolSourceCommandRecord>? OnCommandCaptured;

    public void Start(string pipeName = DefaultPipeName)
    {
        if (_isRunning) return;
        _isRunning = true;
        _cts = new CancellationTokenSource();
        _pipeServerTask = Task.Run(() => RunIpcServerLoop(pipeName, _cts.Token), _cts.Token);
    }

    public void Stop()
    {
        if (!_isRunning) return;
        _isRunning = false;
        _cts?.Cancel();
        _hookedToolNames.Clear();
    }

    public void RegisterToolProcess(int pid, string toolName)
    {
        _hookedToolNames[pid] = toolName;
    }

    public void UnregisterToolProcess(int pid)
    {
        _hookedToolNames.TryRemove(pid, out _);
    }

    /// <summary>
    /// Ingests a raw API call captured from a tool process.
    /// Can be called from the Named Pipe IPC listener or direct in-process hooks.
    /// </summary>
    public ToolSourceCommandRecord IngestApiCall(
        int pid,
        int parentPid,
        string toolName,
        string apiName,
        string endpoint,
        byte[] payload)
    {
        Interlocked.Increment(ref _callsCaptured);

        if (string.IsNullOrWhiteSpace(toolName))
        {
            if (_hookedToolNames.TryGetValue(pid, out var cachedName))
            {
                toolName = cachedName;
            }
            else
            {
                try { toolName = Process.GetProcessById(pid).ProcessName + ".exe"; }
                catch { toolName = "Tool.exe"; }
            }
        }

        // 1. Try MTK BROM / Preloader Parser
        if (MtkBromSourceInterceptor.TryParseMtkCommand(payload, toolName, pid, parentPid, endpoint, apiName, out var mtkRec))
        {
            OnCommandCaptured?.Invoke(mtkRec!);
            return mtkRec!;
        }

        // 2. Try Samsung Odin / Loke Protocol Parser
        if (OdinSourceInterceptor.TryParseOdinCommand(payload, toolName, pid, parentPid, endpoint, apiName, out var odinRec))
        {
            OnCommandCaptured?.Invoke(odinRec!);
            return odinRec!;
        }

        // 3. Try MTP / PTP Parser
        if (MtpSourceInterceptor.TryParseMtpCommand(payload, toolName, pid, parentPid, endpoint, apiName, out var mtpRec))
        {
            OnCommandCaptured?.Invoke(mtpRec!);
            return mtpRec!;
        }

        // 4. Try Port / COM / Serial AT Parser
        if (PortSourceInterceptor.TryParsePortCommand(payload, toolName, pid, parentPid, endpoint, apiName, out var portRec))
        {
            OnCommandCaptured?.Invoke(portRec!);
            return portRec!;
        }

        // 5. Universal Fallback (Zero-Drop Guarantee)
        string shortAscii = Encoding.ASCII.GetString(payload.Length > 64 ? payload[..64] : payload).Trim();
        var fallbackRec = new ToolSourceCommandRecord
        {
            Timestamp = DateTime.UtcNow,
            Mode = ToolSourceMode.Universal,
            ToolName = toolName,
            ProcessId = pid,
            ParentProcessId = parentPid,
            PureCommand = $"TOOL_API_{apiName}: {payload.Length}B -> {endpoint}",
            RawCommand = shortAscii,
            InterceptMechanism = apiName,
            TargetEndpoint = string.IsNullOrWhiteSpace(endpoint) ? "Device Handle" : endpoint,
            RawPayload = payload,
            PayloadHex = ToolSourceCommandRecord.FormatHexDump(payload),
            PayloadAscii = shortAscii,
            TechnicalDetails = $"Direct Tool API Call:\nTool: {toolName} (PID {pid})\nAPI: {apiName}\nTarget: {endpoint}\nSize: {payload.Length} bytes",
            RiskLevel = "INFO",
            Status = "CAPTURED_AT_SOURCE"
        };

        OnCommandCaptured?.Invoke(fallbackRec);
        return fallbackRec;
    }

    private async Task RunIpcServerLoop(string pipeName, CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                using var server = new NamedPipeServerStream(
                    pipeName,
                    PipeDirection.In,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Message,
                    PipeOptions.Asynchronous);

                await server.WaitForConnectionAsync(token);

                _ = Task.Run(() => HandleClientConnection(server, token), token);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                Debug.WriteLine($"[ToolSourceApiHookEngine] Pipe Server Error: {ex.Message}");
                await Task.Delay(1000, token);
            }
        }
    }

    private void HandleClientConnection(NamedPipeServerStream pipe, CancellationToken token)
    {
        using var reader = new BinaryReader(pipe, Encoding.UTF8, leaveOpen: false);
        try
        {
            while (pipe.IsConnected && !token.IsCancellationRequested)
            {
                int pid = reader.ReadInt32();
                int parentPid = reader.ReadInt32();
                string toolName = reader.ReadString();
                string apiName = reader.ReadString();
                string endpoint = reader.ReadString();
                int payloadLen = reader.ReadInt32();
                byte[] payload = reader.ReadBytes(payloadLen);

                IngestApiCall(pid, parentPid, toolName, apiName, endpoint, payload);
            }
        }
        catch (EndOfStreamException) { /* Client disconnected cleanly */ }
        catch (Exception ex)
        {
            Debug.WriteLine($"[ToolSourceApiHookEngine] Client Error: {ex.Message}");
        }
    }

    public void Dispose()
    {
        Stop();
    }
}
