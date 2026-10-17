using System;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;

namespace PhoenixGSM.OmniTrace.Commands;

/// <summary>
/// Captured Android Shell Script details.
/// تفاصيل سكربت شل أندرويد الملتقط
/// </summary>
public class AndroidScriptInfo : EventArgs
{
    public string ScriptContent { get; set; } = string.Empty;
    public bool RunsFromLocalTmp { get; set; }
    public DateTime CapturedAt { get; set; }
}

/// <summary>
/// Captured Interactive Shell / RIL IPC command details.
/// تفاصيل أوامر الشل التفاعلي وقناة RIL IPC الملتقطة
/// </summary>
public class AndroidInteractiveCommandInfo : EventArgs
{
    public string CommandText { get; set; } = string.Empty;
    public byte[] RawBytes { get; set; } = Array.Empty<byte>();
    public string ProtocolTag { get; set; } = "ADB-INTERACTIVE-CMD";
    public string ActiveTool { get; set; } = string.Empty;
    public DateTime CapturedAt { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// Intercepts shell scripts and interactive RIL/AT commands sent via ADB / smart sockets.
/// يعترض نصوص شل وأوامر RIL التفاعلية المرسلة عبر ADB دون إسقاط أي بايت مع استبعاد حزم الملفات الثنائية
/// </summary>
public class AndroidShellStdinInterceptor : IDisposable
{
    private bool _isRunning;
    private StringBuilder _scriptBuffer;
    private readonly object _bufferLock = new object();
    private Timer? _flushTimer;

    private string _activeInteractiveTool = string.Empty;
    public bool IsInteractiveModeActive => !string.IsNullOrEmpty(_activeInteractiveTool);
    public string ActiveInteractiveTool => _activeInteractiveTool;

    public event EventHandler<AndroidScriptInfo>? OnAndroidShellScriptCaptured;
    public event EventHandler<AndroidInteractiveCommandInfo>? OnInteractiveCommandCaptured;

    public AndroidShellStdinInterceptor()
    {
        _scriptBuffer = new StringBuilder();
    }

    public void SetInteractiveSession(string toolOrCommand)
    {
        _activeInteractiveTool = toolOrCommand ?? string.Empty;
    }

    public void ClearInteractiveSession()
    {
        _activeInteractiveTool = string.Empty;
    }

    public void Start()
    {
        if (_isRunning) return;

        try
        {
            _flushTimer = new Timer(FlushBuffer, null, 500, 500);
            _isRunning = true;
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[AndroidShellStdinInterceptor] Start failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Intercepts an interactive packet sent to or received from the shell/tool.
    /// Rejects binary ELF sync chunks while capturing all genuine commands and RIL IPC hex strings.
    /// </summary>
    public bool InterceptInteractivePacket(
        ReadOnlySpan<byte> data,
        string direction,
        out string protocolTag,
        out string commandText)
    {
        protocolTag = "ADB-INTERACTIVE-CMD";
        commandText = string.Empty;

        if (data.Length == 0) return false;

        byte[] rawBytes = data.ToArray();
        string clean = Encoding.UTF8.GetString(rawBytes).Trim('\r', '\n', '\0', ' ');
        string cleanTrimmed = clean.Trim();

        if (PhoneCommandClassifier.IsCorruptedBinaryOrSyncNoise(cleanTrimmed))
        {
            return false;
        }

        bool isLongHex = cleanTrimmed.Length >= 12 &&
                         cleanTrimmed.Length % 2 == 0 &&
                         cleanTrimmed.All(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'));

        bool isRilIpc = isLongHex ||
                        cleanTrimmed.StartsWith("060100", StringComparison.OrdinalIgnoreCase) ||
                        cleanTrimmed.StartsWith("120D00", StringComparison.OrdinalIgnoreCase) ||
                        cleanTrimmed.StartsWith("514200", StringComparison.OrdinalIgnoreCase) ||
                        cleanTrimmed.StartsWith("516400", StringComparison.OrdinalIgnoreCase) ||
                        cleanTrimmed.StartsWith("116300", StringComparison.OrdinalIgnoreCase) ||
                        cleanTrimmed.StartsWith("06090004", StringComparison.OrdinalIgnoreCase) ||
                        cleanTrimmed.StartsWith("07170004", StringComparison.OrdinalIgnoreCase) ||
                        cleanTrimmed.StartsWith("3E257A2C", StringComparison.OrdinalIgnoreCase) ||
                        cleanTrimmed.StartsWith("AF6DBB85", StringComparison.OrdinalIgnoreCase) ||
                        cleanTrimmed.StartsWith("62E83911", StringComparison.OrdinalIgnoreCase) ||
                        cleanTrimmed.StartsWith("<<", StringComparison.Ordinal) ||
                        (rawBytes.Length >= 2 && rawBytes.Length <= 64 && rawBytes[0] == 0x11 && rawBytes[1] == 0x63);

        protocolTag = isRilIpc ? "ADB-RIL-IPC" : "ADB-INTERACTIVE-CMD";
        commandText = cleanTrimmed.Length > 0 ? cleanTrimmed : $"[{protocolTag}] ({rawBytes.Length}B): {Convert.ToHexString(rawBytes)}";

        var info = new AndroidInteractiveCommandInfo
        {
            CommandText = commandText,
            RawBytes = rawBytes,
            ProtocolTag = protocolTag,
            ActiveTool = _activeInteractiveTool,
            CapturedAt = DateTime.UtcNow
        };

        OnInteractiveCommandCaptured?.Invoke(this, info);
        return true;
    }

    public void InjectAdbStdin(byte[] data)
    {
        if (!_isRunning || data == null || data.Length == 0) return;

        try
        {
            if (IsInteractiveModeActive)
            {
                InterceptInteractivePacket(data, "OUT", out _, out _);
                return;
            }

            string content = Encoding.UTF8.GetString(data);
            if (PhoneCommandClassifier.IsCorruptedBinaryOrSyncNoise(content))
            {
                return;
            }

            lock (_bufferLock)
            {
                _scriptBuffer.Append(content);
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[AndroidShellStdinInterceptor] Injection failed: {ex.Message}");
        }
    }

    private void FlushBuffer(object? state)
    {
        try
        {
            string contentToProcess;
            lock (_bufferLock)
            {
                if (_scriptBuffer.Length == 0) return;
                
                contentToProcess = _scriptBuffer.ToString();
                _scriptBuffer.Clear();
            }

            if (!string.IsNullOrWhiteSpace(contentToProcess))
            {
                ProcessScript(contentToProcess);
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[AndroidShellStdinInterceptor] Flush failed: {ex.Message}");
        }
    }

    private void ProcessScript(string scriptContent)
    {
        try
        {
            var info = new AndroidScriptInfo
            {
                ScriptContent = scriptContent,
                CapturedAt = DateTime.UtcNow,
                RunsFromLocalTmp = scriptContent.Contains("/data/local/tmp", StringComparison.OrdinalIgnoreCase)
            };

            OnAndroidShellScriptCaptured?.Invoke(this, info);
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[AndroidShellStdinInterceptor] Processing failed: {ex.Message}");
        }
    }

    public void Stop()
    {
        if (!_isRunning) return;

        try
        {
            _flushTimer?.Dispose();
            _flushTimer = null;
            
            FlushBuffer(null);
            _isRunning = false;
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[AndroidShellStdinInterceptor] Stop failed: {ex.Message}");
        }
    }

    public void Dispose()
    {
        Stop();
        GC.SuppressFinalize(this);
    }
}
