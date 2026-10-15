using System;
using System.Diagnostics;
using System.Text;
using System.Threading;
using System.Collections.Concurrent;

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
/// Intercepts shell scripts sent via ADB / smart sockets.
/// يعترض نصوص شل المرسلة عبر ADB
/// </summary>
public class AndroidShellStdinInterceptor : IDisposable
{
    private bool _isRunning;
    private StringBuilder _scriptBuffer;
    private readonly object _bufferLock = new object();
    private Timer? _flushTimer;

    // Event emitted when a script is captured / حدث عند التقاط سكربت
    public event EventHandler<AndroidScriptInfo>? OnAndroidShellScriptCaptured;

    public AndroidShellStdinInterceptor()
    {
        _scriptBuffer = new StringBuilder();
    }

    /// <summary>
    /// Starts the interceptor.
    /// بدء الاعتراض
    /// </summary>
    public void Start()
    {
        if (_isRunning) return;

        try
        {
            // Initialize flush timer (flush buffer every 500ms if idle)
            // تهيئة مؤقت التفريغ (كل 500 مللي ثانية)
            _flushTimer = new Timer(FlushBuffer, null, 500, 500);
            _isRunning = true;
        }
        catch (Exception ex)
        {
            // Fail-open pattern
            // نمط الفشل المفتوح
            Debug.WriteLine($"[AndroidShellStdinInterceptor] Start failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Injects captured ADB stdin bytes into the interceptor.
    /// حقن البيانات الملتقطة من ADB
    /// </summary>
    public void InjectAdbStdin(byte[] data)
    {
        if (!_isRunning || data == null || data.Length == 0) return;

        try
        {
            string content = Encoding.UTF8.GetString(data);
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

    /// <summary>
    /// Stops the interceptor.
    /// إيقاف الاعتراض
    /// </summary>
    public void Stop()
    {
        if (!_isRunning) return;

        try
        {
            _flushTimer?.Dispose();
            _flushTimer = null;
            
            // Final flush
            // تفريغ أخير
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
