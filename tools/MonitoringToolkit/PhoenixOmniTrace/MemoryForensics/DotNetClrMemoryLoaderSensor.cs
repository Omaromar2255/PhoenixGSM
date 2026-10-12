using System;
using System.Diagnostics;
using System.Diagnostics.Tracing;

namespace PhoenixGSM.OmniTrace.MemoryForensics;

/// <summary>
/// Represents a dynamically loaded .NET assembly.
/// يمثل تجميعة .NET تم تحميلها ديناميكياً.
/// </summary>
public record DotNetDynamicAssembly(
    int ProcessId,
    long ModuleId,
    string AssemblyName,
    bool IsInMemory,
    DateTime Timestamp
);

/// <summary>
/// Monitors ETW for .NET runtime assembly loads to detect in-memory reflection (Assembly.Load(byte[])).
/// يراقب أحداث ETW لعمليات تحميل تجميعات .NET لاكتشاف التحميل الانعكاسي في الذاكرة.
/// </summary>
public class DotNetClrMemoryLoaderSensor : EventListener, IDisposable
{
    private static readonly Guid ClrRuntimeProviderGuid = new Guid("E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4");
    private const EventKeywords LoaderKeyword = (EventKeywords)0x8;
    
    // ModuleLoad Event ID for CLR ETW
    private const int ModuleLoadEventId = 152; 

    private bool _isRunning;

    public event Action<DotNetDynamicAssembly>? OnDynamicAssemblyLoaded;

    /// <summary>
    /// Starts listening to CLR ETW events for memory loads.
    /// يبدأ الاستماع إلى أحداث CLR ETW لتحميلات الذاكرة.
    /// </summary>
    public void Start()
    {
        try
        {
            if (_isRunning) return;
            _isRunning = true;
            // The EventListener base class handles provider enabling inside OnEventSourceCreated
            // الفئة الأساسية تتعامل مع تفعيل المزود
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ClrSensor] Start failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Stops the sensor and disables ETW listening.
    /// يوقف المستشعر ويعطل الاستماع.
    /// </summary>
    public void Stop()
    {
        try
        {
            if (!_isRunning) return;
            _isRunning = false;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ClrSensor] Stop failed: {ex.Message}");
        }
    }

    protected override void OnEventSourceCreated(EventSource eventSource)
    {
        try
        {
            if (eventSource.Guid == ClrRuntimeProviderGuid)
            {
                EnableEvents(eventSource, EventLevel.Informational, LoaderKeyword);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ClrSensor] OnEventSourceCreated failed: {ex.Message}");
        }
    }

    protected override void OnEventWritten(EventWrittenEventArgs eventData)
    {
        try
        {
            if (!_isRunning) return;

            if (eventData.EventId == ModuleLoadEventId)
            {
                long moduleId = 0;
                string modulePath = string.Empty;
                string assemblyName = "UnknownAssembly";

                if (eventData.Payload != null && eventData.Payload.Count >= 4)
                {
                    moduleId = Convert.ToInt64(eventData.Payload[0]);
                    modulePath = eventData.Payload[3]?.ToString() ?? string.Empty;
                    
                    if (eventData.Payload.Count > 4)
                    {
                        assemblyName = eventData.Payload[4]?.ToString() ?? "UnknownAssembly";
                    }
                }

                // If path is empty, it means the assembly was loaded from byte array (Memory)
                // إذا كان المسار فارغاً، فهذا يعني أن التجميعة تم تحميلها من الذاكرة
                bool isInMemory = string.IsNullOrWhiteSpace(modulePath);

                if (isInMemory)
                {
                    var dynAssembly = new DotNetDynamicAssembly(
                        Process.GetCurrentProcess().Id,
                        moduleId,
                        assemblyName,
                        isInMemory,
                        DateTime.UtcNow
                    );

                    OnDynamicAssemblyLoaded?.Invoke(dynAssembly);
                }
            }
        }
        catch (Exception)
        {
            // Fail-open: ignore errors during event parsing
            // تجاوز الأخطاء أثناء تحليل الحدث
        }
    }

    public override void Dispose()
    {
        Stop();
        OnDynamicAssemblyLoaded = null;
        base.Dispose();
    }
}
