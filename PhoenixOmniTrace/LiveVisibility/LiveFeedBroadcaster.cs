using System;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace PhoenixGSM.OmniTrace.LiveVisibility;

public class LiveFeedItem
{
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string Source { get; set; } = string.Empty;
    public string PayloadSummary { get; set; } = string.Empty;
    public string RiskLevel { get; set; } = "Normal";
    public string Category { get; set; } = "Traffic";
}

public class LiveFeedBroadcaster : IDisposable
{
    private readonly Channel<LiveFeedItem> _channel;
    private bool _disposed;

    public event Action<LiveFeedItem>? OnLiveItemAvailable;

    public LiveFeedBroadcaster(int capacity = 10000)
    {
        // استخدام حلقة تخزين عازلة تسقط القديم / Drop-oldest ring buffer
        var options = new BoundedChannelOptions(capacity)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleWriter = false,
            SingleReader = true
        };
        _channel = Channel.CreateBounded<LiveFeedItem>(options);
        Task.Run(ProcessQueueAsync);
    }

    /// <summary>
    /// يبث الأحداث بدون انتظار / Emits events with zero delay without blocking
    /// </summary>
    public void BroadcastEvent(LiveFeedItem item)
    {
        try
        {
            if (_disposed) return;
            _channel.Writer.TryWrite(item);
        }
        catch (Exception ex)
        {
            // Fail-open: لا تعطل النظام / Do not crash system
            Console.WriteLine($"[Broadcaster Error] {ex.Message}");
        }
    }

    private async Task ProcessQueueAsync()
    {
        try
        {
            await foreach (var item in _channel.Reader.ReadAllAsync())
            {
                if (_disposed) break;
                OnLiveItemAvailable?.Invoke(item);
            }
        }
        catch (Exception ex)
        {
            // فشل مفتوح / Fail-open
            Console.WriteLine($"[ProcessQueue Error] {ex.Message}");
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _channel.Writer.TryComplete();
    }
}
