using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;

namespace PhoenixGSM.OmniTrace.NetworkInterception;

/// <summary>
/// Tracks in-flight TCP streams per connection key and reassembles HTTP responses.
/// يتتبع تدفقات TCP قيد التنفيذ لكل مفتاح اتصال ويعيد تجميع استجابات HTTP.
/// </summary>
public class SocketBufferReassembler : IDisposable
{
    private readonly ConcurrentDictionary<string, StreamState> _streams = new();
    private readonly Timer _cleanupTimer;

    public SocketBufferReassembler()
    {
        // Cleanup stale streams every 10 seconds / تنظيف التدفقات القديمة كل 10 ثوانٍ
        _cleanupTimer = new Timer(CleanupStaleStreams, null, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(10));
    }

    /// <summary>
    /// Adds a chunk of data to the stream and checks if the response is complete.
    /// يضيف جزءًا من البيانات إلى التدفق ويتحقق مما إذا كانت الاستجابة مكتملة.
    /// </summary>
    public byte[]? AddChunkAndCheckCompletion(string connectionKey, byte[] data)
    {
        try
        {
            var state = _streams.GetOrAdd(connectionKey, _ => new StreamState { ConnectionKey = connectionKey });
            
            lock (state)
            {
                state.LastActivity = DateTime.UtcNow;
                state.Chunks.Add(new StreamChunk { Data = data });

                if (!state.HeadersParsed)
                {
                    ParseHeaders(state);
                }

                if (state.HeadersParsed && IsResponseComplete(state))
                {
                    var payload = ExtractPayload(state);
                    _streams.TryRemove(connectionKey, out _);
                    return payload;
                }
            }
        }
        catch (Exception ex)
        {
            // Fail-open: log and ignore errors / تجاوز الفشل: تسجيل وتجاهل الأخطاء
            Console.WriteLine($"[Reassembler] Error processing chunk for {connectionKey}: {ex.Message}");
        }

        return null;
    }

    private void ParseHeaders(StreamState state)
    {
        var buffer = CombineChunks(state.Chunks);
        var headerString = Encoding.UTF8.GetString(buffer);
        var headerEndIndex = headerString.IndexOf("\r\n\r\n");

        if (headerEndIndex != -1)
        {
            state.HeadersLength = Encoding.UTF8.GetByteCount(headerString.Substring(0, headerEndIndex + 4));
            state.HeadersParsed = true;

            var headers = headerString.Substring(0, headerEndIndex).Split("\r\n");
            foreach (var header in headers)
            {
                if (header.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))
                {
                    if (int.TryParse(header.Substring(15).Trim(), out int contentLength))
                        state.ExpectedContentLength = contentLength;
                }
                else if (header.StartsWith("Transfer-Encoding:", StringComparison.OrdinalIgnoreCase) && 
                         header.Contains("chunked", StringComparison.OrdinalIgnoreCase))
                {
                    state.IsChunkedEncoding = true;
                }
                else if (header.StartsWith("Content-Type:", StringComparison.OrdinalIgnoreCase))
                {
                    state.ContentType = header.Substring(13).Trim();
                }
            }
        }
    }

    private bool IsResponseComplete(StreamState state)
    {
        var totalBytes = state.Chunks.Sum(c => c.Data.Length);
        var payloadBytes = totalBytes - state.HeadersLength;

        if (state.ExpectedContentLength >= 0)
        {
            return payloadBytes >= state.ExpectedContentLength;
        }

        if (state.IsChunkedEncoding)
        {
            // Simple chunked check: ends with 0\r\n\r\n
            var lastChunk = state.Chunks.Last().Data;
            if (lastChunk.Length >= 5)
            {
                var end = Encoding.UTF8.GetString(lastChunk, lastChunk.Length - 5, 5);
                return end == "0\r\n\r\n";
            }
        }

        return false;
    }

    private byte[] ExtractPayload(StreamState state)
    {
        var buffer = CombineChunks(state.Chunks);
        var payload = new byte[buffer.Length - state.HeadersLength];
        Array.Copy(buffer, state.HeadersLength, payload, 0, payload.Length);
        return payload;
    }

    private byte[] CombineChunks(List<StreamChunk> chunks)
    {
        var totalLength = chunks.Sum(c => c.Data.Length);
        var result = new byte[totalLength];
        var offset = 0;
        foreach (var chunk in chunks)
        {
            Buffer.BlockCopy(chunk.Data, 0, result, offset, chunk.Data.Length);
            offset += chunk.Data.Length;
        }
        return result;
    }

    private void CleanupStaleStreams(object? state)
    {
        var cutoff = DateTime.UtcNow.AddSeconds(-30);
        var staleKeys = _streams.Where(kvp => kvp.Value.LastActivity < cutoff).Select(kvp => kvp.Key).ToList();

        foreach (var key in staleKeys)
        {
            _streams.TryRemove(key, out _);
        }
    }

    public void Dispose()
    {
        _cleanupTimer.Dispose();
    }

    private class StreamChunk
    {
        public byte[] Data { get; set; } = Array.Empty<byte>();
    }

    private class StreamState
    {
        public string ConnectionKey { get; set; } = string.Empty;
        public List<StreamChunk> Chunks { get; set; } = new();
        public DateTime LastActivity { get; set; } = DateTime.UtcNow;
        public bool HeadersParsed { get; set; }
        public int HeadersLength { get; set; } = -1;
        public int ExpectedContentLength { get; set; } = -1;
        public bool IsChunkedEncoding { get; set; }
        public string ContentType { get; set; } = string.Empty;
    }
}
