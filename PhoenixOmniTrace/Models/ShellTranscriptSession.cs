using System;
using System.Collections.Generic;
using System.Text;

namespace PhoenixGSM.OmniTrace.Models;

public sealed class ShellTranscriptEntry
{
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;
    public string StreamType { get; set; } = "stdin"; // stdin, stdout, stderr, exit
    public byte[] RawBytes { get; set; } = Array.Empty<byte>();
    public string RawString => Encoding.UTF8.GetString(RawBytes);
    public string? ReconstructedText { get; set; }
}

public sealed class ShellTranscriptSession
{
    public string SessionId { get; set; } = Guid.NewGuid().ToString("N");
    public string DeviceIdentity { get; set; } = string.Empty;
    public uint LocalChannelId { get; set; }
    public uint RemoteChannelId { get; set; }
    public string ServiceName { get; set; } = "shell";
    public DateTimeOffset StartTime { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? EndTime { get; set; }
    public bool IsActive { get; set; } = true;

    public List<ShellTranscriptEntry> Entries { get; } = [];
    public List<string> ReconstructedCommands { get; } = [];
    public StringBuilder CompleteRawTranscript { get; } = new();

    public void AddEntry(string streamType, byte[] rawBytes, string? reconstructed = null)
    {
        var entry = new ShellTranscriptEntry
        {
            StreamType = streamType,
            RawBytes = rawBytes,
            ReconstructedText = reconstructed
        };
        Entries.Add(entry);

        string str = Encoding.UTF8.GetString(rawBytes);
        CompleteRawTranscript.Append(str);

        if (!string.IsNullOrWhiteSpace(reconstructed) && streamType == "stdin")
        {
            ReconstructedCommands.Add(reconstructed);
        }
    }
}
