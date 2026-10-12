using System;
using System.Collections.Concurrent;
using System.IO;
using System.Text;
using PhoenixGSM.OmniTrace.Models;
using PhoenixGSM.OmniTrace.Sensors;

namespace PhoenixGSM.OmniTrace.Decoders;

/// <summary>
/// State tracker for an in-flight ADB sync stream session.
/// </summary>
public sealed class AdbSyncSessionState
{
    public uint ChannelId { get; set; }
    public string TargetDevicePath { get; set; } = string.Empty;
    public string RemoteMode { get; set; } = string.Empty;
    public MemoryStream DataStream { get; set; } = new();
    public MemoryStream PendingBuffer { get; set; } = new();
    public string ProcessName { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public string DeviceSerial { get; set; } = string.Empty;
    public DateTime StartTime { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// LAYER 9B — ADB Sync Protocol Wire Reassembler
/// Stateful decoder for ADB sync file transfers (SEND -> DATA chunks -> DONE).
/// Reconstructs pushed files sent directly from memory / in-process tools over ADB wire streams.
/// </summary>
public sealed class AdbSyncStreamReconstructor
{
    // ADB Sync Protocol 4-byte Command IDs
    public const uint ID_STAT = 0x54415453; // "STAT"
    public const uint ID_SEND = 0x444E4553; // "SEND"
    public const uint ID_DATA = 0x41544144; // "DATA"
    public const uint ID_DONE = 0x454E4F44; // "DONE"
    public const uint ID_RECV = 0x56434552; // "RECV"
    public const uint ID_QUIT = 0x54495551; // "QUIT"

    private readonly AdbPushArtifactVault _vault;
    private readonly ConcurrentDictionary<uint, AdbSyncSessionState> _sessions = new();

    public AdbPushArtifactVault Vault => _vault;

    public AdbSyncStreamReconstructor(AdbPushArtifactVault vault)
    {
        _vault = vault ?? throw new ArgumentNullException(nameof(vault));
    }

    /// <summary>
    /// Feeds raw payload bytes received on an ADB channel whose service is "sync:".
    /// </summary>
    public bool ProcessSyncPayload(
        uint channelId,
        byte[] payload,
        string procName,
        int pid,
        string deviceSerial,
        out PushedArtifactInfo? completedArtifact)
    {
        completedArtifact = null;
        if (payload == null || payload.Length == 0) return false;

        var state = _sessions.GetOrAdd(channelId, id => new AdbSyncSessionState
        {
            ChannelId = id,
            ProcessName = procName,
            ProcessId = pid,
            DeviceSerial = deviceSerial,
            StartTime = DateTime.UtcNow
        });

        // Append to pending buffer
        state.PendingBuffer.Write(payload, 0, payload.Length);
        byte[] buffer = state.PendingBuffer.ToArray();
        int offset = 0;
        bool artifactCompleted = false;

        while (offset + 8 <= buffer.Length)
        {
            uint id = BitConverter.ToUInt32(buffer, offset);
            uint len = BitConverter.ToUInt32(buffer, offset + 4);

            if (id == ID_SEND)
            {
                // SEND header: 8 bytes + len bytes of "path,mode"
                if (offset + 8 + (int)len > buffer.Length)
                {
                    // Incomplete SEND header, wait for next packet
                    break;
                }

                string pathAndMode = Encoding.UTF8.GetString(buffer, offset + 8, (int)len);
                int commaIdx = pathAndMode.LastIndexOf(',');
                if (commaIdx >= 0)
                {
                    state.TargetDevicePath = pathAndMode[..commaIdx].Trim();
                    state.RemoteMode = pathAndMode[(commaIdx + 1)..].Trim();
                }
                else
                {
                    state.TargetDevicePath = pathAndMode.Trim();
                }

                offset += 8 + (int)len;
            }
            else if (id == ID_DATA)
            {
                // DATA chunk: 8 bytes + len bytes of file content
                if (offset + 8 + (int)len > buffer.Length)
                {
                    // Incomplete DATA chunk, wait for more bytes
                    break;
                }

                state.DataStream.Write(buffer, offset + 8, (int)len);
                offset += 8 + (int)len;
            }
            else if (id == ID_DONE)
            {
                // DONE token: 8 bytes (ID_DONE + mtime)
                offset += 8;

                byte[] fileBytes = state.DataStream.ToArray();
                string remotePath = !string.IsNullOrWhiteSpace(state.TargetDevicePath)
                    ? state.TargetDevicePath
                    : "/data/local/tmp/in_flight_pushed_artifact";
                string fileName = Path.GetFileName(remotePath);
                if (string.IsNullOrWhiteSpace(fileName)) fileName = "sync_artifact.bin";

                var attrs = new Dictionary<string, string>
                {
                    ["RemoteMode"] = state.RemoteMode,
                    ["SyncChannelId"] = $"0x{channelId:X8}"
                };

                completedArtifact = _vault.StoreArtifact(
                    content: fileBytes,
                    fileName: fileName,
                    targetDevicePath: remotePath,
                    processName: !string.IsNullOrWhiteSpace(state.ProcessName) ? state.ProcessName : procName,
                    pid: state.ProcessId > 0 ? state.ProcessId : pid,
                    sourceVector: "AdbSyncWire",
                    deviceSerial: state.DeviceSerial,
                    extraAttrs: attrs
                );

                artifactCompleted = true;

                // Reset session for this channel in case reused
                state.DataStream.SetLength(0);
                state.TargetDevicePath = string.Empty;
                break;
            }
            else
            {
                // Unrecognized sync ID or misaligned stream: advance by 1 byte to re-sync
                offset++;
            }
        }

        // Keep remaining unconsumed bytes in PendingBuffer
        if (offset > 0)
        {
            int remaining = buffer.Length - offset;
            state.PendingBuffer.SetLength(0);
            if (remaining > 0)
            {
                state.PendingBuffer.Write(buffer, offset, remaining);
            }
        }

        if (artifactCompleted)
        {
            _sessions.TryRemove(channelId, out _);
            return true;
        }

        return false;
    }

    public void CloseChannel(uint channelId)
    {
        _sessions.TryRemove(channelId, out _);
    }
}
