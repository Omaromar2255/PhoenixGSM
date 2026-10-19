using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Text;
using PhoenixGSM.OmniTrace.Models;
using PhoenixGSM.OmniTrace.Sensors;

namespace PhoenixGSM.OmniTrace.Decoders;

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

public sealed class AdbSyncStreamReconstructor
{
    public const uint ID_STAT = 0x54415453; // "STAT"
    public const uint ID_SEND = 0x444E4553; // "SEND"
    public const uint ID_DATA = 0x41544144; // "DATA"
    public const uint ID_DONE = 0x454E4F44; // "DONE"
    public const uint ID_RECV = 0x56434552; // "RECV"
    public const uint ID_QUIT = 0x54495551; // "QUIT"

    private const int MaxPendingBufferBytes = 68 * 1024 * 1024;
    private readonly AdbPushArtifactVault _vault;
    private readonly ConcurrentDictionary<uint, AdbSyncSessionState> _sessions = new();

    public AdbPushArtifactVault Vault => _vault;

    public AdbSyncStreamReconstructor(AdbPushArtifactVault vault)
    {
        _vault = vault ?? throw new ArgumentNullException(nameof(vault));
    }

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

        try
        {
            var state = _sessions.GetOrAdd(channelId, id => new AdbSyncSessionState
            {
                ChannelId = id,
                ProcessName = procName,
                ProcessId = pid,
                DeviceSerial = deviceSerial,
                StartTime = DateTime.UtcNow
            });

            lock (state)
            {
                if (state.PendingBuffer.Length + payload.Length > MaxPendingBufferBytes)
                {
                    state.PendingBuffer.SetLength(0);
                    state.DataStream.SetLength(0);
                    return false;
                }

                state.PendingBuffer.Write(payload, 0, payload.Length);
                byte[] buffer = state.PendingBuffer.GetBuffer();
                int bufferLen = (int)state.PendingBuffer.Length;
                int offset = 0;
                bool artifactCompleted = false;

                while (offset + 8 <= bufferLen)
                {
                    uint id = BitConverter.ToUInt32(buffer, offset);
                    uint len = BitConverter.ToUInt32(buffer, offset + 4);

                    if (id == ID_STAT)
                    {
                        if (len > 1024) { offset++; continue; }
                        if (offset + 8 + (int)len > bufferLen) break;
                        offset += 8 + (int)len;
                    }
                    else if (id == ID_SEND)
                    {
                        if (len == 0 || len > 1024) { offset++; continue; }
                        if (offset + 8 + (int)len > bufferLen) break;

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

                        state.DataStream.SetLength(0);
                        offset += 8 + (int)len;
                    }
                    else if (id == ID_DATA)
                    {
                        if (len > 65536) { offset++; continue; }
                        if (offset + 8 + (int)len > bufferLen) break;

                        state.DataStream.Write(buffer, offset + 8, (int)len);
                        offset += 8 + (int)len;
                    }
                    else if (id == ID_DONE)
                    {
                        offset += 8;

                        byte[] fileBytes = state.DataStream.ToArray();
                        if (fileBytes.Length > 0)
                        {
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
                        }

                        state.DataStream.SetLength(0);
                        state.TargetDevicePath = string.Empty;
                        break;
                    }
                    else if (id == ID_QUIT)
                    {
                        offset += 8;
                        CloseChannel(channelId);
                        break;
                    }
                    else
                    {
                        offset++;
                    }
                }

                if (offset > 0)
                {
                    int remaining = bufferLen - offset;
                    if (remaining > 0)
                    {
                        byte[] remCopy = new byte[remaining];
                        Buffer.BlockCopy(buffer, offset, remCopy, 0, remaining);
                        state.PendingBuffer.SetLength(0);
                        state.PendingBuffer.Write(remCopy, 0, remaining);
                    }
                    else
                    {
                        state.PendingBuffer.SetLength(0);
                    }
                }

                return artifactCompleted;
            }
        }
        catch
        {
            return false;
        }
    }

    public void CloseChannel(uint channelId)
    {
        if (_sessions.TryRemove(channelId, out var state))
        {
            try
            {
                state.DataStream.Dispose();
                state.PendingBuffer.Dispose();
            }
            catch { }
        }
    }
}
