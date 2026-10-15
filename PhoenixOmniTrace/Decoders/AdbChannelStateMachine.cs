using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.Decoders;

public enum ChannelState
{
    Closed,
    Opening,
    Ready,
    Closing,
    Anomalous
}

public sealed class AdbChannelInfo
{
    public uint LocalId { get; set; }
    public uint RemoteId { get; set; }
    public string Service { get; set; } = string.Empty;
    public ChannelState State { get; set; } = ChannelState.Closed;
    public DateTimeOffset CreatedTime { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset LastActivityTime { get; set; } = DateTimeOffset.UtcNow;
    public List<string> Anomalies { get; } = [];
}

/// <summary>
/// LAYER 9 — ADB Channel State Machine
/// Tracks localId <-> remoteId channel lifecycles and flags anomalies without dropping raw data.
/// Strictly enforces ADB wire protocol stream ID conventions:
/// - Arg0: sender's channel ID
/// - Arg1: receiver's channel ID
/// </summary>
public sealed class AdbChannelStateMachine
{
    private readonly ConcurrentDictionary<uint, AdbChannelInfo> _channelsByLocalId = new();
    private readonly ConcurrentDictionary<uint, AdbChannelInfo> _channelsByRemoteId = new();

    public event Action<AdbChannelInfo, string, byte[]>? OnProtocolAnomaly;

    public AdbChannelInfo ProcessWirePacket(AdbWirePacket packet, PacketDirection direction)
    {
        switch (packet.Command)
        {
            case AdbWirePacket.A_OPEN:
                {
                    // Arg0 = LocalId (Host-allocated), Arg1 = 0, Payload = service name (e.g. "shell:\0")
                    string service = System.Text.Encoding.UTF8.GetString(packet.Payload).TrimEnd('\0');
                    var channel = new AdbChannelInfo
                    {
                        LocalId = packet.Arg0,
                        RemoteId = 0,
                        Service = service,
                        State = ChannelState.Opening,
                        CreatedTime = DateTimeOffset.UtcNow,
                        LastActivityTime = DateTimeOffset.UtcNow
                    };
                    _channelsByLocalId[packet.Arg0] = channel;
                    return channel;
                }

            case AdbWirePacket.A_OKAY:
                {
                    // In response to OPEN: Arg0 = Device RemoteId, Arg1 = Host LocalId
                    uint hostLocalId = packet.Arg1;
                    uint deviceRemoteId = packet.Arg0;

                    if (_channelsByLocalId.TryGetValue(hostLocalId, out var channel))
                    {
                        channel.RemoteId = deviceRemoteId;
                        channel.State = ChannelState.Ready;
                        channel.LastActivityTime = DateTimeOffset.UtcNow;
                        _channelsByRemoteId[deviceRemoteId] = channel;
                        return channel;
                    }
                    else
                    {
                        // OKAY without prior OPEN recorded as anomaly
                        var anomalyChannel = new AdbChannelInfo
                        {
                            LocalId = hostLocalId,
                            RemoteId = deviceRemoteId,
                            State = ChannelState.Anomalous,
                            Service = "UNKNOWN"
                        };
                        string anomalyMsg = $"Unexpected OKAY received for untracked channel LocalId=0x{hostLocalId:X8}, RemoteId=0x{deviceRemoteId:X8}";
                        anomalyChannel.Anomalies.Add(anomalyMsg);
                        _channelsByLocalId[hostLocalId] = anomalyChannel;
                        _channelsByRemoteId[deviceRemoteId] = anomalyChannel;
                        OnProtocolAnomaly?.Invoke(anomalyChannel, anomalyMsg, packet.Payload);
                        return anomalyChannel;
                    }
                }

            case AdbWirePacket.A_WRTE:
                {
                    // In ADB Wire: Arg0 = sender channel ID, Arg1 = receiver channel ID
                    // When HOST_TO_DEVICE: Host is sender (Arg0=LocalId), Device is receiver (Arg1=RemoteId)
                    // When DEVICE_TO_HOST: Device is sender (Arg0=RemoteId), Host is receiver (Arg1=LocalId)
                    AdbChannelInfo? channel = null;

                    if (direction == PacketDirection.HOST_TO_DEVICE)
                    {
                        _channelsByLocalId.TryGetValue(packet.Arg0, out channel);
                        if (channel == null && packet.Arg1 != 0)
                        {
                            _channelsByRemoteId.TryGetValue(packet.Arg1, out channel);
                        }
                    }
                    else
                    {
                        _channelsByLocalId.TryGetValue(packet.Arg1, out channel);
                        if (channel == null && packet.Arg0 != 0)
                        {
                            _channelsByRemoteId.TryGetValue(packet.Arg0, out channel);
                        }
                    }

                    if (channel == null)
                    {
                        // Fallback search across all registered channels
                        channel = _channelsByLocalId.Values.FirstOrDefault(c =>
                            c.LocalId == packet.Arg0 || c.LocalId == packet.Arg1 ||
                            c.RemoteId == packet.Arg0 || c.RemoteId == packet.Arg1);
                    }

                    if (channel != null)
                    {
                        channel.LastActivityTime = DateTimeOffset.UtcNow;
                        if (channel.State != ChannelState.Ready && channel.State != ChannelState.Opening)
                        {
                            string msg = $"WRTE packet arrived on channel Local=0x{channel.LocalId:X8}/Remote=0x{channel.RemoteId:X8} in state {channel.State}";
                            channel.Anomalies.Add(msg);
                            OnProtocolAnomaly?.Invoke(channel, msg, packet.Payload);
                        }
                        return channel;
                    }
                    else
                    {
                        var phantomChannel = new AdbChannelInfo
                        {
                            LocalId = direction == PacketDirection.HOST_TO_DEVICE ? packet.Arg0 : packet.Arg1,
                            RemoteId = direction == PacketDirection.HOST_TO_DEVICE ? packet.Arg1 : packet.Arg0,
                            State = ChannelState.Anomalous,
                            Service = "UNKNOWN"
                        };
                        string msg = $"Untracked WRTE stream on channel 0x{packet.Arg0:X8}->0x{packet.Arg1:X8}";
                        phantomChannel.Anomalies.Add(msg);
                        _channelsByLocalId[phantomChannel.LocalId] = phantomChannel;
                        OnProtocolAnomaly?.Invoke(phantomChannel, msg, packet.Payload);
                        return phantomChannel;
                    }
                }

            case AdbWirePacket.A_CLSE:
                {
                    AdbChannelInfo? channel = null;
                    if (direction == PacketDirection.HOST_TO_DEVICE)
                    {
                        _channelsByLocalId.TryGetValue(packet.Arg0, out channel);
                        if (channel == null && packet.Arg1 != 0)
                        {
                            _channelsByRemoteId.TryGetValue(packet.Arg1, out channel);
                        }
                    }
                    else
                    {
                        _channelsByLocalId.TryGetValue(packet.Arg1, out channel);
                        if (channel == null && packet.Arg0 != 0)
                        {
                            _channelsByRemoteId.TryGetValue(packet.Arg0, out channel);
                        }
                    }

                    if (channel != null)
                    {
                        channel.State = ChannelState.Closed;
                        channel.LastActivityTime = DateTimeOffset.UtcNow;
                        return channel;
                    }
                    break;
                }
        }

        return new AdbChannelInfo { State = ChannelState.Closed, Service = "UNKNOWN" };
    }

    public AdbChannelInfo? GetChannel(uint localId)
    {
        _channelsByLocalId.TryGetValue(localId, out var ch);
        return ch;
    }

    public int ActiveChannelCount => _channelsByLocalId.Values.Count(c => c.State == ChannelState.Ready || c.State == ChannelState.Opening);
}
