using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.Correlation;

/// <summary>
/// LAYER 13 — Command Correlation Engine
/// Associates raw events, decoded transport streams, and process execution events.
/// Enforces the architectural rule: Logical Command is the Primary Fact;
/// Process Execution is purely Attribution Metadata.
/// </summary>
public sealed class CommandCorrelationEngine
{
    private readonly ConcurrentDictionary<int, ProcessAttributionMetadata> _activeProcessesByPid = new();
    private readonly ConcurrentDictionary<string, ProcessAttributionMetadata> _processesByImageName = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, LogicalCommandEvent> _commands = new();

    public void RegisterProcess(ProcessAttributionMetadata proc)
    {
        _activeProcessesByPid[proc.ProcessId] = proc;
        if (!string.IsNullOrEmpty(proc.ImageName))
        {
            _processesByImageName[proc.ImageName] = proc;
        }
    }

    public void UnregisterProcess(int pid)
    {
        _activeProcessesByPid.TryRemove(pid, out _);
    }

    public LogicalCommandEvent Correlate(
        string commandText,
        KnownProtocol protocol,
        string service,
        TransportType transport,
        string device,
        string session,
        PacketDirection direction,
        List<ulong> rawEvidenceSequences,
        List<string> evidenceHashes,
        double confidence = 1.0,
        int? suspectedPid = null,
        string? suspectedToolName = null)
    {
        var cmd = new LogicalCommandEvent
        {
            Command = commandText,
            Protocol = protocol,
            Service = service,
            Transport = transport,
            DeviceIdentity = device,
            SessionIdentity = session,
            Direction = direction,
            RawEvidenceSequences = new List<ulong>(rawEvidenceSequences),
            EvidenceHashes = new List<string>(evidenceHashes),
            Confidence = confidence
        };

        // Attach attribution metadata if available
        if (suspectedPid.HasValue && _activeProcessesByPid.TryGetValue(suspectedPid.Value, out var procByPid))
        {
            cmd.Attribution = procByPid;
        }
        else if (!string.IsNullOrEmpty(suspectedToolName) && _processesByImageName.TryGetValue(suspectedToolName, out var procByName))
        {
            cmd.Attribution = procByName;
        }
        else if (suspectedPid.HasValue || !string.IsNullOrEmpty(suspectedToolName))
        {
            cmd.Attribution = new ProcessAttributionMetadata
            {
                ProcessId = suspectedPid ?? 0,
                ImageName = suspectedToolName ?? string.Empty
            };
        }

        _commands[cmd.CommandId] = cmd;
        return cmd;
    }

    public LogicalCommandEvent? GetCommand(string commandId)
    {
        _commands.TryGetValue(commandId, out var cmd);
        return cmd;
    }

    public IReadOnlyCollection<LogicalCommandEvent> GetAllCommands() => _commands.Values.ToList();
    public IReadOnlyCollection<ProcessAttributionMetadata> ActiveProcesses => _activeProcessesByPid.Values.ToList();
    public ProcessAttributionMetadata? GetProcess(int pid) => _activeProcessesByPid.TryGetValue(pid, out var p) ? p : null;

    public void Clear()
    {
        _commands.Clear();
        _activeProcessesByPid.Clear();
        _processesByImageName.Clear();
    }
}
