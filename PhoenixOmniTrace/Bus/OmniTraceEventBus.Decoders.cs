using System;
using System.IO;
using System.Text;
using System.Threading;
using PhoenixGSM.OmniTrace.Apple.Decoders;
using PhoenixGSM.OmniTrace.Apple.Models;
using PhoenixGSM.OmniTrace.Decoders;
using PhoenixGSM.OmniTrace.Models;
using PhoenixGSM.OmniTrace.Reassembly;

namespace PhoenixGSM.OmniTrace.Bus;

public sealed partial class OmniTraceEventBus
{
    private void DecodeAdbStream(CaptureSessionKey key, byte[] stream, RawCaptureEvent evt)
    {
        // Try wire decoding first
        var wirePackets = AdbDecoder.DecodePackets(stream, out int wireConsumed);
        if (wirePackets.Count > 0)
        {
            (var sessionSeqs, var sessionHashes) = Reassembler.GetEvidenceSnapshot(key);
            if (sessionSeqs.Count == 0) sessionSeqs = [evt.SequenceNumber];
            if (sessionHashes.Count == 0 && !string.IsNullOrEmpty(evt.PayloadHash)) sessionHashes = [evt.PayloadHash];

            Reassembler.ConsumeStream(key, wireConsumed);
            Interlocked.Add(ref _decodedEvents, wirePackets.Count);

            foreach (var wp in wirePackets)
            {
                var ch = ChannelStateMachine.ProcessWirePacket(wp, evt.Direction);

                // Handle WRTE payload (e.g. interactive shell / sub-binary session commands and responses)
                if (wp.Command == AdbWirePacket.A_WRTE && wp.Payload.Length > 0)
                {
                    bool isHostToDevice = evt.Direction == PacketDirection.HOST_TO_DEVICE;

                    if (isHostToDevice)
                    {
                        if (ch.Service.StartsWith("sync", StringComparison.OrdinalIgnoreCase))
                        {
                            string pName = evt.Metadata != null && evt.Metadata.TryGetValue("ProcessName", out var pn) ? pn : (!string.IsNullOrWhiteSpace(evt.SessionIdentity) ? evt.SessionIdentity : "GSM_Tool.exe");
                            int pid = 0;
                            if (evt.Metadata != null && evt.Metadata.TryGetValue("ProcessId", out var pStr)) int.TryParse(pStr, out pid);
                            ArtifactSensor?.ProcessSyncWirePayload(wp.Arg0, wp.Payload, pName, pid, evt.DeviceIdentity, out _);
                        }

                        // 1. Host writing into sub-shell / binary (>> STDIN)
                        ShellReconstructor.ProcessInputBytes(
                            wp.Payload,
                            evt.SequenceNumber,
                            evt.PayloadHash,
                            out string? cmdText,
                            out _,
                            out var shellSeqs,
                            out var shellHashes);

                        string? finalCmd = cmdText;
                        if (string.IsNullOrEmpty(finalCmd))
                        {
                            // Capture non-newline-terminated payloads (e.g. auth keys, tokens, interactive choices)
                            string rawStr = ShellStreamReconstructor.CleanTerminalOutput(Encoding.UTF8.GetString(wp.Payload)).Trim();
                            if (!string.IsNullOrWhiteSpace(rawStr) && rawStr.Length >= 2)
                            {
                                finalCmd = rawStr;
                            }
                        }

                        if (!string.IsNullOrEmpty(finalCmd))
                        {
                            var evidenceSeqs = shellSeqs.Count > 0 ? shellSeqs : sessionSeqs;
                            var evidenceHshs = shellHashes.Count > 0 ? shellHashes : sessionHashes;

                            var cmd = Correlation.Correlate(
                                $">> {finalCmd}",
                                KnownProtocol.ADB,
                                ch.Service,
                                evt.Transport,
                                evt.DeviceIdentity,
                                evt.SessionIdentity,
                                PacketDirection.HOST_TO_DEVICE,
                                evidenceSeqs,
                                evidenceHshs,
                                confidence: 0.99
                            );
                            OnLogicalCommand?.Invoke(cmd);
                        }
                    }
                    else
                    {
                        // 2. Device returning stdout / prompts / status to host (<< STDOUT)
                        string outputText = ShellStreamReconstructor.CleanTerminalOutput(Encoding.UTF8.GetString(wp.Payload)).Trim();
                        if (!string.IsNullOrWhiteSpace(outputText) && outputText.Length >= 2)
                        {
                            // Suppress raw ADB wire headers leaked into payload (WRTE, CLSE, OKAY, OPEN, CNXN)
                            if (outputText.StartsWith("WRTE") || outputText.StartsWith("CLSE") ||
                                outputText.StartsWith("OKAY") || outputText.StartsWith("CNXN") ||
                                outputText.StartsWith("OPEN"))
                            {
                                continue;
                            }

                            var cmd = Correlation.Correlate(
                                $"<< {outputText}",
                                KnownProtocol.ADB,
                                ch.Service,
                                evt.Transport,
                                evt.DeviceIdentity,
                                evt.SessionIdentity,
                                PacketDirection.DEVICE_TO_HOST,
                                sessionSeqs,
                                sessionHashes,
                                confidence: 0.95
                            );
                            OnLogicalCommand?.Invoke(cmd);
                        }
                    }
                }
                else if (wp.Command == AdbWirePacket.A_OPEN)
                {
                    string svc = Encoding.UTF8.GetString(wp.Payload).TrimEnd('\0');
                    var cmd = Correlation.Correlate(
                        $"OPEN {svc}",
                        KnownProtocol.ADB,
                        svc,
                        evt.Transport,
                        evt.DeviceIdentity,
                        evt.SessionIdentity,
                        evt.Direction,
                        sessionSeqs,
                        sessionHashes,
                        confidence: 0.99
                    );
                    OnLogicalCommand?.Invoke(cmd);
                }
            }
            return;
        }

        // Try Smart Socket decoding if wire decode yielded no packets
        var smartFrames = SmartSocketDecoder.Decode(stream, out int smartConsumed);
        if (smartFrames.Count > 0)
        {
            (var sessionSeqs, var sessionHashes) = Reassembler.GetEvidenceSnapshot(key);
            if (sessionSeqs.Count == 0) sessionSeqs = [evt.SequenceNumber];
            if (sessionHashes.Count == 0 && !string.IsNullOrEmpty(evt.PayloadHash)) sessionHashes = [evt.PayloadHash];

            Reassembler.ConsumeStream(key, smartConsumed);
            Interlocked.Add(ref _decodedEvents, smartFrames.Count);

            foreach (var sf in smartFrames)
            {
                if (!sf.IsStatusResponse)
                {
                    var cmd = Correlation.Correlate(
                        $"{sf.ServicePrefix}:{sf.ServicePayload}",
                        KnownProtocol.ADB,
                        sf.ServicePrefix,
                        evt.Transport,
                        evt.DeviceIdentity,
                        evt.SessionIdentity,
                        evt.Direction,
                        sessionSeqs,
                        sessionHashes,
                        confidence: 0.96
                    );
                    OnLogicalCommand?.Invoke(cmd);
                }
            }
        }
    }

    private void DecodeFastbootStream(CaptureSessionKey key, byte[] stream, RawCaptureEvent evt)
    {
        string text = Encoding.ASCII.GetString(stream).Trim();
        if (!string.IsNullOrEmpty(text))
        {
            (var sessionSeqs, var sessionHashes) = Reassembler.GetEvidenceSnapshot(key);
            if (sessionSeqs.Count == 0) sessionSeqs = [evt.SequenceNumber];
            if (sessionHashes.Count == 0 && !string.IsNullOrEmpty(evt.PayloadHash)) sessionHashes = [evt.PayloadHash];

            Reassembler.ConsumeStream(key, stream.Length);
            Interlocked.Increment(ref _decodedEvents);

            var cmd = Correlation.Correlate(
                text,
                KnownProtocol.Fastboot,
                "fastboot",
                evt.Transport,
                evt.DeviceIdentity,
                evt.SessionIdentity,
                evt.Direction,
                sessionSeqs,
                sessionHashes,
                confidence: 0.95
            );
            OnLogicalCommand?.Invoke(cmd);
        }
    }

    private void DecodeSerialAtStream(CaptureSessionKey key, byte[] stream, RawCaptureEvent evt)
    {
        int lastTerminator = Math.Max(Array.LastIndexOf(stream, (byte)'\r'), Array.LastIndexOf(stream, (byte)'\n'));
        if (lastTerminator < 0)
        {
            if (stream.Length < 4096) return;
            lastTerminator = stream.Length - 1;
        }
        int bytesToConsume = lastTerminator + 1;

        byte[] bytesToDecode = new byte[bytesToConsume];
        Buffer.BlockCopy(stream, 0, bytesToDecode, 0, bytesToConsume);

        string text = Encoding.ASCII.GetString(bytesToDecode);
        var lines = text.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.RemoveEmptyEntries);

        (var sessionSeqs, var sessionHashes) = Reassembler.GetEvidenceSnapshot(key);
        if (sessionSeqs.Count == 0) sessionSeqs = [evt.SequenceNumber];
        if (sessionHashes.Count == 0 && !string.IsNullOrEmpty(evt.PayloadHash)) sessionHashes = [evt.PayloadHash];

        Reassembler.ConsumeStream(key, bytesToConsume);

        foreach (var rawLine in lines)
        {
            string cleanLine = rawLine.Trim();
            if (string.IsNullOrEmpty(cleanLine)) continue;

            // Strict ADB Isolation Rule:
            // Reject getprop fragments, hex streams, parcel results, and non-modem text
            if (cleanLine.Contains("]: [") || cleanLine == "]" || cleanLine.Contains("0x0000") ||
                cleanLine.Contains("Enforcing", StringComparison.OrdinalIgnoreCase) ||
                cleanLine.Contains("Permissive", StringComparison.OrdinalIgnoreCase) ||
                cleanLine.Contains("0x4948", StringComparison.OrdinalIgnoreCase) ||
                cleanLine.Contains("0x4f4c", StringComparison.OrdinalIgnoreCase) ||
                cleanLine.Contains("0x494d", StringComparison.OrdinalIgnoreCase) ||
                cleanLine.Contains("Product Name", StringComparison.OrdinalIgnoreCase) ||
                cleanLine.Contains("Product Model", StringComparison.OrdinalIgnoreCase) ||
                cleanLine.Contains("Build  Number", StringComparison.OrdinalIgnoreCase) ||
                cleanLine.Contains("Serial Number", StringComparison.OrdinalIgnoreCase) ||
                cleanLine.Contains("restarting in USB mode", StringComparison.OrdinalIgnoreCase) ||
                cleanLine.Contains("#OK", StringComparison.OrdinalIgnoreCase) ||
                cleanLine.StartsWith("AuthKey", StringComparison.OrdinalIgnoreCase) ||
                cleanLine.StartsWith("Token AuthKey", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            // Reject long hex streams (e.g. >= 32 hex chars)
            if (cleanLine.Length >= 32 && cleanLine.All(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            {
                continue;
            }

            // Must start with standard AT command or modem response prefix
            string upper = cleanLine.ToUpperInvariant();
            bool isModemAt = upper.StartsWith("AT+") || upper.StartsWith("AT*") || upper.StartsWith("AT#") ||
                             upper.StartsWith("AT$") || upper.StartsWith("AT%") || upper.StartsWith("AT^") ||
                             upper.StartsWith("ATE") || upper.StartsWith("ATI") || upper.StartsWith("ATD") ||
                             upper.StartsWith("ATA") || upper.StartsWith("ATH") || upper.StartsWith("ATO") ||
                             upper.StartsWith("ATZ") || upper.StartsWith("AT&") || upper.StartsWith("ATQ") ||
                             upper.StartsWith("ATV") || upper.StartsWith("ATX") || upper == "AT" ||
                             upper == "A/" || upper.StartsWith("^") ||
                             upper.StartsWith("+") || upper == "OK" || upper.StartsWith("ERROR") ||
                             upper.StartsWith("+CME ERROR:") || upper.StartsWith("+CMS ERROR:") || upper.StartsWith("+DEVCONINFO:") ||
                             upper.StartsWith("ANY-") || upper.StartsWith("SM-") || upper.StartsWith("MODEL:") || upper.StartsWith("IMEI:") ||
                             (cleanLine.Length >= 14 && cleanLine.Length <= 16 && cleanLine.All(char.IsDigit));

            if (!isModemAt)
            {
                continue;
            }

            Interlocked.Increment(ref _decodedEvents);

            var cmd = Correlation.Correlate(
                cleanLine,
                KnownProtocol.SerialAt,
                evt.Transport == TransportType.FILE ? "modem-file-staged" : "modem",
                evt.Transport,
                evt.DeviceIdentity,
                evt.SessionIdentity,
                evt.Direction,
                sessionSeqs,
                sessionHashes,
                confidence: 0.95
            );
            OnLogicalCommand?.Invoke(cmd);
        }
    }

    private void DecodeMtpStream(CaptureSessionKey key, byte[] stream, RawCaptureEvent evt)
    {
        var packet = MtpDecoder.DecodePacket(stream);
        (var sessionSeqs, var sessionHashes) = Reassembler.GetEvidenceSnapshot(key);
        if (sessionSeqs.Count == 0) sessionSeqs = [evt.SequenceNumber];
        if (sessionHashes.Count == 0 && !string.IsNullOrEmpty(evt.PayloadHash)) sessionHashes = [evt.PayloadHash];

        int consumeLen = packet != null ? Math.Min(stream.Length, (int)packet.ContainerLength) : stream.Length;
        if (consumeLen <= 0) consumeLen = stream.Length;
        Reassembler.ConsumeStream(key, consumeLen);
        Interlocked.Increment(ref _decodedEvents);

        string cmdText = packet != null ? packet.ToString() : $"MTP Container ({stream.Length} bytes)";
        var cmd = Correlation.Correlate(
            cmdText,
            KnownProtocol.Mtp,
            "mtp",
            evt.Transport,
            evt.DeviceIdentity,
            evt.SessionIdentity,
            evt.Direction,
            sessionSeqs,
            sessionHashes,
            confidence: 0.96
        );

        if (packet != null)
        {
            foreach (var kvp in packet.Details) cmd.Details[kvp.Key] = kvp.Value;
        }

        OnLogicalCommand?.Invoke(cmd);
    }

    private void DecodeMtkStream(CaptureSessionKey key, byte[] stream, RawCaptureEvent evt)
    {
        var packet = MtkProtocolDecoder.DecodePacket(stream, evt.Direction);
        (var sessionSeqs, var sessionHashes) = Reassembler.GetEvidenceSnapshot(key);
        if (sessionSeqs.Count == 0) sessionSeqs = [evt.SequenceNumber];
        if (sessionHashes.Count == 0 && !string.IsNullOrEmpty(evt.PayloadHash)) sessionHashes = [evt.PayloadHash];

        Reassembler.ConsumeStream(key, stream.Length);
        Interlocked.Increment(ref _decodedEvents);

        string cmdText = packet != null ? packet.ToString() : $"MTK Frame ({stream.Length} bytes)";
        var proto = (packet != null && packet.Stage == "DA") ? KnownProtocol.MtkDa : KnownProtocol.MtkBrom;

        var cmd = Correlation.Correlate(
            cmdText,
            proto,
            packet != null ? packet.Stage.ToLowerInvariant() : "mtk",
            evt.Transport,
            evt.DeviceIdentity,
            evt.SessionIdentity,
            evt.Direction,
            sessionSeqs,
            sessionHashes,
            confidence: 0.95
        );

        if (packet != null)
        {
            foreach (var kvp in packet.Details) cmd.Details[kvp.Key] = kvp.Value;
        }

        OnLogicalCommand?.Invoke(cmd);
    }

    private void DecodeSpdFdlStream(CaptureSessionKey key, byte[] stream, RawCaptureEvent evt)
    {
        var packet = SpdFdlDecoder.DecodePacket(stream);
        (var sessionSeqs, var sessionHashes) = Reassembler.GetEvidenceSnapshot(key);
        if (sessionSeqs.Count == 0) sessionSeqs = [evt.SequenceNumber];
        if (sessionHashes.Count == 0 && !string.IsNullOrEmpty(evt.PayloadHash)) sessionHashes = [evt.PayloadHash];

        Reassembler.ConsumeStream(key, stream.Length);
        Interlocked.Increment(ref _decodedEvents);

        string cmdText = packet != null ? packet.ToString() : $"SPD FDL Frame ({stream.Length} bytes)";
        var cmd = Correlation.Correlate(
            cmdText,
            KnownProtocol.SpreadtrumFdl,
            "spd-fdl",
            evt.Transport,
            evt.DeviceIdentity,
            evt.SessionIdentity,
            evt.Direction,
            sessionSeqs,
            sessionHashes,
            confidence: 0.95
        );

        if (packet != null)
        {
            foreach (var kvp in packet.Details) cmd.Details[kvp.Key] = kvp.Value;
        }

        OnLogicalCommand?.Invoke(cmd);
    }

    private void DecodeQualcommEdlStream(KnownProtocol detectedProto, CaptureSessionKey key, byte[] stream, RawCaptureEvent evt)
    {
        var packet = QualcommEdlDecoder.DecodePacket(stream);
        (var sessionSeqs, var sessionHashes) = Reassembler.GetEvidenceSnapshot(key);
        if (sessionSeqs.Count == 0) sessionSeqs = [evt.SequenceNumber];
        if (sessionHashes.Count == 0 && !string.IsNullOrEmpty(evt.PayloadHash)) sessionHashes = [evt.PayloadHash];

        Reassembler.ConsumeStream(key, stream.Length);
        Interlocked.Increment(ref _decodedEvents);

        string cmdText = packet != null ? packet.ToString() : $"Qualcomm EDL Frame ({stream.Length} bytes)";
        var proto = packet != null && packet.Phase == "FIREHOSE" ? KnownProtocol.QualcommFirehose : KnownProtocol.QualcommSahara;

        var cmd = Correlation.Correlate(
            cmdText,
            proto,
            packet != null ? packet.Phase.ToLowerInvariant() : "edl",
            evt.Transport,
            evt.DeviceIdentity,
            evt.SessionIdentity,
            evt.Direction,
            sessionSeqs,
            sessionHashes,
            confidence: 0.98
        );

        if (packet != null)
        {
            foreach (var kvp in packet.Details) cmd.Details[kvp.Key] = kvp.Value;
        }

        OnLogicalCommand?.Invoke(cmd);
    }

    private void DecodeAppleStream(KnownProtocol proto, CaptureSessionKey key, byte[] stream, RawCaptureEvent evt)
    {
        (var sessionSeqs, var sessionHashes) = Reassembler.GetEvidenceSnapshot(key);
        if (sessionSeqs.Count == 0) sessionSeqs = [evt.SequenceNumber];
        if (sessionHashes.Count == 0 && !string.IsNullOrEmpty(evt.PayloadHash)) sessionHashes = [evt.PayloadHash];

        Reassembler.ConsumeStream(key, stream.Length);
        Interlocked.Increment(ref _decodedEvents);

        AppleDecodedCommand? appleCmd = proto switch
        {
            KnownProtocol.AppleUsbmuxd => AppleUsbmuxdDecoder.DecodePacket(stream),
            KnownProtocol.AppleLockdown => AppleLockdownDecoder.DecodePacket(stream),
            KnownProtocol.AppleRecovery => AppleRecoveryDecoder.DecodePacket(stream),
            KnownProtocol.AppleDfu => AppleDfuDecoder.DecodePacket(stream),
            KnownProtocol.AppleRamdiskSsh => AppleRamdiskSshDecoder.DecodePacket(stream),
            KnownProtocol.ApplePurpleDiag => ApplePurpleDiagDecoder.DecodePacket(stream),
            _ => null
        };

        string cmdText = appleCmd?.Summary ?? $"Apple {proto} Frame ({stream.Length} bytes)";
        string subService = appleCmd?.Category.ToLowerInvariant() ?? "apple";

        var cmd = Correlation.Correlate(
            cmdText,
            proto,
            subService,
            evt.Transport,
            evt.DeviceIdentity,
            evt.SessionIdentity,
            evt.Direction,
            sessionSeqs,
            sessionHashes,
            confidence: 0.98
        );

        if (appleCmd != null)
        {
            cmd.Details["AppleMode"] = appleCmd.Mode.ToString();
            cmd.Details["AppleCategory"] = appleCmd.Category;
            cmd.Details["AppleOperation"] = appleCmd.Operation;
            if (!string.IsNullOrEmpty(appleCmd.Ecid)) cmd.Details["ECID"] = appleCmd.Ecid;
            if (!string.IsNullOrEmpty(appleCmd.Cpid)) cmd.Details["CPID"] = appleCmd.Cpid;
            if (!string.IsNullOrEmpty(appleCmd.Bdid)) cmd.Details["BDID"] = appleCmd.Bdid;
            if (!string.IsNullOrEmpty(appleCmd.SerialNumber)) cmd.Details["SerialNumber"] = appleCmd.SerialNumber;
            if (!string.IsNullOrEmpty(appleCmd.Model)) cmd.Details["Model"] = appleCmd.Model;
            foreach (var kvp in appleCmd.Details) cmd.Details[kvp.Key] = kvp.Value;
        }

        OnLogicalCommand?.Invoke(cmd);
    }

    private void DecodeGenericKnownProtocol(KnownProtocol proto, CaptureSessionKey key, byte[] stream, RawCaptureEvent evt)
    {
        (var sessionSeqs, var sessionHashes) = Reassembler.GetEvidenceSnapshot(key);
        if (sessionSeqs.Count == 0) sessionSeqs = [evt.SequenceNumber];
        if (sessionHashes.Count == 0 && !string.IsNullOrEmpty(evt.PayloadHash)) sessionHashes = [evt.PayloadHash];

        Reassembler.ConsumeStream(key, stream.Length);
        Interlocked.Increment(ref _decodedEvents);

        var cmd = Correlation.Correlate(
            $"{proto} Frame ({stream.Length} bytes)",
            proto,
            proto.ToString().ToLowerInvariant(),
            evt.Transport,
            evt.DeviceIdentity,
            evt.SessionIdentity,
            evt.Direction,
            sessionSeqs,
            sessionHashes,
            confidence: 0.90
        );
        OnLogicalCommand?.Invoke(cmd);
    }

    private void DecodeHostCommandStream(CaptureSessionKey key, byte[] stream, RawCaptureEvent evt)
    {
        (var sessionSeqs, var sessionHashes) = Reassembler.GetEvidenceSnapshot(key);
        if (sessionSeqs.Count == 0) sessionSeqs = [evt.SequenceNumber];
        if (sessionHashes.Count == 0 && !string.IsNullOrEmpty(evt.PayloadHash)) sessionHashes = [evt.PayloadHash];

        Reassembler.ConsumeStream(key, stream.Length);
        Interlocked.Increment(ref _decodedEvents);

        string rawPayload = Encoding.UTF8.GetString(stream).Trim();
        string cmdLine = rawPayload;
        if (evt.Metadata.TryGetValue("CommandLine", out var metaCmd) && !string.IsNullOrWhiteSpace(metaCmd))
        {
            cmdLine = metaCmd;
        }
        else if (evt.Metadata.TryGetValue("Command", out var metaCmd2) && !string.IsNullOrWhiteSpace(metaCmd2))
        {
            cmdLine = metaCmd2;
        }

        string imageName = "cmd.exe";
        if (evt.Metadata.TryGetValue("ImageName", out var img) && !string.IsNullOrWhiteSpace(img))
        {
            imageName = img;
        }
        else if (evt.Metadata.TryGetValue("ProcessName", out var pName) && !string.IsNullOrWhiteSpace(pName))
        {
            imageName = pName;
        }
        else if (!string.IsNullOrWhiteSpace(evt.SessionIdentity))
        {
            imageName = evt.SessionIdentity;
        }

        var parsed = ShellCommandParser.ParseShellExecution(imageName, cmdLine);
        string displayCmd = !string.IsNullOrWhiteSpace(parsed.Subcommand) ? parsed.Subcommand : cmdLine;
        string service = parsed.IsPowerShell ? "PowerShell" : (parsed.IsShellWrapper ? "CMD" : Path.GetFileNameWithoutExtension(imageName));

        int pid = 0;
        if (evt.Metadata.TryGetValue("ProcessId", out var pidStr)) int.TryParse(pidStr, out pid);

        var cmd = Correlation.Correlate(
            displayCmd,
            KnownProtocol.HostCommand,
            service,
            evt.Transport,
            evt.DeviceIdentity,
            evt.SessionIdentity,
            evt.Direction,
            sessionSeqs,
            sessionHashes,
            confidence: 0.98,
            suspectedPid: pid,
            suspectedToolName: imageName
        );

        cmd.Details["CommandLine"] = cmdLine;
        cmd.Details["NormalizedCommand"] = parsed.NormalizedCommand;
        if (!string.IsNullOrEmpty(parsed.DecodedScript))
        {
            cmd.Details["DecodedScript"] = parsed.DecodedScript;
        }
        if (parsed.IsPowerShell) cmd.Details["IsPowerShell"] = "True";
        if (parsed.IsShellWrapper) cmd.Details["IsShellWrapper"] = "True";
        if (parsed.IsBatchFile) cmd.Details["IsBatchFile"] = "True";

        if (evt.Metadata.TryGetValue("ParentProcessId", out var ppidStr) && int.TryParse(ppidStr, out int ppid))
        {
            cmd.Attribution.ParentProcessId = ppid;
        }
        if (evt.Metadata.TryGetValue("ImagePath", out var imgPath))
        {
            cmd.Attribution.ImagePath = imgPath;
        }
        if (pid > 0) cmd.Attribution.ProcessId = pid;
        cmd.Attribution.ImageName = imageName;
        cmd.Attribution.CommandLine = cmdLine;

        OnLogicalCommand?.Invoke(cmd);
    }

    private void DecodeInProcessStream(CaptureSessionKey key, byte[] stream, RawCaptureEvent evt)
    {
        (var sessionSeqs, var sessionHashes) = Reassembler.GetEvidenceSnapshot(key);
        if (sessionSeqs.Count == 0) sessionSeqs = [evt.SequenceNumber];
        if (sessionHashes.Count == 0 && !string.IsNullOrEmpty(evt.PayloadHash)) sessionHashes = [evt.PayloadHash];

        Reassembler.ConsumeStream(key, stream.Length);
        Interlocked.Increment(ref _decodedEvents);

        string opName = evt.Endpoint;
        if (string.IsNullOrWhiteSpace(opName))
        {
            opName = Encoding.UTF8.GetString(stream).Trim();
        }

        string toolName = evt.Metadata.TryGetValue("ToolName", out var tName) ? tName : evt.SessionIdentity;
        int pid = 0;
        if (evt.Metadata.TryGetValue("ProcessId", out var pidStr)) int.TryParse(pidStr, out pid);

        var cmd = Correlation.Correlate(
            opName,
            KnownProtocol.InProcess,
            toolName,
            evt.Transport,
            evt.DeviceIdentity,
            evt.SessionIdentity,
            evt.Direction,
            sessionSeqs,
            sessionHashes,
            confidence: 1.0,
            suspectedPid: pid,
            suspectedToolName: toolName
        );

        foreach (var kvp in evt.Metadata)
        {
            cmd.Details[kvp.Key] = kvp.Value;
        }

        if (pid > 0) cmd.Attribution.ProcessId = pid;
        cmd.Attribution.ImageName = toolName;

        OnLogicalCommand?.Invoke(cmd);
    }
}
