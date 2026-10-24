using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using PhoenixGSM.MonitoringStudio.Models;
using PhoenixGSM.OmniTrace.Decoders;

namespace PhoenixGSM.MonitoringStudio.Services;

public partial class MonitoringEngine
{
    private readonly object _adbStreamCoalesceLock = new();
    private readonly List<byte> _pendingAdbStreamBytes = new();
    private string _pendingAdbStreamEp = string.Empty;
    private uint _pendingAdbStreamTransferType;
    private CancellationTokenSource? _adbStreamFlushCts;

    private void HandleMtkPacket(
        PhoenixGSM.UsbMonitor.UsbDriverClient.KernelUsbPacket pkt,
        byte[] chunk,
        string dir,
        string epHex,
        PhoenixGSM.OmniTrace.Models.PacketDirection pDir,
        bool isUpperFilterPort,
        double mtkConf,
        string cleanLine)
    {
        var mtkPkt = PhoenixGSM.OmniTrace.Decoders.MtkProtocolDecoder.DecodePacket(chunk, pDir);
        string mtkStage = mtkPkt?.Stage ?? "MTK";
        string mtkCmd = mtkPkt?.CommandName ?? $"MTK_0x{chunk[0]:X2}";
        string mtkSummary = mtkPkt?.Summary ?? $"MediaTek Frame ({chunk.Length} B)";
        string mtkProto = mtkStage == "DA" ? "MTK-DA" : "MTK-BROM";
        string target = !string.IsNullOrEmpty(mtkPkt?.ChipName)
            ? mtkPkt.ChipName
            : (isUpperFilterPort ? ResolveModemPortName(chunk, cleanLine) : $"EP {epHex}");

        EmitEvent(new LiveEventItem
        {
            Timestamp = DateTime.UtcNow,
            Category = EventSourceCategory.MediaTek,
            SourceTag = mtkProto,
            Direction = dir,
            EndpointOrTarget = target,
            Protocol = mtkProto,
            Command = mtkCmd,
            Summary = $"[{mtkProto}] {dir}: {mtkSummary}",
            RawPayload = chunk,
            PayloadAscii = mtkPkt?.ToString() ?? "",
            PayloadHex = LiveEventItem.FormatHexDump(chunk),
            AdditionalDetails = $"TransferType: {pkt.TransferType}\nStage: {mtkStage}\nOpCode: 0x{chunk[0]:X2}\nConfidence: {mtkConf:P0}\nActualLength: {pkt.ActualLength} B\nSource: KernelDriver MTK Sniff"
        });

        if (_omniService != null)
        {
            try
            {
                var rawEvt = new PhoenixGSM.OmniTrace.Models.RawCaptureEvent
                {
                    Timestamp = DateTimeOffset.UtcNow,
                    Sensor = isUpperFilterPort ? PhoenixGSM.OmniTrace.Models.SensorType.Serial : PhoenixGSM.OmniTrace.Models.SensorType.USB,
                    Transport = isUpperFilterPort ? PhoenixGSM.OmniTrace.Models.TransportType.SERIAL : (pkt.TransferType == 0 ? PhoenixGSM.OmniTrace.Models.TransportType.CONTROL : PhoenixGSM.OmniTrace.Models.TransportType.BULK),
                    Direction = pDir,
                    DeviceIdentity = target,
                    Endpoint = epHex,
                    Length = chunk.Length,
                    RawPayload = chunk,
                    PayloadHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(chunk)),
                    Metadata = new Dictionary<string, string> { ["Source"] = "KernelDriver", ["Protocol"] = mtkProto, ["Endpoint"] = epHex }
                };
                _omniService.EventBus.Publish(rawEvt);
            }
            catch { }
        }
    }

    private void HandleSocketBridgePacket(
        byte[] chunk,
        string dir,
        string epHex,
        string cleanLine,
        string cleanLineTrimmed)
    {
        string bridgeTarget = !string.IsNullOrEmpty(_activeSocketBridgeChannel) ? _activeSocketBridgeChannel : cleanLineTrimmed;
        string bridgeCmd = cleanLineTrimmed.Length > 0 ? cleanLineTrimmed : $"[ADB-SOCKET-BRIDGE] ({chunk.Length}B): {Convert.ToHexString(chunk)}";

        EmitEvent(new LiveEventItem
        {
            Timestamp = DateTime.UtcNow,
            Category = EventSourceCategory.AdbProxy,
            SourceTag = "ADB-BRIDGE",
            Direction = dir,
            EndpointOrTarget = $"EP {epHex} -> {bridgeTarget}",
            Protocol = "ADB-SOCKET-BRIDGE",
            Command = bridgeCmd,
            Summary = $"[ADB-SOCKET-BRIDGE] {dir} -> {bridgeTarget}: {bridgeCmd}",
            RawPayload = chunk,
            PayloadAscii = cleanLine,
            PayloadHex = LiveEventItem.FormatHexDump(chunk),
            AdditionalDetails = $"Forwarded Bridge Channel: {bridgeTarget}\nDirection: {dir}\nLength: {chunk.Length} B\nSource: KernelDriver ADB Socket Bridge Sniff"
        });
    }

    private void HandleAppPrivilegePacket(
        byte[] chunk,
        string dir,
        string epHex,
        string cleanLine,
        string cleanLineTrimmed)
    {
        EmitEvent(new LiveEventItem
        {
            Timestamp = DateTime.UtcNow,
            Category = EventSourceCategory.AdbProxy,
            SourceTag = "ADB-PRIV",
            Direction = dir,
            EndpointOrTarget = $"EP {epHex}",
            Protocol = "ADB-PRIVILEGE-CMD",
            Command = cleanLineTrimmed,
            Summary = $"[ADB-PRIVILEGE-CMD] {dir}: {cleanLineTrimmed}",
            RawPayload = chunk,
            PayloadAscii = cleanLine,
            PayloadHex = LiveEventItem.FormatHexDump(chunk),
            AdditionalDetails = $"Privilege escalation command detected: {cleanLineTrimmed}\nDirection: {dir}\nLength: {chunk.Length} B"
        });
    }

    private void HandleAdbRilOrInteractivePacket(
        PhoenixGSM.UsbMonitor.UsbDriverClient.KernelUsbPacket pkt,
        byte[] chunk,
        string dir,
        string epHex,
        PhoenixGSM.OmniTrace.Models.PacketDirection pDir,
        bool isAdbRilIpc,
        string cleanLine,
        string cleanLineTrimmed)
    {
        if (dir == "OUT")
        {
            FlushPendingAdbStreamInbound();
        }

        string activeAtInstance = _smartFileArchiver.GetActiveArtifactInstanceLabel("/data/local/tmp/AT");
        string targetTool = isAdbRilIpc
            ? (!string.IsNullOrEmpty(activeAtInstance) ? activeAtInstance : (!string.IsNullOrEmpty(_lastActiveAtBinaryCommand) ? _lastActiveAtBinaryCommand : "/data/local/tmp/AT"))
            : (!string.IsNullOrEmpty(_activeInteractiveShellCommand) ? _activeInteractiveShellCommand : activeAtInstance);

        if (string.IsNullOrWhiteSpace(targetTool))
        {
            targetTool = _isPtySessionActive ? "shell,v2,pty:" : "shell:";
        }

        // 1. إذا كان الأمر المرسل هو فتح جلسة PTY أو Shell (مثل shell,v2,pty: أو pty:)
        if (dir == "OUT" && !isAdbRilIpc &&
            ShellStreamReconstructor.IsShellOrPtyOpenService(cleanLineTrimmed, out string svcHdr, out string innerCmd, out bool isPtyOpen, out bool isV2Open))
        {
            _isPtySessionActive = isPtyOpen;
            _isShellV2SessionActive = isV2Open;

            if (string.IsNullOrWhiteSpace(innerCmd))
            {
                // تم فتح جلسة تيرمنال تفاعلي PTY فارغة تنتظر إدخال الأوامر حرفاً بحرف أو سطراً بسطر
                EmitCompletedInteractiveOrPtyCommand(
                    pkt.TransferType,
                    chunk,
                    dir,
                    epHex,
                    pDir,
                    isAdbRilIpc: false,
                    isPtySession: isPtyOpen,
                    targetTool: svcHdr,
                    commandText: svcHdr);
                return;
            }
            else
            {
                // أمر مباشر مرفق مع فتح الجلسة (مثل shell,v2,pty:su -c id)
                EmitCompletedInteractiveOrPtyCommand(
                    pkt.TransferType,
                    chunk,
                    dir,
                    epHex,
                    pDir,
                    isAdbRilIpc: false,
                    isPtySession: isPtyOpen,
                    targetTool: svcHdr,
                    commandText: innerCmd);
                return;
            }
        }

        // 2. إذا كنا في جلسة PTY تفاعلية (أو تُرسل الحروف حرفاً بحرف بدون أو مع Enter):
        // نمرر البايتات عبر مجمع الأسطر التفاعلي _ptyInputReconstructor الذي يعالج الحروف المفردة و Backspace والأسهم!
        if (dir == "OUT" && !isAdbRilIpc && (_isPtySessionActive || chunk.Length <= 4 || !_ptyInputReconstructor.HasPendingInput == false))
        {
            string? completedPtyLine;
            lock (_ptyInputLock)
            {
                _lastPtyKeystrokeTime = DateTime.UtcNow;
                _ptyInputReconstructor.ProcessInputBytes(chunk, out completedPtyLine, out _);

                if (!string.IsNullOrWhiteSpace(completedPtyLine))
                {
                    _ptyIdleFlushCts?.Cancel();
                    _lastCompletedPtyCommand = completedPtyLine;
                }
                else if (_ptyInputReconstructor.HasPendingInput)
                {
                    // المستخدم أو الأداة تكتب حرفاً بحرف ولم تضغط Enter بعد:
                    // نضبط مؤقت 650ms لتفريغ السطر تلقائياً فقط إذا توقفت الكتابة ولم يُرسل \r\n (مثل إدخال مفتاح تفاعلي)
                    _ptyIdleFlushCts?.Cancel();
                    var cts = new CancellationTokenSource();
                    _ptyIdleFlushCts = cts;
                    uint savedTransferType = pkt.TransferType;
                    string savedTarget = targetTool;

                    _ = System.Threading.Tasks.Task.Run(async () =>
                    {
                        try
                        {
                            await System.Threading.Tasks.Task.Delay(650, cts.Token).ConfigureAwait(false);
                            string? flushed = null;
                            lock (_ptyInputLock)
                            {
                                if (_ptyInputReconstructor.TryFlushPendingLine(out string fl))
                                {
                                    flushed = fl;
                                    _lastCompletedPtyCommand = fl;
                                }
                            }
                            if (!string.IsNullOrWhiteSpace(flushed))
                            {
                                byte[] flBytes = Encoding.UTF8.GetBytes(flushed);
                                EmitCompletedInteractiveOrPtyCommand(
                                    savedTransferType,
                                    flBytes,
                                    "OUT",
                                    epHex,
                                    PhoenixGSM.OmniTrace.Models.PacketDirection.HOST_TO_DEVICE,
                                    isAdbRilIpc: false,
                                    isPtySession: _isPtySessionActive,
                                    targetTool: savedTarget,
                                    commandText: flushed);
                            }
                        }
                        catch (OperationCanceledException) { }
                    });
                    return;
                }
                else
                {
                    return;
                }
            }

            if (!string.IsNullOrWhiteSpace(completedPtyLine))
            {
                byte[] lineBytes = Encoding.UTF8.GetBytes(completedPtyLine);
                EmitCompletedInteractiveOrPtyCommand(
                    pkt.TransferType,
                    lineBytes,
                    dir,
                    epHex,
                    pDir,
                    isAdbRilIpc: false,
                    isPtySession: _isPtySessionActive,
                    targetTool: targetTool,
                    commandText: completedPtyLine);
                return;
            }
        }

        string rilCmdText = cleanLineTrimmed.Length > 0 ? cleanLineTrimmed : $"[ADB-INTERACTIVE-CMD] ({chunk.Length}B): {Convert.ToHexString(chunk)}";
        EmitCompletedInteractiveOrPtyCommand(
            pkt.TransferType,
            chunk,
            dir,
            epHex,
            pDir,
            isAdbRilIpc,
            _isPtySessionActive,
            targetTool,
            rilCmdText);
    }

    private void EmitCompletedInteractiveOrPtyCommand(
        uint transferType,
        byte[] chunk,
        string dir,
        string epHex,
        PhoenixGSM.OmniTrace.Models.PacketDirection pDir,
        bool isAdbRilIpc,
        bool isPtySession,
        string targetTool,
        string commandText)
    {
        string protoTag = isAdbRilIpc
            ? "ADB-RIL-IPC"
            : (isPtySession ? "ADB-PTY-CMD" : "ADB-INTERACTIVE-CMD");
        string sourceTag = isAdbRilIpc
            ? "ADB-RIL"
            : (isPtySession ? "ADB-PTY" : "ADB-SHELL");

        string decodedEmbedded = isAdbRilIpc ? DecodeEmbeddedRilOrAtHex(commandText) : string.Empty;
        string summaryText = !string.IsNullOrEmpty(decodedEmbedded)
            ? $"[{protoTag}] {dir} -> {targetTool}: {commandText} ({decodedEmbedded})"
            : $"[{protoTag}] {dir} -> {targetTool}: {commandText}";

        EmitEvent(new LiveEventItem
        {
            Timestamp = DateTime.UtcNow,
            Category = EventSourceCategory.AdbProxy,
            SourceTag = sourceTag,
            Direction = dir,
            EndpointOrTarget = $"EP {epHex} -> {targetTool}",
            Protocol = protoTag,
            Command = commandText,
            Summary = summaryText,
            RawPayload = chunk,
            PayloadAscii = !string.IsNullOrEmpty(decodedEmbedded) ? $"{commandText}\nDecoded Embedded Payload: {decodedEmbedded}" : commandText,
            PayloadHex = LiveEventItem.FormatHexDump(chunk),
            AdditionalDetails = $"Active Interactive Target: {targetTool}\nPTY Mode: {isPtySession} (Shell_v2: {_isShellV2SessionActive})\nDecoded Payload: {decodedEmbedded}\nTransferType: {transferType}\nDirection: {dir}\nActualLength: {chunk.Length} B\nSource: KernelDriver ADB/PTY Interactive Sniff"
        });

        if (_omniService != null)
        {
            try
            {
                _omniService.EventBus.Publish(new PhoenixGSM.OmniTrace.Models.RawCaptureEvent
                {
                    Timestamp = DateTimeOffset.UtcNow,
                    Sensor = PhoenixGSM.OmniTrace.Models.SensorType.USB,
                    Transport = PhoenixGSM.OmniTrace.Models.TransportType.BULK,
                    Direction = pDir,
                    DeviceIdentity = targetTool,
                    Endpoint = epHex,
                    Length = chunk.Length,
                    RawPayload = chunk,
                    PayloadHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(chunk)),
                    Metadata = new Dictionary<string, string>
                    {
                        ["Source"] = "KernelDriver",
                        ["Protocol"] = protoTag,
                        ["Endpoint"] = epHex,
                        ["Command"] = commandText,
                        ["ActiveShell"] = targetTool,
                        ["IsPty"] = isPtySession.ToString()
                    }
                });

                var logicalCmd = new PhoenixGSM.OmniTrace.Models.LogicalCommandEvent
                {
                    Command = commandText,
                    Protocol = PhoenixGSM.OmniTrace.Models.KnownProtocol.ADB,
                    Service = targetTool,
                    Transport = PhoenixGSM.OmniTrace.Models.TransportType.BULK,
                    DeviceIdentity = targetTool,
                    SessionIdentity = targetTool,
                    Direction = pDir,
                    Confidence = 0.99,
                    Timestamp = DateTime.UtcNow
                };
                logicalCmd.Details["ProtocolName"] = protoTag;
                logicalCmd.Details["CommandLine"] = commandText;
                logicalCmd.Details["EmittedByKernelDriver"] = "true";
                _omniService.EventBus.ReportLogicalCommand(logicalCmd);
            }
            catch { }
        }
    }

    private void HandleGetpropPacket(
        byte[] chunk,
        string dir,
        string epHex,
        string cleanLine,
        string cleanLineTrimmed)
    {
        _getpropAggregator.IngestChunk(cleanLine + "\n");
        _isAggregatingGetprop = true;
        _lastGetpropChunkTime = DateTime.UtcNow;

        if (cleanLineTrimmed.EndsWith("#") || cleanLineTrimmed.EndsWith("OK") || cleanLineTrimmed == "]")
        {
            FlushGetpropSummary(epHex, dir);
        }
    }

    private void HandleAdbStreamPacket(
        PhoenixGSM.UsbMonitor.UsbDriverClient.KernelUsbPacket pkt,
        byte[] chunk,
        string dir,
        string epHex,
        PhoenixGSM.OmniTrace.Models.PacketDirection pDir,
        bool isReadableInboundAdbResponse,
        string cleanedInboundText,
        string cleanLine)
    {
        if (dir == "IN")
        {
            string trimmedCheck = (cleanedInboundText ?? cleanLine).Trim();

            // 1. في وضع PTY، نتجاهل صدى الحروف المفردة الراجعة أثناء كتابة المستخدم قبل ضغط Enter
            lock (_ptyInputLock)
            {
                if (_ptyInputReconstructor.HasPendingInput && chunk.Length <= 4 && !chunk.Contains((byte)'\n'))
                {
                    return;
                }
            }

            // 2. نتجاهل صدى الأمر الكامل نفسه إذا رجع في أول شريحة من الـ PTY
            string strippedActive = ShellStreamReconstructor.StripShellOrPtyPrefix(_activeInteractiveShellCommand);
            if (trimmedCheck.Length > 0 &&
                !trimmedCheck.Equals(_activeInteractiveShellCommand, StringComparison.OrdinalIgnoreCase) &&
                !trimmedCheck.Equals(strippedActive, StringComparison.OrdinalIgnoreCase) &&
                !trimmedCheck.Equals(_lastCompletedPtyCommand, StringComparison.OrdinalIgnoreCase))
            {
                lock (_adbStreamCoalesceLock)
                {
                    _pendingAdbStreamBytes.AddRange(chunk);
                    _pendingAdbStreamEp = epHex;
                    _pendingAdbStreamTransferType = pkt.TransferType;

                    _adbStreamFlushCts?.Cancel();
                    var cts = new CancellationTokenSource();
                    _adbStreamFlushCts = cts;

                    int delayMs = (chunk.Length >= 400 || trimmedCheck.Contains("****") || trimmedCheck.Contains("Token")) ? 95 : 40;

                    _ = System.Threading.Tasks.Task.Run(async () =>
                    {
                        try
                        {
                            await System.Threading.Tasks.Task.Delay(delayMs, cts.Token).ConfigureAwait(false);
                            FlushPendingAdbStreamInbound();
                        }
                        catch (OperationCanceledException) { }
                    });
                    return;
                }
            }
            else if (trimmedCheck.Equals(_lastCompletedPtyCommand, StringComparison.OrdinalIgnoreCase))
            {
                // تجاهل صدى السطر المرسل للتو في جلسة PTY
                return;
            }
        }

        EmitAdbStreamEventImmediate(pkt.TransferType, chunk, dir, epHex, pDir);
    }

    private void FlushPendingAdbStreamInbound()
    {
        byte[] combinedBytes;
        string epHex;
        uint transferType;

        lock (_adbStreamCoalesceLock)
        {
            if (_pendingAdbStreamBytes.Count == 0) return;
            combinedBytes = _pendingAdbStreamBytes.ToArray();
            _pendingAdbStreamBytes.Clear();
            epHex = _pendingAdbStreamEp;
            transferType = _pendingAdbStreamTransferType;
        }

        EmitAdbStreamEventImmediate(
            transferType,
            combinedBytes,
            "IN",
            epHex,
            PhoenixGSM.OmniTrace.Models.PacketDirection.DEVICE_TO_HOST);
    }

    private void EmitAdbStreamEventImmediate(
        uint transferType,
        byte[] chunk,
        string dir,
        string epHex,
        PhoenixGSM.OmniTrace.Models.PacketDirection pDir)
    {
        string streamCmdText = CleanInboundPhoneResponse(chunk).Trim('\r', '\n');
        if (string.IsNullOrWhiteSpace(streamCmdText))
        {
            streamCmdText = ShellStreamReconstructor.CleanTerminalOutput(Encoding.UTF8.GetString(chunk)).Replace("\0", "").Trim('\r', '\n');
        }

        // إذا كان أول سطر في مخرجات PTY هو صدى الأمر المرسل، نزيل سطر الصدى ونبقي بقية المخرجات كاملة
        if (dir == "IN" && !string.IsNullOrWhiteSpace(_lastCompletedPtyCommand))
        {
            string normalized = streamCmdText.Replace("\r\n", "\n");
            int firstNl = normalized.IndexOf('\n');
            if (firstNl > 0)
            {
                string firstLine = normalized[..firstNl].Trim();
                if (firstLine.Equals(_lastCompletedPtyCommand, StringComparison.OrdinalIgnoreCase) ||
                    firstLine.EndsWith("# " + _lastCompletedPtyCommand, StringComparison.OrdinalIgnoreCase) ||
                    firstLine.EndsWith("$ " + _lastCompletedPtyCommand, StringComparison.OrdinalIgnoreCase))
                {
                    streamCmdText = normalized[(firstNl + 1)..].Replace("\n", Environment.NewLine).Trim('\r', '\n');
                }
            }
        }

        if (string.IsNullOrWhiteSpace(streamCmdText))
            return;

        EmitEvent(new LiveEventItem
        {
            Timestamp = DateTime.UtcNow,
            Category = EventSourceCategory.AdbProxy,
            SourceTag = dir == "OUT" ? "ADB-OUT" : (_isPtySessionActive ? "ADB-PTY-STREAM" : "ADB-STREAM"),
            Direction = dir,
            EndpointOrTarget = $"EP {epHex}",
            Protocol = "ADB-STREAM",
            Command = streamCmdText,
            Summary = $"[ADB-STREAM] {dir}: {streamCmdText}",
            RawPayload = chunk,
            PayloadAscii = streamCmdText,
            PayloadHex = LiveEventItem.FormatHexDump(chunk),
            AdditionalDetails = $"TransferType: {transferType}\nDirection: {dir}\nActualLength: {chunk.Length} B\nActiveShell: {_activeInteractiveShellCommand}\nPTY Mode: {_isPtySessionActive}\nSource: KernelDriver ADB/PTY Active Stream Sniff (Reassembled)"
        });

        if (_omniService != null)
        {
            try
            {
                _omniService.EventBus.Publish(new PhoenixGSM.OmniTrace.Models.RawCaptureEvent
                {
                    Timestamp = DateTimeOffset.UtcNow,
                    Sensor = PhoenixGSM.OmniTrace.Models.SensorType.USB,
                    Transport = PhoenixGSM.OmniTrace.Models.TransportType.BULK,
                    Direction = pDir,
                    DeviceIdentity = !string.IsNullOrEmpty(_activeInteractiveShellCommand) ? _activeInteractiveShellCommand : "Android Phone",
                    Endpoint = epHex,
                    Length = chunk.Length,
                    RawPayload = chunk,
                    PayloadHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(chunk)),
                    Metadata = new Dictionary<string, string>
                    {
                        ["Source"] = "KernelDriver",
                        ["Protocol"] = "ADB-STREAM",
                        ["Endpoint"] = epHex,
                        ["Command"] = streamCmdText,
                        ["ActiveShell"] = _activeInteractiveShellCommand,
                        ["IsPty"] = _isPtySessionActive.ToString()
                    }
                });
            }
            catch { }
        }
    }

    private void HandleAtOrModemPacket(
        PhoenixGSM.UsbMonitor.UsbDriverClient.KernelUsbPacket pkt,
        byte[] chunk,
        string dir,
        string epHex,
        PhoenixGSM.OmniTrace.Models.PacketDirection pDir,
        bool isAsciiText,
        double atConf,
        string cleanLine)
    {
        string tag = "MODEM-USB";
        string proto = "SERIAL-AT";
        var category = EventSourceCategory.SerialPort;

        string fullCommandText;
        string asciiPayload;
        if (isAsciiText)
        {
            if (string.IsNullOrEmpty(cleanLine))
            {
                fullCommandText = (chunk.Length == 1 && chunk[0] == '\r') ? "<CR>" :
                                  (chunk.Length == 1 && chunk[0] == '\n') ? "<LF>" : "<CRLF>";
                asciiPayload = fullCommandText;
            }
            else
            {
                fullCommandText = cleanLine;
                asciiPayload = Encoding.ASCII.GetString(chunk).Trim('\0');
            }
        }
        else
        {
            if (chunk.Length >= 2 && chunk[0] == 0x7E)
            {
                proto = "QUALCOMM-DIAG";
                fullCommandText = $"[DIAG 0x7E] ({chunk.Length}B): {Convert.ToHexString(chunk)}";
                asciiPayload = Encoding.ASCII.GetString(chunk.Select(b => b >= 32 && b < 127 ? b : (byte)'.').ToArray());
            }
            else
            {
                proto = "MODEM-BINARY";
                fullCommandText = $"[MODEM-BIN] ({chunk.Length}B): {Convert.ToHexString(chunk)}";
                asciiPayload = Encoding.ASCII.GetString(chunk.Select(b => b >= 32 && b < 127 ? b : (byte)'.').ToArray());
            }
        }

        EmitEvent(new LiveEventItem
        {
            Timestamp = DateTime.UtcNow,
            Category = category,
            SourceTag = tag,
            Direction = dir,
            EndpointOrTarget = $"EP {epHex}",
            Protocol = proto,
            Command = fullCommandText,
            Summary = $"[MODEM-USB] {dir}: {fullCommandText} ({Math.Max(atConf, 0.90):P0} conf)",
            RawPayload = chunk,
            PayloadAscii = asciiPayload,
            PayloadHex = LiveEventItem.FormatHexDump(chunk),
            AdditionalDetails = $"TransferType: {pkt.TransferType}\nDirection: {dir}\nActualLength: {pkt.ActualLength} B\nCaptured: {pkt.CapturedLength} B\nSource: UpperFilter Passive Sniff"
        });

        if (_omniService != null)
        {
            try
            {
                string portName = ResolveModemPortName(chunk, cleanLine);

                if (_omniService.SerialSensor != null)
                {
                    _omniService.SerialSensor.IngestCapturedPortTraffic(portName, chunk, pDir, "KernelDriverUpperFilter");
                }
                else
                {
                    _omniService.EventBus.Publish(new PhoenixGSM.OmniTrace.Models.RawCaptureEvent
                    {
                        Timestamp = DateTimeOffset.UtcNow,
                        Sensor = PhoenixGSM.OmniTrace.Models.SensorType.Serial,
                        Transport = PhoenixGSM.OmniTrace.Models.TransportType.SERIAL,
                        Direction = pDir,
                        DeviceIdentity = $"Modem ({portName})",
                        Endpoint = epHex,
                        Length = chunk.Length,
                        RawPayload = chunk,
                        PayloadHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(chunk)),
                        Metadata = new Dictionary<string, string> { ["Source"] = "KernelDriverUpperFilter", ["Endpoint"] = epHex, ["Port"] = portName }
                    });
                }
            }
            catch { }
        }
    }

    private static bool IsHexDumpPreview(string preview, byte[]? rawPayload)
    {
        if (rawPayload != null && rawPayload.Length > 0)
        {
            // لا نحجب حزم Shell v2 الصالحة
            if (ShellStreamReconstructor.TryUnpackShellV2Frames(rawPayload, out _, out _, out _, out _))
                return false;

            int nonPrintable = 0;
            foreach (byte b in rawPayload)
            {
                if (b < 32 && b != 9 && b != 10 && b != 13 && b != 0 && b != 0x1B && b != 0x08 && b != 0x7F) nonPrintable++;
                else if (b > 126 && b != 0x7F) nonPrintable++;
            }
            if (nonPrintable > rawPayload.Length / 5) return true;
        }

        if (string.IsNullOrWhiteSpace(preview)) return true;
        string trimmed = preview.Trim();
        if (trimmed.StartsWith("00 00 ", StringComparison.Ordinal) ||
            trimmed.EndsWith("bytes total)", StringComparison.Ordinal))
        {
            return true;
        }

        if (trimmed.Length >= 8 && trimmed.IndexOf(' ') == 2)
        {
            string[] parts = trimmed.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 3 && parts.All(p => p.Length == 2 && Uri.IsHexDigit(p[0]) && Uri.IsHexDigit(p[1])))
            {
                return true;
            }
        }

        return false;
    }

    private void HandleAdbFrameOrRawUsbPacket(
        PhoenixGSM.UsbMonitor.UsbDriverClient.KernelUsbPacket pkt,
        byte[] chunk,
        string dir,
        string epHex,
        PhoenixGSM.OmniTrace.Models.PacketDirection pDir,
        bool isUpperFilterPort,
        bool isAdbHeader,
        bool isBinaryPayloadChunk,
        bool isAdbSyncToken,
        string rawAsciiPreview,
        string cleanLineTrimmed)
    {
        var frames = _adbParser.ProcessChunk(chunk, dir, "Android Phone", "", "", 1, epHex);

        if (frames != null && frames.Count > 0)
        {
            _isAdbSessionActive = true;
            foreach (var frame in frames)
            {
                if (frame.Command == "CLSE")
                {
                    _smartFileArchiver.FlushIfActive(out _, isClseSignal: true);
                    if (!_smartFileArchiver.IsInsideTransfer)
                    {
                        _isInsideFileSyncTransfer = false;
                    }
                    continue;
                }

                if (frame.Command == "OKAY")
                {
                    continue;
                }

                string payloadPreview = frame.PayloadPreview ?? "";
                if (payloadPreview.Contains(".phx_keep_", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (frame.Command == "OPEN")
                {
                    if (payloadPreview.Contains("sync:"))
                    {
                        _isInsideFileSyncTransfer = true;
                        _activeInteractiveShellCommand = string.Empty;
                        _isPtySessionActive = false;
                    }
                    else
                    {
                        _isInsideFileSyncTransfer = false;
                        if (ShellStreamReconstructor.IsShellOrPtyOpenService(payloadPreview, out string svcHdr, out string innerCmd, out bool openPty, out bool openV2))
                        {
                            _activeInteractiveShellCommand = payloadPreview.Trim();
                            _isPtySessionActive = openPty;
                            _isShellV2SessionActive = openV2;

                            if (_activeInteractiveShellCommand.Contains("/data/local/tmp/AT", StringComparison.OrdinalIgnoreCase) &&
                                !_activeInteractiveShellCommand.Contains("chmod ", StringComparison.OrdinalIgnoreCase))
                            {
                                _lastActiveAtBinaryCommand = _smartFileArchiver.GetActiveArtifactInstanceLabel("/data/local/tmp/AT");
                            }

                            if (_smartFileArchiver.CheckShellCommandForInlineFileOrFlush(_activeInteractiveShellCommand, 0, "adb.exe", out var shellRec) && shellRec != null)
                            {
                                EmitCapturedPushedFile(shellRec, epHex);
                            }
                        }
                        else if (PhoenixGSM.OmniTrace.Decoders.AdbSmartSocketDecoder.IsSocketBridgeChannel(payloadPreview) ||
                                 PhoenixGSM.OmniTrace.Decoders.AdbSmartSocketDecoder.IsModernAndroidService(payloadPreview))
                        {
                            _activeSocketBridgeChannel = payloadPreview.Trim();
                        }
                    }
                }

                if (frame.Command == "WRTE")
                {
                    if (_isInsideFileSyncTransfer ||
                        _smartFileArchiver.IsInsideTransfer ||
                        epHex.Equals("0x8D", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    // إذا كانت حزمة WRTE تحتوي على إطار Shell v2 PTY، نقوم بفكها وتنظيفها!
                    if (frame.Payload != null &&
                        ShellStreamReconstructor.TryUnpackShellV2Frames(frame.Payload, out _, out byte[] unpackedWrte, out bool isCtrlOnly, out _))
                    {
                        if (isCtrlOnly)
                            continue;

                        payloadPreview = ShellStreamReconstructor.CleanTerminalOutput(Encoding.UTF8.GetString(unpackedWrte)).Trim('\0', '\r', '\n');
                    }
                    else if (IsHexDumpPreview(payloadPreview, frame.Payload))
                    {
                        continue;
                    }
                }

                string pTrim = payloadPreview.Trim();
                bool isDuplicateWireHeader = pTrim.Contains("43 4C 53 45") ||
                                             pTrim.Contains("4F 4B 41 59") ||
                                             pTrim.Contains("57 52 54 45") ||
                                             pTrim.Contains("F7 2D E6 F4") ||
                                             pTrim.Contains("4E 45 50 4F") ||
                                             pTrim.Contains("4E 58 4E 43") ||
                                             pTrim.EndsWith("bytes total)") ||
                                             pTrim.Contains("OPEN CLSE") ||
                                             pTrim.Equals("WRTEa", StringComparison.Ordinal);

                if (isDuplicateWireHeader)
                {
                    continue;
                }

                string cmdDisplay = (!string.IsNullOrEmpty(payloadPreview) && (frame.Command == "OPEN" || frame.Command == "WRTE"))
                    ? $"{frame.Command} -> {payloadPreview}"
                    : frame.Command;

                EmitEvent(new LiveEventItem
                {
                    Timestamp = frame.Timestamp,
                    Category = EventSourceCategory.UsbDriver,
                    SourceTag = "USB-DRV",
                    Direction = frame.Direction,
                    EndpointOrTarget = $"EP {frame.Endpoint}",
                    Protocol = !string.IsNullOrWhiteSpace(frame.Protocol) ? frame.Protocol : "ADB-USB",
                    Command = cmdDisplay,
                    Summary = frame.GetDetailSummary(),
                    RawPayload = frame.Payload,
                    PayloadAscii = payloadPreview,
                    PayloadHex = LiveEventItem.FormatHexDump(frame.Payload ?? Array.Empty<byte>()),
                    AdditionalDetails = $"Arg0=0x{frame.Arg0:X8}, Arg1=0x{frame.Arg1:X8}, Length={frame.DataLength} B, Checksum=0x{frame.DataCheck:X8}"
                });
            }
        }
        else if (chunk.Length > 0)
        {
            if (chunk.Length == 24 && isAdbHeader)
            {
                // Suppress duplicate 24-byte ADB wire header
            }
            else
            {
                bool isRepeatedBinaryPattern = rawAsciiPreview.Contains("d8d8d8d8") ||
                                               rawAsciiPreview.Contains("FW22222") ||
                                               rawAsciiPreview.Contains("a4..?HR") ||
                                               rawAsciiPreview.Contains("I7..MS") ||
                                               rawAsciiPreview.Contains("..a4") ||
                                               rawAsciiPreview.Contains("..I7");

                bool isFileTransferInProgress = _smartFileArchiver.IsInsideTransfer || _isInsideFileSyncTransfer;

                if (isFileTransferInProgress || isBinaryPayloadChunk || isRepeatedBinaryPattern || isAdbSyncToken)
                {
                    // Suppress individual binary / sync chunks during file upload
                }
                else
                {
                    if (chunk.Length <= 5 && (cleanLineTrimmed == "." || cleanLineTrimmed == "[1]." || cleanLineTrimmed == "" || cleanLineTrimmed == "[1]" || cleanLineTrimmed == ".."))
                    {
                        return;
                    }

                    string tag = pkt.TransferType == 0 ? "USB-CTRL" : "USB-RAW";
                    string proto = pkt.TransferType == 0 ? "CONTROL" : "RAW-BULK";
                    string fullAscii = Encoding.ASCII.GetString(chunk.Select(b => b >= 32 && b < 127 ? b : (byte)'.').ToArray());

                    EmitEvent(new LiveEventItem
                    {
                        Timestamp = DateTime.UtcNow,
                        Category = EventSourceCategory.UsbDriver,
                        SourceTag = tag,
                        Direction = dir,
                        EndpointOrTarget = $"EP {epHex}",
                        Protocol = proto,
                        Command = $"DATA {dir} ({chunk.Length}B)",
                        Summary = $"[{tag}] {dir} {chunk.Length}B: {fullAscii}",
                        RawPayload = chunk,
                        PayloadAscii = fullAscii,
                        PayloadHex = LiveEventItem.FormatHexDump(chunk),
                        AdditionalDetails = $"TransferType: {pkt.TransferType}\nDirection: {dir}\nActualLength: {pkt.ActualLength} B\nCaptured: {pkt.CapturedLength} B"
                    });
                }
            }
        }

        if (chunk.Length > 0 && _omniService != null && !isBinaryPayloadChunk && !_isInsideFileSyncTransfer && !_smartFileArchiver.IsInsideTransfer && !(_isAdbSessionActive && !isUpperFilterPort))
        {
            try
            {
                _omniService.EventBus.Publish(new PhoenixGSM.OmniTrace.Models.RawCaptureEvent
                {
                    Timestamp = DateTimeOffset.UtcNow,
                    Sensor = PhoenixGSM.OmniTrace.Models.SensorType.USB,
                    Transport = pkt.TransferType == 0 ? PhoenixGSM.OmniTrace.Models.TransportType.CONTROL : PhoenixGSM.OmniTrace.Models.TransportType.BULK,
                    Direction = pDir,
                    DeviceIdentity = "Android Phone",
                    Endpoint = epHex,
                    Length = chunk.Length,
                    RawPayload = chunk,
                    PayloadHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(chunk)),
                    Metadata = new Dictionary<string, string> { ["Source"] = "KernelDriver", ["Endpoint"] = epHex }
                });
            }
            catch { }
        }
    }
}
