using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using PhoenixGSM.OmniTrace.Bus;
using PhoenixGSM.OmniTrace.Models;
using PhoenixGSM.OmniTrace.ToolSourceInterception;
using PhoenixOmniTrace.L24_SourceSentinel.Models;

namespace PhoenixOmniTrace.L24_SourceSentinel.Core;

public sealed class WinUsbFilterAdbBridge : IDisposable
{
    private readonly Action<SourceTelemetryEvent> _eventSink;
    private readonly List<OmniTraceEventBus> _attachedBuses = new();
    private bool _isDisposed;

    public WinUsbFilterAdbBridge(Action<SourceTelemetryEvent> eventSink)
    {
        _eventSink = eventSink ?? throw new ArgumentNullException(nameof(eventSink));
    }

    public void Attach(OmniTraceEventBus bus)
    {
        if (_isDisposed || bus == null) return;
        lock (_attachedBuses)
        {
            if (_attachedBuses.Contains(bus)) return;
            _attachedBuses.Add(bus);
        }

        bus.OnLogicalCommand += HandleLogicalCommand;
        bus.OnRawCaptured += HandleRawCaptured;
    }

    public void Detach()
    {
        lock (_attachedBuses)
        {
            foreach (var bus in _attachedBuses)
            {
                bus.OnLogicalCommand -= HandleLogicalCommand;
                bus.OnRawCaptured -= HandleRawCaptured;
            }
            _attachedBuses.Clear();
        }
    }

    private void HandleLogicalCommand(LogicalCommandEvent cmd)
    {
        if (_isDisposed || cmd == null) return;

        string proto = cmd.Details.TryGetValue("ProtocolName", out var pVal) ? pVal : (cmd.Protocol.ToString() ?? "");
        string commandText = (cmd.Command ?? "").Trim();
        if (string.IsNullOrWhiteSpace(commandText)) return;

        if (commandText.Equals("SUBPROCESS_EXECUTION", StringComparison.OrdinalIgnoreCase))
        {
            if (cmd.Details.TryGetValue("CommandLine", out var subCli) && !string.IsNullOrWhiteSpace(subCli))
                commandText = subCli.Trim();
            else
                return;
        }

        string? callerTool = cmd.Attribution?.ImageName;
        if (string.IsNullOrWhiteSpace(callerTool))
        {
            callerTool = cmd.Details.TryGetValue("Caller", out var clr) && !string.IsNullOrWhiteSpace(clr)
                ? clr
                : (!string.IsNullOrWhiteSpace(cmd.Service) ? cmd.Service : "OmniTraceBus");
        }

        int pid = cmd.Attribution?.ProcessId ?? 0;
        if (pid == 0 && cmd.Details.TryGetValue("PID", out var pidStr))
            int.TryParse(pidStr, out pid);

        string targetRes = !string.IsNullOrWhiteSpace(cmd.DeviceIdentity) ? cmd.DeviceIdentity : cmd.Service;
        string summary = cmd.Details.TryGetValue("Summary", out var sum) && !string.IsNullOrWhiteSpace(sum)
            ? sum
            : commandText;
        string techDetails = cmd.Details.TryGetValue("TechnicalDetails", out var td) && !string.IsNullOrWhiteSpace(td)
            ? td
            : string.Empty;

        string fullDesc = !string.IsNullOrWhiteSpace(techDetails) && !summary.Contains(techDetails, StringComparison.Ordinal)
            ? $"{summary} | {techDetails.Replace("\r\n", " | ").Replace("\n", " | ")}"
            : summary;

        byte[] rawBytes = Encoding.UTF8.GetBytes(!string.IsNullOrWhiteSpace(techDetails) ? techDetails : commandText);
        string dirStr = cmd.Direction == PacketDirection.HOST_TO_DEVICE ? "OUT" : "IN";
        string catHint = cmd.Details.TryGetValue("Category", out var cHint) ? cHint : "";
        string sourceTag = cmd.Details.TryGetValue("SourceTag", out var sTag) ? sTag : "";

        // 1. MediaTek BROM / Preloader / DA / XFlash / UI Action / Live Session / Filter / PnP Arrival
        if (cmd.Protocol is KnownProtocol.MtkBrom or KnownProtocol.MtkDa ||
            proto.Contains("MTK", StringComparison.OrdinalIgnoreCase) ||
            catHint.Equals("MediaTek", StringComparison.OrdinalIgnoreCase) ||
            sourceTag.Contains("MTK", StringComparison.OrdinalIgnoreCase) ||
            commandText.Contains("BROM", StringComparison.OrdinalIgnoreCase) ||
            commandText.Contains("VID_0E8D", StringComparison.OrdinalIgnoreCase) ||
            targetRes.Contains("0E8D", StringComparison.OrdinalIgnoreCase))
        {
            string mtkCategory = cmd.Protocol == KnownProtocol.MtkDa || proto.Contains("DA", StringComparison.OrdinalIgnoreCase)
                ? "MediaTek DA Executed Command"
                : "MediaTek BROM / Service Execution";

            _eventSink(new SourceTelemetryEvent
            {
                ProcessId = pid,
                ThreadId = 0,
                Stage = SentinelStage.RawCommandExecution,
                HookedApiName = "L24_MtkProtocolBridge",
                CallerModuleOrigin = $"{callerTool} -> MTK ({dirStr})",
                TargetResource = string.IsNullOrWhiteSpace(targetRes) ? "USB\\VID_0E8D&PID_0003 (MTK)" : targetRes,
                CommandCategory = mtkCategory,
                DecodedCommandText = $"[{mtkCategory}] ({dirStr}) على [{targetRes}]: {fullDesc}",
                PureCommandText = commandText,
                PayloadSize = rawBytes.Length,
                RawPayloadHex = Convert.ToHexString(rawBytes)
            });
            return;
        }

        // 2. Apple iOS / iPadOS All 7 Modes
        if (cmd.Protocol is KnownProtocol.AppleUsbmuxd or KnownProtocol.AppleLockdown or KnownProtocol.AppleRecovery or
            KnownProtocol.AppleDfu or KnownProtocol.AppleRamdiskSsh or KnownProtocol.ApplePurpleDiag ||
            catHint.Equals("AppleIos", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("APPLE", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("IBOOT", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("LOCKDOWN", StringComparison.OrdinalIgnoreCase))
        {
            string appleCategory = $"Apple {cmd.Protocol}";
            _eventSink(new SourceTelemetryEvent
            {
                ProcessId = pid,
                ThreadId = 0,
                Stage = SentinelStage.RawCommandExecution,
                HookedApiName = "L24_AppleProtocolBridge",
                CallerModuleOrigin = $"{callerTool} -> {appleCategory}",
                TargetResource = string.IsNullOrWhiteSpace(targetRes) ? "Apple USB / Lockdown" : targetRes,
                CommandCategory = appleCategory,
                DecodedCommandText = $"[{appleCategory}] ({dirStr}): {fullDesc}",
                PureCommandText = commandText,
                PayloadSize = rawBytes.Length,
                RawPayloadHex = Convert.ToHexString(rawBytes)
            });
            return;
        }

        // 3. Modem AT / Serial COM Port / Qualcomm DIAG / Staged AT Commands
        if (cmd.Protocol == KnownProtocol.SerialAt ||
            proto.Contains("SERIAL", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("AT", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("DIAG", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("MODEM", StringComparison.OrdinalIgnoreCase))
        {
            bool isReply = cmd.Direction == PacketDirection.DEVICE_TO_HOST || commandText.StartsWith("<<");
            string cleanAt = commandText.TrimStart('<', '>', ' ');
            string modemCat = isReply ? "Modem Phone Response" : "Modem AT Command";

            _eventSink(new SourceTelemetryEvent
            {
                ProcessId = pid,
                ThreadId = 0,
                Stage = SentinelStage.RawCommandExecution,
                HookedApiName = "L24_ModemSerialBridge",
                CallerModuleOrigin = $"{callerTool} -> {targetRes}",
                TargetResource = string.IsNullOrWhiteSpace(targetRes) ? "COM / Modem Port" : targetRes,
                CommandCategory = modemCat,
                DecodedCommandText = isReply
                    ? $"رد المودم/الهاتف على [{targetRes}]: {cleanAt}"
                    : $"أمر مودم/بورت صادر إلى [{targetRes}]: {cleanAt}",
                PureCommandText = cleanAt,
                PayloadSize = rawBytes.Length,
                RawPayloadHex = Convert.ToHexString(rawBytes)
            });
            return;
        }

        // 4. Qualcomm EDL (Sahara / Firehose) & Unisoc SPD & Fastboot & Odin & MTP
        if (cmd.Protocol is KnownProtocol.QualcommSahara or KnownProtocol.QualcommFirehose or
            KnownProtocol.SpreadtrumFdl or KnownProtocol.Fastboot or KnownProtocol.SamsungOdin or KnownProtocol.Mtp ||
            catHint is "QualcommEdl" or "UnisocSpd" or "Samsung")
        {
            string protoCategory = cmd.Protocol switch
            {
                KnownProtocol.QualcommFirehose => "Qualcomm Firehose XML",
                KnownProtocol.QualcommSahara => "Qualcomm Sahara / EDL 9008",
                KnownProtocol.SpreadtrumFdl => "Unisoc / SPD BSL Frame",
                KnownProtocol.Fastboot => "Fastboot Command",
                KnownProtocol.SamsungOdin => "Samsung Odin Protocol",
                KnownProtocol.Mtp => "MTP Protocol Command",
                _ => !string.IsNullOrWhiteSpace(catHint) ? catHint : proto
            };

            _eventSink(new SourceTelemetryEvent
            {
                ProcessId = pid,
                ThreadId = 0,
                Stage = SentinelStage.RawCommandExecution,
                HookedApiName = "L24_ChipsetProtocolBridge",
                CallerModuleOrigin = $"{callerTool} -> {protoCategory}",
                TargetResource = string.IsNullOrWhiteSpace(targetRes) ? protoCategory : targetRes,
                CommandCategory = protoCategory,
                DecodedCommandText = $"[{protoCategory}] ({dirStr}): {fullDesc}",
                PureCommandText = commandText,
                PayloadSize = rawBytes.Length,
                RawPayloadHex = Convert.ToHexString(rawBytes)
            });
            return;
        }

        // 5. ADB / Interactive Shell / RIL IPC Commands & Responses
        if (cmd.Protocol == KnownProtocol.ADB ||
            proto.Contains("ADB", StringComparison.OrdinalIgnoreCase))
        {
            bool isRilIpc = proto.Contains("ADB-RIL-IPC", StringComparison.OrdinalIgnoreCase);
            // تجاهل أوامر ADB العادية إذا لم تكن أوامر مودم RIL IPC وذلك لمنع تلوث تبويب الأوامر المنفذة بأوامر ADB
            if (!isRilIpc)
                return;

            if (!IsCleanPrintableOrHexCommand(commandText))
                return;

            string cli = cmd.Details.TryGetValue("CommandLine", out var cLine) && !string.IsNullOrWhiteSpace(cLine)
                ? cLine.Trim()
                : commandText;

            string adbCategory = "ADB RIL / AT IPC Command";
            string targetService = !string.IsNullOrWhiteSpace(cmd.Service) ? cmd.Service : "/data/local/tmp/AT";

            _eventSink(new SourceTelemetryEvent
            {
                ProcessId = pid,
                ThreadId = 0,
                Stage = SentinelStage.RawCommandExecution,
                HookedApiName = "WinUsbFilterAdbBridge",
                CallerModuleOrigin = $"{callerTool} -> {targetService}",
                TargetResource = targetService,
                CommandCategory = adbCategory,
                DecodedCommandText = cmd.Direction == PacketDirection.HOST_TO_DEVICE
                    ? $"أمر ADB مرسل للهاتف ({targetService}): {cli}"
                    : $"رد الهاتف عبر ADB ({targetService}): {cli}",
                PureCommandText = cli,
                PayloadSize = rawBytes.Length,
                RawPayloadHex = Convert.ToHexString(rawBytes)
            });
            return;
        }

        // 6. General HostCommand / InProcess / Extraction / Decryption / Tool Operations
        if (cmd.Protocol is KnownProtocol.HostCommand or KnownProtocol.InProcess)
        {
            string cli = cmd.Details.TryGetValue("CommandLine", out var cLine) && !string.IsNullOrWhiteSpace(cLine)
                ? cLine.Trim()
                : commandText;

            string opType = cmd.Details.TryGetValue("OperationType", out var op) && !string.IsNullOrWhiteSpace(op)
                ? op
                : "Tool Command Execution";

            _eventSink(new SourceTelemetryEvent
            {
                ProcessId = pid,
                ThreadId = 0,
                Stage = SentinelStage.RawCommandExecution,
                HookedApiName = "L24_ToolExecutionBridge",
                CallerModuleOrigin = $"{callerTool} ({opType})",
                TargetResource = string.IsNullOrWhiteSpace(targetRes) ? callerTool : targetRes,
                CommandCategory = opType,
                DecodedCommandText = $"[{opType}] من [{callerTool}]: {fullDesc}",
                PureCommandText = cli,
                PayloadSize = rawBytes.Length,
                RawPayloadHex = Convert.ToHexString(rawBytes)
            });
        }
    }

    private void HandleRawCaptured(RawCaptureEvent raw)
    {
        if (_isDisposed || raw == null) return;

        string proto = raw.Metadata != null && raw.Metadata.TryGetValue("Protocol", out var pVal) ? pVal : "";
        string dir = raw.Direction == PacketDirection.HOST_TO_DEVICE ? "OUT" : "IN";
        string portOrEp = raw.Metadata != null && raw.Metadata.TryGetValue("Port", out var portVal) && !string.IsNullOrWhiteSpace(portVal)
            ? portVal
            : (!string.IsNullOrWhiteSpace(raw.Endpoint) ? raw.Endpoint : raw.DeviceIdentity);

        int pid = 0;
        if (raw.Metadata != null && raw.Metadata.TryGetValue("ProcessId", out var pidStr))
            int.TryParse(pidStr, out pid);

        string procName = raw.Metadata != null && raw.Metadata.TryGetValue("ProcessName", out var pName) && !string.IsNullOrWhiteSpace(pName)
            ? pName
            : (raw.Metadata != null && raw.Metadata.TryGetValue("ToolName", out var tName) && !string.IsNullOrWhiteSpace(tName) ? tName : "Network/Bus");

        // 1. Network URLs, Links, DNS, HTTP, TLS SNI, and Cloud File Requests (from NetworkUrlSensor & ClipboardUrlSensor!)
        if (raw.Sensor == SensorType.Network ||
            (raw.Metadata != null && raw.Metadata.ContainsKey("Url")))
        {
            string url = raw.Metadata != null && raw.Metadata.TryGetValue("Url", out var uVal) && !string.IsNullOrWhiteSpace(uVal)
                ? uVal
                : (raw.RawPayload != null && raw.RawPayload.Length > 0 ? Encoding.UTF8.GetString(raw.RawPayload).Trim() : raw.DeviceIdentity);

            if (string.IsNullOrWhiteSpace(url)) return;

            string method = raw.Metadata != null && raw.Metadata.TryGetValue("Method", out var mVal) ? mVal : "GET";
            string srcTag = raw.Metadata != null && raw.Metadata.TryGetValue("SourceTag", out var sVal) ? sVal : "NET-URL";
            string host = raw.Metadata != null && raw.Metadata.TryGetValue("Host", out var hVal) ? hVal : raw.DeviceIdentity;

            byte[] urlBytes = Encoding.UTF8.GetBytes(url);
            _eventSink(new SourceTelemetryEvent
            {
                ProcessId = pid,
                ThreadId = 0,
                Stage = SentinelStage.NetworkPreEncryption,
                HookedApiName = $"L24_NetworkUrlBridge ({srcTag})",
                CallerModuleOrigin = $"{procName} (PID {pid})",
                TargetResource = !string.IsNullOrWhiteSpace(host) ? host : url,
                CommandCategory = "Network URL / Server Connection",
                DecodedCommandText = $"🌐 رابط/اتصال خادم [{srcTag}] ({method}) من [{procName}]: {url}",
                PureCommandText = url,
                PayloadSize = urlBytes.Length,
                RawPayloadHex = Convert.ToHexString(urlBytes)
            });
            return;
        }

        // 2. FileSystem / TempFileAt / Pushed Artifacts -> Auto-Save to L24FileArchiver!
        if (raw.Sensor == SensorType.FileSystem && raw.RawPayload != null && raw.RawPayload.Length > 0)
        {
            string filePath = raw.DeviceIdentity ?? "StagedFile.bin";
            string savedPath = string.Empty;
            if (!File.Exists(filePath) || !L24FileArchiver.TryArchiveDiscoveredFile(filePath, $"BusFileSystem ({procName})", out savedPath, out _, out _))
            {
                L24FileArchiver.TryArchiveRawBuffer(raw.RawPayload, Path.GetFileName(filePath), $"BusFileSystemRaw ({procName})", out savedPath, out _, out _);
            }

            string saveBadge = !string.IsNullOrWhiteSpace(savedPath) ? $" | 💾 تم حفظ نسخة: [{Path.GetFileName(savedPath)}]" : "";
            _eventSink(new SourceTelemetryEvent
            {
                ProcessId = pid,
                ThreadId = 0,
                Stage = SentinelStage.LocalFilePreparation,
                HookedApiName = "L24_FileSystemBridge",
                CallerModuleOrigin = procName,
                TargetResource = !string.IsNullOrWhiteSpace(savedPath) ? savedPath : filePath,
                CommandCategory = "Archived Helper / Loader File",
                DecodedCommandText = $"📁 رصد وحفظ ملف مرحلي [{Path.GetFileName(filePath)}] ({raw.RawPayload.Length:N0} بايت){saveBadge}",
                PureCommandText = filePath,
                SavedFilePath = savedPath,
                PayloadSize = raw.RawPayload.Length,
                RawPayloadHex = Convert.ToHexString(raw.RawPayload.AsSpan(0, Math.Min(raw.RawPayload.Length, 256)))
            });
            return;
        }

        if (raw.RawPayload == null || raw.RawPayload.Length == 0) return;

        // 3. Raw MTK BROM / DA / XFlash Traffic (works for ANY packet size, including > 64 bytes and XFlash EF EE EE FE!)
        bool isMtkDeviceOrProto = proto.Contains("MTK", StringComparison.OrdinalIgnoreCase) ||
                                  (raw.DeviceIdentity != null && (raw.DeviceIdentity.Contains("0E8D", StringComparison.OrdinalIgnoreCase) || raw.DeviceIdentity.Contains("MTK", StringComparison.OrdinalIgnoreCase))) ||
                                  portOrEp.Contains("0E8D", StringComparison.OrdinalIgnoreCase) ||
                                  portOrEp.Contains("cdcacm", StringComparison.OrdinalIgnoreCase) ||
                                  portOrEp.Contains("vcom", StringComparison.OrdinalIgnoreCase);

        if (isMtkDeviceOrProto ||
            PhoenixGSM.OmniTrace.Decoders.MtkProtocolDecoder.EvaluateMtk(raw.RawPayload) >= 0.70 ||
            (raw.RawPayload.Length >= 4 && MtkBromSourceInterceptor.TryParseMtkCommand(raw.RawPayload, procName, pid, 0, portOrEp, "USB/VCOM", out _)))
        {
            string mtkCat = "MediaTek BROM / DA Command";
            string mtkDesc;
            string mtkPure;

            var mtkPkt = PhoenixGSM.OmniTrace.Decoders.MtkProtocolDecoder.DecodePacket(raw.RawPayload, raw.Direction);
            if (mtkPkt != null)
            {
                mtkCat = $"MediaTek {mtkPkt.Stage} Command";
                mtkDesc = $"{mtkPkt} ({dir})";
                mtkPure = mtkPkt.CommandName;
            }
            else if (MtkBromSourceInterceptor.TryParseMtkCommand(raw.RawPayload, procName, pid, 0, portOrEp, "USB/VCOM", out var mtkRec) && mtkRec != null)
            {
                mtkCat = "MediaTek BROM / DA Command";
                mtkDesc = $"{mtkRec.PureCommand} ({dir}) — {mtkRec.TechnicalDetails.Replace("\r\n", " | ").Replace("\n", " | ")}";
                mtkPure = mtkRec.PureCommand;
            }
            else
            {
                var (c, d) = Decoders.RawPayloadClassifier.Classify("MtkRawUsbBridge", portOrEp, 0, raw.RawPayload);
                mtkCat = c.Contains("MTK", StringComparison.OrdinalIgnoreCase) ? c : "MediaTek BROM / DA Stream";
                mtkDesc = $"[{mtkCat}] ({dir}) على [{portOrEp}]: {d}";
                mtkPure = d;
            }

            string savedDaPath = string.Empty;
            if (raw.RawPayload.Length >= 1024 && dir == "OUT")
            {
                L24FileArchiver.TryArchiveRawBuffer(raw.RawPayload, $"MTK_DA_Payload_{raw.RawPayload.Length}B.bin", "MtkRawUsbBridge", out savedDaPath, out _, out _);
                if (!string.IsNullOrWhiteSpace(savedDaPath))
                    mtkDesc += $" | 💾 تم حفظ حمولة DA الثنائية: [{Path.GetFileName(savedDaPath)}]";
            }

            _eventSink(new SourceTelemetryEvent
            {
                ProcessId = pid,
                ThreadId = 0,
                Stage = SentinelStage.RawCommandExecution,
                HookedApiName = "MtkRawUsbBridge",
                CallerModuleOrigin = $"MTK USB/VCOM ({dir})",
                TargetResource = portOrEp,
                CommandCategory = mtkCat,
                DecodedCommandText = mtkDesc,
                PureCommandText = mtkPure,
                SavedFilePath = savedDaPath,
                PayloadSize = raw.RawPayload.Length,
                RawPayloadHex = Convert.ToHexString(raw.RawPayload.AsSpan(0, Math.Min(raw.RawPayload.Length, 256)))
            });
            return;
        }

        // 4. Raw Serial / Modem / Qualcomm EDL / Samsung Odin Port Traffic
        if (raw.Sensor == SensorType.Serial || raw.Transport == TransportType.SERIAL ||
            proto.Contains("SERIAL", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("MODEM", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("SAHARA", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("FIREHOSE", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("ODIN", StringComparison.OrdinalIgnoreCase) ||
            proto.Contains("DIAG", StringComparison.OrdinalIgnoreCase) ||
            portOrEp.Contains("9008", StringComparison.OrdinalIgnoreCase) ||
            portOrEp.Contains("05C6", StringComparison.OrdinalIgnoreCase) ||
            portOrEp.Contains("04E8", StringComparison.OrdinalIgnoreCase))
        {
            var (cat, decoded) = Decoders.RawPayloadClassifier.Classify("SerialPortCapture", portOrEp, 0, raw.RawPayload);
            _eventSink(new SourceTelemetryEvent
            {
                ProcessId = pid,
                ThreadId = 0,
                Stage = SentinelStage.RawCommandExecution,
                HookedApiName = "SerialAndModemBusBridge",
                CallerModuleOrigin = $"Serial/Modem ({dir}) -> {portOrEp}",
                TargetResource = portOrEp,
                CommandCategory = cat,
                DecodedCommandText = $"[{cat}] ({dir}) عبر المنفذ [{portOrEp}]: {decoded}",
                PureCommandText = decoded,
                PayloadSize = raw.RawPayload.Length,
                RawPayloadHex = Convert.ToHexString(raw.RawPayload.AsSpan(0, Math.Min(raw.RawPayload.Length, 256)))
            });
            return;
        }

        // 5. Raw ADB / RIL-IPC Commands (RIL-IPC only to prevent ADB spam in L24)
        bool isRelevantAdb = proto.Equals("ADB-RIL-IPC", StringComparison.OrdinalIgnoreCase);

        if (isRelevantAdb)
        {
            string ascii = Encoding.UTF8.GetString(raw.RawPayload).Trim('\0', '\r', '\n');
            string cmdText = raw.Metadata != null && raw.Metadata.TryGetValue("Command", out var cVal) && !string.IsNullOrWhiteSpace(cVal)
                ? cVal
                : (ascii.Length > 0 ? ascii : Convert.ToHexString(raw.RawPayload));

            if (!IsCleanPrintableOrHexCommand(cmdText))
                return;

            string activeShell = raw.Metadata != null && raw.Metadata.TryGetValue("ActiveShell", out var sh) && !string.IsNullOrWhiteSpace(sh)
                ? sh
                : "/data/local/tmp/AT";

            _eventSink(new SourceTelemetryEvent
            {
                ProcessId = pid,
                ThreadId = 0,
                Stage = SentinelStage.RawCommandExecution,
                HookedApiName = "WinUsbFilterAdbBridge",
                CallerModuleOrigin = $"WinUSB Kernel Filter -> {activeShell}",
                TargetResource = activeShell,
                CommandCategory = proto.Equals("ADB-RIL-IPC", StringComparison.OrdinalIgnoreCase) ? "ADB RIL / AT IPC Command" : "ADB / Interactive Shell",
                DecodedCommandText = $"أمر تفاعلي على السلك (USB {dir}): {cmdText}",
                PureCommandText = cmdText,
                PayloadSize = raw.RawPayload.Length,
                RawPayloadHex = Convert.ToHexString(raw.RawPayload.AsSpan(0, Math.Min(raw.RawPayload.Length, 256)))
            });
        }
    }

    public static bool IsCleanPrintableOrHexCommand(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return false;
        string trimmed = text.Trim();

        if (trimmed.Contains("ELF") && trimmed.Contains("DATA")) return false;
        if (trimmed.Contains("????", StringComparison.Ordinal)) return false;

        int nonPrintable = 0;
        foreach (char c in trimmed)
        {
            if (c < 0x20 && c != '\r' && c != '\n' && c != '\t') nonPrintable++;
            else if (c > 0x7E) nonPrintable++;
        }
        return (double)nonPrintable / trimmed.Length <= 0.10;
    }

    public void ReportInteractiveCommand(string commandText, string targetTool = "/data/local/tmp/AT", int pid = 0)
    {
        if (_isDisposed || string.IsNullOrWhiteSpace(commandText)) return;
        if (!IsCleanPrintableOrHexCommand(commandText)) return;

        byte[] rawBytes = Encoding.UTF8.GetBytes(commandText);
        _eventSink(new SourceTelemetryEvent
        {
            ProcessId = pid,
            ThreadId = 0,
            Stage = SentinelStage.RawCommandExecution,
            HookedApiName = "WinUsbFilterAdbBridge",
            CallerModuleOrigin = $"WinUSB Kernel Filter -> {targetTool}",
            TargetResource = targetTool,
            CommandCategory = "ADB / Interactive Shell",
            DecodedCommandText = $"أمر تفاعلي مرسل للأداة ({targetTool}): {commandText}",
            PureCommandText = commandText,
            PayloadSize = rawBytes.Length,
            RawPayloadHex = Convert.ToHexString(rawBytes)
        });
    }

    public void Dispose()
    {
        if (_isDisposed) return;
        _isDisposed = true;
        Detach();
    }
}
