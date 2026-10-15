using System;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using PhoenixGSM.MonitoringStudio.Models;

namespace PhoenixGSM.MonitoringStudio.Services;

public partial class MonitoringEngine
{
    private static string? _activeTransferFile = null;
    private static string _activeTransferDir = "";
    private static long _activeTransferTotalBytes = 0;
    private static int _activeTransferChunkCount = 0;
    private static DateTime _activeTransferStartTime = DateTime.UtcNow;

    // Requirement 1: Stateful Channel Tracking
    private bool _isInsideFileSyncTransfer = false;
    private string _activeInteractiveShellCommand = string.Empty;

    #region USB Driver Capture Loop
    private async Task DriverCaptureLoop(CancellationToken token)
    {
        bool driverAvailable = false;
        while (!token.IsCancellationRequested)
        {
            try
            {
                if (!driverAvailable)
                {
                    if (_driverClient.IsDriverAvailable() && _driverClient.Connect())
                    {
                        driverAvailable = true;
                        var stats = _driverClient.GetStats();
                        OnDriverStatusChanged?.Invoke(true, $"Active (v{(stats?.DriverVersion >> 16) ?? 1}.0)");
                        EmitEvent(new LiveEventItem
                        {
                            Category = EventSourceCategory.UsbDriver,
                            SourceTag = "KERNEL",
                            Protocol = "KMDF",
                            Command = "ATTACHED",
                            Summary = $"Connected to \\\\.\\PhoenixUsbMonitor kernel device. Bulk filter active.",
                            AdditionalDetails = $"Queue Capacity: {stats?.MaxQueueCapacity ?? 512} packets"
                        });
                    }
                    else
                    {
                        OnDriverStatusChanged?.Invoke(false, "Service Stopped / Pending Reboot");
                        await Task.Delay(2000, token);
                        continue;
                    }
                }

                // Dequeue packets from kernel ring buffer
                var kPacket = _driverClient.DequeuePacket();
                if (kPacket.HasValue)
                {
                    var pkt = kPacket.Value;
                    string dir = pkt.Direction == 0 ? "OUT" : "IN";
                    byte[] chunk = new byte[pkt.CapturedLength];
                    if (pkt.CapturedLength > 0 && pkt.Data != null)
                    {
                        Array.Copy(pkt.Data, chunk, Math.Min((int)pkt.CapturedLength, pkt.Data.Length));
                    }

                    string epHex = $"0x{pkt.EndpointAddress:X2}";
                    var pDir = pkt.Direction == 0 ? PhoenixGSM.OmniTrace.Models.PacketDirection.HOST_TO_DEVICE : PhoenixGSM.OmniTrace.Models.PacketDirection.DEVICE_TO_HOST;

                    bool isAdbHeader = chunk.Length >= 24 && PhoenixGSM.UsbMonitor.Protocol.AdbProtocolParser.ValidateHeader(chunk, 0, out _, out _, out _, out _, out _);
                    bool isSahara = chunk.Length >= 8 && PhoenixGSM.OmniTrace.Decoders.QualcommEdlDecoder.EvaluateSahara(chunk) >= 0.8;
                    bool isFirehose = chunk.Length >= 5 && (Encoding.ASCII.GetString(chunk[..Math.Min(chunk.Length, 64)]).StartsWith("<?xml", StringComparison.OrdinalIgnoreCase) || Encoding.ASCII.GetString(chunk[..Math.Min(chunk.Length, 64)]).Contains("<data>"));
                    string rawAsciiPreview = chunk.Length > 0 ? Encoding.ASCII.GetString(chunk[..Math.Min(chunk.Length, 128)]) : "";

                    string cleanLine = chunk.Length > 0 ? Encoding.ASCII.GetString(chunk).Trim('\r', '\n', '\t', '\0', ' ') : "";
                    string cleanLineTrimmed = cleanLine.Trim();

                    // Track channel state transitions
                    if (cleanLineTrimmed.StartsWith("shell:", StringComparison.OrdinalIgnoreCase) ||
                        rawAsciiPreview.StartsWith("shell:", StringComparison.OrdinalIgnoreCase) ||
                        cleanLineTrimmed.Contains("shell:/data/local/tmp", StringComparison.OrdinalIgnoreCase) ||
                        rawAsciiPreview.Contains("shell:/data/local/tmp", StringComparison.OrdinalIgnoreCase))
                    {
                        string sCmd = cleanLineTrimmed.StartsWith("shell:", StringComparison.OrdinalIgnoreCase)
                            ? cleanLineTrimmed
                            : (rawAsciiPreview.Contains("shell:", StringComparison.OrdinalIgnoreCase)
                                ? rawAsciiPreview[rawAsciiPreview.IndexOf("shell:", StringComparison.OrdinalIgnoreCase)..].Split(new[] { '\0', '\r', '\n' })[0].Trim()
                                : cleanLineTrimmed);
                        _activeInteractiveShellCommand = sCmd;
                        _isInsideFileSyncTransfer = false;
                    }
                    else if (cleanLineTrimmed.Contains("chmod ") || rawAsciiPreview.Contains("chmod "))
                    {
                        _isInsideFileSyncTransfer = false;
                    }

                    // Fastboot is only classified when an explicit Fastboot command is seen (never during generic OKAY/DATA/FAIL responses in ADB Sync)
                    bool isFastboot = rawAsciiPreview.StartsWith("getvar:", StringComparison.OrdinalIgnoreCase) ||
                                      rawAsciiPreview.StartsWith("flash:", StringComparison.OrdinalIgnoreCase) ||
                                      rawAsciiPreview.StartsWith("erase:", StringComparison.OrdinalIgnoreCase) ||
                                      rawAsciiPreview.StartsWith("download:", StringComparison.OrdinalIgnoreCase) ||
                                      rawAsciiPreview.StartsWith("boot", StringComparison.OrdinalIgnoreCase) ||
                                      rawAsciiPreview.StartsWith("reboot", StringComparison.OrdinalIgnoreCase) ||
                                      rawAsciiPreview.StartsWith("continue", StringComparison.OrdinalIgnoreCase) ||
                                      rawAsciiPreview.StartsWith("oem ", StringComparison.OrdinalIgnoreCase) ||
                                      rawAsciiPreview.StartsWith("flashing ", StringComparison.OrdinalIgnoreCase);

                    bool isAdbSync = rawAsciiPreview.StartsWith("STAT", StringComparison.Ordinal) ||
                                     rawAsciiPreview.StartsWith("SEND", StringComparison.Ordinal) ||
                                     rawAsciiPreview.StartsWith("RECV", StringComparison.Ordinal) ||
                                     rawAsciiPreview.StartsWith("DATA", StringComparison.Ordinal) ||
                                     rawAsciiPreview.StartsWith("DONE", StringComparison.Ordinal) ||
                                     rawAsciiPreview.StartsWith("OKAY", StringComparison.Ordinal) ||
                                     rawAsciiPreview.StartsWith("FAIL", StringComparison.Ordinal) ||
                                     rawAsciiPreview.StartsWith("DENT", StringComparison.Ordinal) ||
                                     rawAsciiPreview.StartsWith("LIST", StringComparison.Ordinal);

                    bool isLongHex = cleanLineTrimmed.Length >= 32 && cleanLineTrimmed.All(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'));

                    bool isAdbRilIpc = isLongHex ||
                                       rawAsciiPreview.StartsWith("1163000501", StringComparison.OrdinalIgnoreCase) ||
                                       rawAsciiPreview.StartsWith("06090004", StringComparison.OrdinalIgnoreCase) ||
                                       rawAsciiPreview.StartsWith("07170004", StringComparison.OrdinalIgnoreCase) ||
                                       rawAsciiPreview.StartsWith("1163005F", StringComparison.OrdinalIgnoreCase) ||
                                       rawAsciiPreview.StartsWith("116300", StringComparison.OrdinalIgnoreCase) ||
                                       cleanLineTrimmed.StartsWith("1163000501", StringComparison.OrdinalIgnoreCase) ||
                                       cleanLineTrimmed.StartsWith("06090004", StringComparison.OrdinalIgnoreCase) ||
                                       cleanLineTrimmed.StartsWith("07170004", StringComparison.OrdinalIgnoreCase) ||
                                       cleanLineTrimmed.StartsWith("3E257A2C", StringComparison.OrdinalIgnoreCase) ||
                                       cleanLineTrimmed.StartsWith("AF6DBB85", StringComparison.OrdinalIgnoreCase) ||
                                       cleanLineTrimmed.StartsWith("62E83911", StringComparison.OrdinalIgnoreCase) ||
                                       cleanLineTrimmed.StartsWith("d8d8d8", StringComparison.OrdinalIgnoreCase) ||
                                       (chunk.Length >= 4 && chunk[0] == 0x11 && chunk[1] == 0x63);

                    bool isAsciiText = chunk.Length > 0 && chunk.All(b => b == 0 || b == 10 || b == 13 || (b >= 32 && b < 127));
                    bool isInteractiveShellActive = !string.IsNullOrEmpty(_activeInteractiveShellCommand);

                    // Requirement 1: Zero-Drop Interactive Command Rule in OUT direction
                    bool isAdbInteractiveCmd = (dir == "OUT" && isInteractiveShellActive && !isAdbHeader && chunk.Length > 0 &&
                                               (isAsciiText || isLongHex || isAdbRilIpc || cleanLineTrimmed.Length > 0 ||
                                                rawAsciiPreview.StartsWith("usb:", StringComparison.OrdinalIgnoreCase) ||
                                                cleanLineTrimmed.StartsWith("usb:", StringComparison.OrdinalIgnoreCase) ||
                                                cleanLineTrimmed.StartsWith("<<", StringComparison.Ordinal)));

                    bool isAdbStream = !isAdbRilIpc && !isAdbInteractiveCmd && (
                                       rawAsciiPreview.Contains("]: [") ||
                                       cleanLineTrimmed.Contains("]: [") ||
                                       cleanLineTrimmed == "]" ||
                                       cleanLineTrimmed.Contains("0x0000") ||
                                       cleanLineTrimmed.Equals("Enforcing", StringComparison.OrdinalIgnoreCase) ||
                                       cleanLineTrimmed.Equals("Permissive", StringComparison.OrdinalIgnoreCase) ||
                                       cleanLineTrimmed.Contains("0x4948", StringComparison.OrdinalIgnoreCase) ||
                                       cleanLineTrimmed.Contains("0x4f4c", StringComparison.OrdinalIgnoreCase) ||
                                       cleanLineTrimmed.Contains("0x494d", StringComparison.OrdinalIgnoreCase) ||
                                       cleanLineTrimmed.Contains("Product Name", StringComparison.OrdinalIgnoreCase) ||
                                       cleanLineTrimmed.Contains("Product Model", StringComparison.OrdinalIgnoreCase) ||
                                       cleanLineTrimmed.Contains("Build  Number", StringComparison.OrdinalIgnoreCase) ||
                                       cleanLineTrimmed.Contains("Serial Number", StringComparison.OrdinalIgnoreCase) ||
                                       cleanLineTrimmed.Contains("AuthKey Encrypt", StringComparison.OrdinalIgnoreCase) ||
                                       cleanLineTrimmed.Contains("restarting in USB mode", StringComparison.OrdinalIgnoreCase) ||
                                       cleanLineTrimmed.Contains("device::ro.product.", StringComparison.OrdinalIgnoreCase) ||
                                       cleanLineTrimmed.Equals("OK\n\n\n#", StringComparison.Ordinal) ||
                                       cleanLineTrimmed.Equals("#OK", StringComparison.Ordinal) ||
                                       cleanLineTrimmed.Equals("OK", StringComparison.Ordinal) ||
                                       cleanLineTrimmed.Equals("#", StringComparison.Ordinal) ||
                                       cleanLineTrimmed.Equals("<<", StringComparison.Ordinal) ||
                                       cleanLineTrimmed.Contains("****") ||
                                       rawAsciiPreview.StartsWith("shell:", StringComparison.OrdinalIgnoreCase) ||
                                       rawAsciiPreview.StartsWith("Result: Parcel(", StringComparison.OrdinalIgnoreCase) ||
                                       rawAsciiPreview.StartsWith("[DEVICE_PROVISIONED]", StringComparison.OrdinalIgnoreCase) ||
                                       rawAsciiPreview.StartsWith("while [ \"$(getprop", StringComparison.OrdinalIgnoreCase) ||
                                       rawAsciiPreview.Contains("[ro.") ||
                                       rawAsciiPreview.Contains("[init.svc.") ||
                                       rawAsciiPreview.Contains("[persist.") ||
                                       rawAsciiPreview.Contains("[dalvik.") ||
                                       rawAsciiPreview.Contains("[sys.") ||
                                       rawAsciiPreview.Contains("[ril.") ||
                                       rawAsciiPreview.Contains("[gsm.") ||
                                       rawAsciiPreview.Contains("rm: ") ||
                                       rawAsciiPreview.Contains("Permission denied") ||
                                       rawAsciiPreview.Contains("Operation not permitted") ||
                                       rawAsciiPreview.Contains("records in") ||
                                       rawAsciiPreview.Contains("records out") ||
                                       rawAsciiPreview.Contains("E RILD") ||
                                       rawAsciiPreview.Contains("D boot") ||
                                       rawAsciiPreview.Contains(" D RIL") ||
                                       rawAsciiPreview.Contains(" V RIL") ||
                                       rawAsciiPreview.Contains(" I RIL") ||
                                       rawAsciiPreview.Contains("OEM_HOOK_RAW", StringComparison.OrdinalIgnoreCase) ||
                                       rawAsciiPreview.Contains("SAMSUNG AT Ril Command TOOL", StringComparison.OrdinalIgnoreCase) ||
                                       rawAsciiPreview.Contains("Token AuthKey:", StringComparison.OrdinalIgnoreCase) ||
                                       rawAsciiPreview.Contains("Enter AuthKey:", StringComparison.OrdinalIgnoreCase) ||
                                       rawAsciiPreview.Contains("AuthKey : OK", StringComparison.OrdinalIgnoreCase) ||
                                       rawAsciiPreview.Contains("AuthKey : FAIL", StringComparison.OrdinalIgnoreCase) ||
                                       rawAsciiPreview.Contains("<<") ||
                                       rawAsciiPreview.StartsWith("/data/local/tmp", StringComparison.OrdinalIgnoreCase)
                    );

                    bool isUpperFilterPort = (pkt.TransferType == 4);
                    bool isNonAtUsbProtocol = isAdbHeader || isAdbStream || isAdbRilIpc || isAdbInteractiveCmd || isAdbSync || isSahara || isFirehose || isFastboot;

                    double atConf = chunk.Length > 0 
                        ? PhoenixGSM.OmniTrace.Detection.ProtocolDetector.EvaluateSerialAt(chunk, PhoenixGSM.OmniTrace.Models.SensorType.Serial, PhoenixGSM.OmniTrace.Models.TransportType.SERIAL) 
                        : 0.0;

                    // Requirement 2: Strict Isolation against MTK False Detection
                    bool hasAdbOrPrintableKeywords = cleanLineTrimmed.Contains("Product", StringComparison.OrdinalIgnoreCase) ||
                                                     cleanLineTrimmed.Contains("Token", StringComparison.OrdinalIgnoreCase) ||
                                                     cleanLineTrimmed.Contains("AuthKey", StringComparison.OrdinalIgnoreCase) ||
                                                     cleanLineTrimmed.Contains("****") ||
                                                     cleanLineTrimmed.Contains("samsung", StringComparison.OrdinalIgnoreCase) ||
                                                     cleanLineTrimmed.Contains("restarting in USB mode", StringComparison.OrdinalIgnoreCase) ||
                                                     cleanLineTrimmed.Contains("<<") ||
                                                     cleanLineTrimmed.StartsWith("shell:", StringComparison.OrdinalIgnoreCase) ||
                                                     cleanLineTrimmed.StartsWith("/data/local/tmp", StringComparison.OrdinalIgnoreCase);

                    bool isDeviceInAdb = isInteractiveShellActive || _isInsideFileSyncTransfer || isAdbHeader || isAdbStream || isAdbRilIpc || isAdbInteractiveCmd || hasAdbOrPrintableKeywords;

                    double mtkConf = (chunk.Length > 0 && !isDeviceInAdb && !hasAdbOrPrintableKeywords)
                        ? PhoenixGSM.OmniTrace.Decoders.MtkProtocolDecoder.EvaluateMtk(chunk)
                        : 0.0;
                    bool isMtk = mtkConf >= 0.70;

                    string cleanUpper = cleanLineTrimmed.ToUpperInvariant();
                    bool isExplicitModemCmd = cleanUpper.StartsWith("AT+") || cleanUpper.StartsWith("AT*") ||
                                              cleanUpper.StartsWith("AT#") || cleanUpper.StartsWith("ATE") ||
                                              cleanUpper.StartsWith("ATI") || cleanUpper.StartsWith("ATD") ||
                                              cleanUpper.StartsWith("ATA") || cleanUpper.StartsWith("ATZ") ||
                                              cleanUpper.StartsWith("AT&") || cleanUpper == "AT" ||
                                              cleanUpper.StartsWith("+DEVCONINFO:") || cleanUpper.StartsWith("+CME ERROR:") ||
                                              cleanUpper.StartsWith("+CMS ERROR:") ||
                                              (isUpperFilterPort && (cleanUpper.StartsWith("+") || cleanUpper == "OK" || cleanUpper.StartsWith("ERROR")));

                    bool isAt = !isMtk && !isNonAtUsbProtocol && !isAdbStream && !isAdbRilIpc && !isAdbInteractiveCmd && (
                        isExplicitModemCmd ||
                        (isUpperFilterPort && atConf >= 0.70 && !cleanLineTrimmed.Contains("]: [") && cleanLineTrimmed != "]")
                    );

                    KernelDiagLog($"PKT {dir} EP={epHex} TT={pkt.TransferType} len={pkt.ActualLength} cap={chunk.Length} isMtk={isMtk}({mtkConf:F2}) isAt={isAt} isUF={isUpperFilterPort} atConf={atConf:F2} ascii={isAsciiText} adb={isAdbHeader} sahara={isSahara} fh={isFirehose} fb={isFastboot} isShell={isInteractiveShellActive} | {Encoding.ASCII.GetString(chunk[..Math.Min(chunk.Length, 64)].Select(b => b >= 32 && b < 127 ? b : (byte)'.').ToArray())}");

                    if (chunk.Length > 0 && isMtk)
                    {
                        // Dedicated MediaTek (BROM / DA) Protocol Processing
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

                        // Feed OmniTrace Fabric for MTK
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
                    else if (chunk.Length > 0 && (isAdbRilIpc || isAdbInteractiveCmd))
                    {
                        // Requirement 1: Zero-Drop Interactive and RIL IPC Commands Sent to Tool / Shell
                        string protoTag = isAdbRilIpc ? "ADB-RIL-IPC" : "ADB-INTERACTIVE-CMD";
                        string sourceTag = isAdbRilIpc ? "ADB-RIL" : "ADB-SHELL";
                        string targetTool = !string.IsNullOrEmpty(_activeInteractiveShellCommand) ? _activeInteractiveShellCommand : "/data/local/tmp/AT";

                        string rilCmdText = cleanLineTrimmed.Length > 0 ? cleanLineTrimmed : $"[{protoTag}] ({chunk.Length}B): {Convert.ToHexString(chunk)}";
                        EmitEvent(new LiveEventItem
                        {
                            Timestamp = DateTime.UtcNow,
                            Category = EventSourceCategory.AdbProxy,
                            SourceTag = sourceTag,
                            Direction = dir,
                            EndpointOrTarget = $"EP {epHex} -> {targetTool}",
                            Protocol = protoTag,
                            Command = rilCmdText,
                            Summary = $"[{protoTag}] {dir} -> {targetTool}: {rilCmdText}",
                            RawPayload = chunk,
                            PayloadAscii = cleanLine,
                            PayloadHex = LiveEventItem.FormatHexDump(chunk),
                            AdditionalDetails = $"Active Interactive Shell: {targetTool}\nTransferType: {pkt.TransferType}\nDirection: {dir}\nActualLength: {pkt.ActualLength} B\nSource: KernelDriver ADB Interactive Sniff"
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
                                        ["Command"] = rilCmdText,
                                        ["ActiveShell"] = targetTool
                                    }
                                });

                                var logicalCmd = new PhoenixGSM.OmniTrace.Models.LogicalCommandEvent
                                {
                                    Command = rilCmdText,
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
                                _omniService.EventBus.ReportLogicalCommand(logicalCmd);
                            }
                            catch { }
                        }
                    }
                    else if (chunk.Length > 0 && isAdbStream)
                    {
                        // Active ADB Stream Output (ro. properties, shell errors, logcat, Samsung RIL Tool banner & responses) -> ADB-STREAM
                        string streamCmdText = cleanLine.Length > 0 ? cleanLine : Encoding.ASCII.GetString(chunk).Trim('\0');
                        EmitEvent(new LiveEventItem
                        {
                            Timestamp = DateTime.UtcNow,
                            Category = EventSourceCategory.AdbProxy,
                            SourceTag = dir == "OUT" ? "ADB-OUT" : "ADB-STREAM",
                            Direction = dir,
                            EndpointOrTarget = $"EP {epHex}",
                            Protocol = "ADB-STREAM",
                            Command = streamCmdText,
                            Summary = $"[ADB-STREAM] {dir}: {streamCmdText}",
                            RawPayload = chunk,
                            PayloadAscii = streamCmdText,
                            PayloadHex = LiveEventItem.FormatHexDump(chunk),
                            AdditionalDetails = $"TransferType: {pkt.TransferType}\nDirection: {dir}\nActualLength: {pkt.ActualLength} B\nActiveShell: {_activeInteractiveShellCommand}\nSource: KernelDriver ADB Active Stream Sniff"
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
                                        ["ActiveShell"] = _activeInteractiveShellCommand
                                    }
                                });
                            }
                            catch { }
                        }
                    }
                    else if (chunk.Length > 0 && isAt)
                    {
                        // Priority Serial / Modem Port Processing
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
                                fullCommandText = cleanLine; // Preserves 100% of untruncated command text
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
                            Command = fullCommandText, // Full, complete command with zero truncation
                            Summary = $"[MODEM-USB] {dir}: {fullCommandText} ({Math.Max(atConf, 0.90):P0} conf)",
                            RawPayload = chunk,
                            PayloadAscii = asciiPayload, // Full un-truncated decoded ASCII payload
                            PayloadHex = LiveEventItem.FormatHexDump(chunk),
                            AdditionalDetails = $"TransferType: {pkt.TransferType}\nDirection: {dir}\nActualLength: {pkt.ActualLength} B\nCaptured: {pkt.CapturedLength} B\nSource: UpperFilter Passive Sniff"
                        });

                        // Feed OmniTrace Fabric via SerialPortSensor
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
                    else
                    {
                        // Non-Serial USB traffic: ADB, Fastboot, Control, or Raw Bulk
                        var frames = _adbParser.ProcessChunk(chunk, dir, "Android Phone", "", "", 1, epHex);

                        if (frames != null && frames.Count > 0)
                        {
                            foreach (var frame in frames)
                            {
                                // Suppress routine OKAY and CLSE events between ADB-STREAM packets
                                if (frame.Command == "OKAY" || frame.Command == "CLSE")
                                {
                                    _isInsideFileSyncTransfer = false;
                                    continue;
                                }

                                string payloadPreview = frame.PayloadPreview ?? "";

                                if (frame.Command == "OPEN")
                                {
                                    _isInsideFileSyncTransfer = false;
                                    if (payloadPreview.Contains("shell:"))
                                    {
                                        _activeInteractiveShellCommand = payloadPreview.Trim();
                                    }
                                }

                                // Check if OPEN or WRTE or CNXN resulted in raw Hex string or mangled header
                                if (frame.Command == "OPEN" || frame.Command == "WRTE" || frame.Command == "CNXN")
                                {
                                    string pTrim = payloadPreview.Trim();
                                    bool isHexByteDump = pTrim.Contains("bytes total)") ||
                                                         (pTrim.Length >= 8 && pTrim.Contains(" ") &&
                                                          pTrim.Split(' ').All(tok => (tok.Length == 2 && Uri.IsHexDigit(tok[0]) && Uri.IsHexDigit(tok[1])) || tok == "..." || tok.StartsWith("(") || tok.EndsWith(")")));

                                    bool isMangledHeader = pTrim.Contains("CLSE") || pTrim.Contains("OPEN") ||
                                                           pTrim.StartsWith("OKAY") || pTrim.StartsWith("WRTE") ||
                                                           pTrim.StartsWith("CNXN") ||
                                                           pTrim.StartsWith("43 4C 53 45") ||
                                                           pTrim.StartsWith("4F 4B 41 59") ||
                                                           pTrim.StartsWith("57 52 54 45") ||
                                                           pTrim.StartsWith("4E 45 50 4F") ||
                                                           pTrim.StartsWith("4E 58 4E 43");

                                    if (isHexByteDump || isMangledHeader)
                                    {
                                        continue;
                                    }
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
                            // 1. If this is a 24-byte ADB wire header (CNXN, OPEN, OKAY, WRTE, CLSE), do NOT print duplicate RAW-BULK (24B) line
                            if (chunk.Length == 24 && isAdbHeader)
                            {
                                // Already buffered or processed by ADB decoder — suppress duplicate raw dump
                            }
                            else
                            {
                                // 2. Check if chunk is a binary data chunk (> 40% non-printable characters or dots)
                                int nonPrintable = 0;
                                for (int i = 0; i < chunk.Length; i++)
                                {
                                    byte b = chunk[i];
                                    if (b < 0x20 && b != 9 && b != 10 && b != 13) nonPrintable++;
                                    else if (b == (byte)'.') nonPrintable++;
                                }
                                double nonPrintableRatio = (double)nonPrintable / chunk.Length;

                                bool isRepeatedBinaryPattern = rawAsciiPreview.Contains("d8d8d8d8") ||
                                                               rawAsciiPreview.Contains("FW22222") ||
                                                               rawAsciiPreview.Contains("a4..?HR") ||
                                                               rawAsciiPreview.Contains("I7..MS") ||
                                                               rawAsciiPreview.Contains("..a4") ||
                                                               rawAsciiPreview.Contains("..I7");

                                if (rawAsciiPreview.StartsWith("SEND /", StringComparison.Ordinal) || rawAsciiPreview.StartsWith("SEND ", StringComparison.Ordinal) ||
                                    rawAsciiPreview.Contains("SEND /data/local/tmp/"))
                                {
                                    string headerText = rawAsciiPreview.Split(new[] { '\0', '\r', '\n' })[0].Trim();
                                    string targetPath = "/data/local/tmp/AT";
                                    string mode = "33188";
                                    var m = System.Text.RegularExpressions.Regex.Match(headerText, @"(?:SEND\s+)?([^\s,]+),(\d+)");
                                    if (m.Success)
                                    {
                                        targetPath = m.Groups[1].Value.Trim();
                                        mode = m.Groups[2].Value.Trim();
                                    }
                                    else
                                    {
                                        targetPath = headerText.Replace("SEND", "").Trim();
                                    }

                                    bool isElf = chunk.Length >= 4 && (Encoding.ASCII.GetString(chunk).Contains("ELF") || chunk.Any(b => b == 0x7F && rawAsciiPreview.Contains("ELF")));
                                    string fileType = isElf ? "ELF Binary" : "Binary";
                                    string syncCmd = $"PUSH {targetPath} (Mode: {mode}, Type: {fileType})";

                                    _activeTransferFile = syncCmd;
                                    _isInsideFileSyncTransfer = true;
                                    _activeTransferDir = dir;
                                    _activeTransferTotalBytes = chunk.Length;
                                    _activeTransferChunkCount = 1;
                                    _activeTransferStartTime = DateTime.UtcNow;

                                    EmitEvent(new LiveEventItem
                                    {
                                        Timestamp = DateTime.UtcNow,
                                        Category = EventSourceCategory.UsbDriver,
                                        SourceTag = "ADB-SYNC",
                                        Direction = dir,
                                        EndpointOrTarget = $"EP {epHex}",
                                        Protocol = "ADB-SYNC",
                                        Command = syncCmd,
                                        Summary = $"[ADB-SYNC] {dir} Transfer Started: {syncCmd}",
                                        RawPayload = chunk,
                                        PayloadAscii = syncCmd,
                                        PayloadHex = LiveEventItem.FormatHexDump(chunk[..Math.Min(chunk.Length, 64)]),
                                        AdditionalDetails = $"Sync file push started: {syncCmd}\nDirection: {dir}\nEndpoint: {epHex}"
                                    });
                                }
                                else if (rawAsciiPreview.StartsWith("RECV /", StringComparison.Ordinal) || rawAsciiPreview.StartsWith("RECV ", StringComparison.Ordinal))
                                {
                                    _activeTransferFile = rawAsciiPreview.Split(new[] { '\0', ',', '\r', '\n' })[0].Trim();
                                    _activeTransferDir = dir;
                                    _activeTransferTotalBytes = chunk.Length;
                                    _activeTransferChunkCount = 1;
                                    _activeTransferStartTime = DateTime.UtcNow;

                                    EmitEvent(new LiveEventItem
                                    {
                                        Timestamp = DateTime.UtcNow,
                                        Category = EventSourceCategory.UsbDriver,
                                        SourceTag = "ADB-SYNC",
                                        Direction = dir,
                                        EndpointOrTarget = $"EP {epHex}",
                                        Protocol = "ADB-SYNC",
                                        Command = _activeTransferFile,
                                        Summary = $"[ADB-SYNC] {dir} Transfer Started: {_activeTransferFile}",
                                        RawPayload = chunk,
                                        PayloadAscii = _activeTransferFile,
                                        PayloadHex = LiveEventItem.FormatHexDump(chunk[..Math.Min(chunk.Length, 64)]),
                                        AdditionalDetails = $"Sync file pull started: {_activeTransferFile}\nDirection: {dir}\nEndpoint: {epHex}"
                                    });
                                }
                                else if (rawAsciiPreview.StartsWith("DONE", StringComparison.Ordinal) ||
                                         rawAsciiPreview.StartsWith("OKAY", StringComparison.Ordinal) ||
                                         rawAsciiPreview.StartsWith("CLSE", StringComparison.Ordinal))
                                {
                                    _isInsideFileSyncTransfer = false;
                                    if (!string.IsNullOrEmpty(_activeTransferFile))
                                    {
                                        double duration = (DateTime.UtcNow - _activeTransferStartTime).TotalSeconds;
                                        string summaryMsg = $"[ADB-SYNC] Transfer Completed: {_activeTransferFile} ({_activeTransferTotalBytes:N0} bytes, {_activeTransferChunkCount} chunks in {duration:F1}s)";

                                        EmitEvent(new LiveEventItem
                                        {
                                            Timestamp = DateTime.UtcNow,
                                            Category = EventSourceCategory.UsbDriver,
                                            SourceTag = "ADB-SYNC",
                                            Direction = dir,
                                            EndpointOrTarget = $"EP {epHex}",
                                            Protocol = "ADB-SYNC",
                                            Command = "TRANSFER DONE",
                                            Summary = summaryMsg,
                                            RawPayload = chunk,
                                            PayloadAscii = summaryMsg,
                                            PayloadHex = LiveEventItem.FormatHexDump(chunk),
                                            AdditionalDetails = $"Total Transfer: {_activeTransferTotalBytes:N0} bytes\nChunks: {_activeTransferChunkCount}\nDuration: {duration:F2}s\nTarget: {_activeTransferFile}"
                                        });

                                        _activeTransferFile = null;
                                    }
                                }
                                else if (isRepeatedBinaryPattern || nonPrintableRatio > 0.30 || _isInsideFileSyncTransfer || !string.IsNullOrEmpty(_activeTransferFile))
                                {
                                    // Suppress individual 1024B / 4096B line flooding for binary chunks (ELF, cp, data)
                                    _activeTransferTotalBytes += chunk.Length;
                                    _activeTransferChunkCount++;
                                }
                                else
                                {
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

                        // Feed OmniTrace Fabric for USB
                        if (chunk.Length > 0 && _omniService != null)
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
                else
                {
                    // Empty queue, sleep shortly to preserve CPU
                    await Task.Delay(10, token);
                }
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                KernelDiagLog($"EXCEPTION: {ex}");
                driverAvailable = false;
                await Task.Delay(1000, token);
            }
        }
    }

    private static readonly string KernelDiagFile = System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PhoenixGSM", "Logs", "kernel_packets.log");

    private static void KernelDiagLog(string line)
    {
        try
        {
            System.IO.Directory.CreateDirectory(System.IO.Path.GetDirectoryName(KernelDiagFile)!);
            System.IO.File.AppendAllText(KernelDiagFile, $"{DateTime.Now:HH:mm:ss.fff} {line}\n");
        }
        catch { }
    }

    private string ResolveModemPortName(byte[] chunk, string cleanText)
    {
        if (_omniService?.SerialSensor == null) return "MODEM_PORT";
        var sensor = _omniService.SerialSensor;
        var allPorts = sensor.AllDiscoveredPortNames ?? (IReadOnlyCollection<string>)Array.Empty<string>();

        // 1. Check for Huawei / Honor traffic signatures
        bool isHuawei = cleanText.Contains("^", StringComparison.OrdinalIgnoreCase) ||
                        cleanText.Contains("Honor", StringComparison.OrdinalIgnoreCase) ||
                        cleanText.Contains("Huawei", StringComparison.OrdinalIgnoreCase) ||
                        cleanText.StartsWith("ANY-", StringComparison.OrdinalIgnoreCase) ||
                        cleanText.StartsWith("WKG-", StringComparison.OrdinalIgnoreCase) ||
                        cleanText.StartsWith("H60-", StringComparison.OrdinalIgnoreCase) ||
                        cleanText.StartsWith("LLD-", StringComparison.OrdinalIgnoreCase) ||
                        cleanText.StartsWith("STK-", StringComparison.OrdinalIgnoreCase) ||
                        cleanText.StartsWith("POT-", StringComparison.OrdinalIgnoreCase) ||
                        cleanText.StartsWith("PRA-", StringComparison.OrdinalIgnoreCase) ||
                        cleanText.StartsWith("FIG-", StringComparison.OrdinalIgnoreCase) ||
                        cleanText.StartsWith("JSN-", StringComparison.OrdinalIgnoreCase) ||
                        cleanText.StartsWith("VOG-", StringComparison.OrdinalIgnoreCase) ||
                        cleanText.StartsWith("ELE-", StringComparison.OrdinalIgnoreCase) ||
                        cleanText.StartsWith("YAL-", StringComparison.OrdinalIgnoreCase) ||
                        cleanText.StartsWith("NOH-", StringComparison.OrdinalIgnoreCase) ||
                        cleanText.StartsWith("NEN-", StringComparison.OrdinalIgnoreCase);

        if (isHuawei)
        {
            var hwPort = allPorts.FirstOrDefault(p =>
            {
                var desc = sensor.GetPortDescription(p) ?? "";
                var hwId = sensor.GetPortHardwareId(p) ?? "";
                return desc.Contains("Huawei", StringComparison.OrdinalIgnoreCase) ||
                       desc.Contains("Honor", StringComparison.OrdinalIgnoreCase) ||
                       desc.Contains("Adapter Modem", StringComparison.OrdinalIgnoreCase) ||
                       desc.Contains("PC UI", StringComparison.OrdinalIgnoreCase) ||
                       hwId.Contains("12D1", StringComparison.OrdinalIgnoreCase);
            });
            if (hwPort != null) return hwPort;
            return allPorts.Count == 0 ? "COM12 (Honor/Huawei)" : "MODEM_HUAWEI";
        }

        // 2. Check for Samsung traffic signatures
        bool isSamsung = cleanText.Contains("Samsung", StringComparison.OrdinalIgnoreCase) ||
                         cleanText.StartsWith("SM-", StringComparison.OrdinalIgnoreCase) ||
                         cleanText.StartsWith("SEC-", StringComparison.OrdinalIgnoreCase) ||
                         cleanText.Contains("PACM(AP)", StringComparison.OrdinalIgnoreCase);

        if (isSamsung)
        {
            var samPort = allPorts.FirstOrDefault(p =>
            {
                var desc = sensor.GetPortDescription(p) ?? "";
                var hwId = sensor.GetPortHardwareId(p) ?? "";
                return desc.Contains("Samsung", StringComparison.OrdinalIgnoreCase) ||
                       hwId.Contains("04E8", StringComparison.OrdinalIgnoreCase);
            });
            if (samPort != null) return samPort;
            return allPorts.Count == 0 ? "COM5 (Samsung)" : "MODEM_SAMSUNG";
        }

        // 3. Fallback to any active/known modem or serial port
        var defaultModem = allPorts.FirstOrDefault(p =>
        {
            var desc = sensor.GetPortDescription(p) ?? "";
            return desc.Contains("Modem", StringComparison.OrdinalIgnoreCase) ||
                   desc.Contains("PC UI", StringComparison.OrdinalIgnoreCase) ||
                   desc.Contains("Serial", StringComparison.OrdinalIgnoreCase);
        });

        return defaultModem ?? allPorts.FirstOrDefault() ?? "MODEM_PORT";
    }
    #endregion
}
