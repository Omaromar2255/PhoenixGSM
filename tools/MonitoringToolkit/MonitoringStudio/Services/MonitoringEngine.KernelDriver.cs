using System;
using System.Collections.Generic;
using System.IO;
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

    // Requirement 1 & 4: Stateful Channel & Artifact Tracking
    private bool _isInsideFileSyncTransfer = false;
    private string _activeInteractiveShellCommand = string.Empty;
    private string _activeSocketBridgeChannel = string.Empty;

    private static readonly object _transferLock = new();
    private static readonly MemoryStream _activeUploadStream = new();
    private static string _activeUploadFilePath = string.Empty;
    private static string _activeUploadFileMode = string.Empty;

    private readonly PhoenixGSM.OmniTrace.BinaryAnalysis.ElfBinaryInspector _elfInspector = new();
    private readonly PhoenixGSM.OmniTrace.BinaryAnalysis.ApkManifestInspector _apkInspector = new();
    private readonly PhoenixGSM.OmniTrace.AdvancedExploits.PrivilegeBridgeDetector _bridgeDetector = new();

    private readonly PhoenixGSM.OmniTrace.Decoders.AdbGetpropAggregator _getpropAggregator = new();
    private bool _isAggregatingGetprop = false;
    private DateTime _lastGetpropChunkTime = DateTime.UtcNow;

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

                    // Flush getprop aggregator if idle or another command is seen
                    if (_isAggregatingGetprop)
                    {
                        if ((DateTime.UtcNow - _lastGetpropChunkTime).TotalMilliseconds > 400 ||
                            cleanLineTrimmed.StartsWith("shell:") || cleanLineTrimmed.StartsWith("<<") ||
                            cleanLineTrimmed.StartsWith("AT") || cleanLineTrimmed.StartsWith("SEND"))
                        {
                            FlushGetpropSummary(epHex, dir);
                        }
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

                    bool isLongHex = cleanLineTrimmed.Length >= 16 && cleanLineTrimmed.All(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'));

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
                                       cleanLineTrimmed.StartsWith("<<", StringComparison.Ordinal) ||
                                       (chunk.Length >= 4 && chunk[0] == 0x11 && chunk[1] == 0x63);

                    bool isAsciiText = chunk.Length > 0 && chunk.All(b => b == 0 || b == 10 || b == 13 || (b >= 32 && b < 127));
                    bool isInteractiveShellActive = !string.IsNullOrEmpty(_activeInteractiveShellCommand);

                    // Requirement 1 & 3: Zero-Drop Interactive Command Rule in OUT direction
                    bool isAdbInteractiveCmd = (dir == "OUT" && isInteractiveShellActive && !isAdbHeader && chunk.Length > 0 &&
                                               (isAsciiText || isLongHex || isAdbRilIpc || cleanLineTrimmed.Length > 0 ||
                                                rawAsciiPreview.StartsWith("usb:", StringComparison.OrdinalIgnoreCase) ||
                                                cleanLineTrimmed.StartsWith("usb:", StringComparison.OrdinalIgnoreCase) ||
                                                cleanLineTrimmed.StartsWith("<<", StringComparison.Ordinal)));

                    // Requirement 2: Detect Socket Bridges and Android 11+ Binder Bridges
                    bool isSocketBridgeChannel = !string.IsNullOrEmpty(_activeSocketBridgeChannel) ||
                                                 PhoenixGSM.OmniTrace.Decoders.AdbSmartSocketDecoder.IsSocketBridgeChannel(cleanLineTrimmed) ||
                                                 PhoenixGSM.OmniTrace.Decoders.AdbSmartSocketDecoder.IsModernAndroidService(cleanLineTrimmed) ||
                                                 cleanLineTrimmed.StartsWith("tcp:", StringComparison.OrdinalIgnoreCase) ||
                                                 cleanLineTrimmed.StartsWith("localabstract:", StringComparison.OrdinalIgnoreCase) ||
                                                 cleanLineTrimmed.StartsWith("abb:", StringComparison.OrdinalIgnoreCase);

                    bool isAppPrivilegeCmd = PhoenixGSM.OmniTrace.Decoders.AdbSmartSocketDecoder.IsAppPrivilegeCommand(cleanLineTrimmed);

                    // Requirement 3: Detect getprop property stream lines
                    bool isGetpropOutput = cleanLineTrimmed.Contains("]: [") ||
                                           (rawAsciiPreview.Contains("]: [") && !cleanLineTrimmed.StartsWith("AT", StringComparison.OrdinalIgnoreCase)) ||
                                           (cleanLineTrimmed.StartsWith("[ro.") || cleanLineTrimmed.StartsWith("[gsm.") || cleanLineTrimmed.StartsWith("[sys.") || cleanLineTrimmed.StartsWith("[ril."));

                    bool isAdbStream = !isAdbRilIpc && !isAdbInteractiveCmd && (
                                       isGetpropOutput ||
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
                                       cleanLineTrimmed.StartsWith("usb:", StringComparison.OrdinalIgnoreCase) ||
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
                    bool isNonAtUsbProtocol = isAdbHeader || isAdbStream || isAdbRilIpc || isAdbInteractiveCmd || isAdbSync || isSahara || isFirehose || isFastboot || isSocketBridgeChannel;

                    double atConf = chunk.Length > 0 
                        ? PhoenixGSM.OmniTrace.Detection.ProtocolDetector.EvaluateSerialAt(chunk, PhoenixGSM.OmniTrace.Models.SensorType.Serial, PhoenixGSM.OmniTrace.Models.TransportType.SERIAL) 
                        : 0.0;

                    // Requirement 2 & 4: Strict Isolation against MTK False Detection
                    // Single handshake sync byte 'P' (0x50) in multi-byte packet must NEVER be treated as MTK
                    bool hasAdbOrPrintableKeywords = cleanLineTrimmed.Contains("Product", StringComparison.OrdinalIgnoreCase) ||
                                                     cleanLineTrimmed.Contains("Token", StringComparison.OrdinalIgnoreCase) ||
                                                     cleanLineTrimmed.Contains("AuthKey", StringComparison.OrdinalIgnoreCase) ||
                                                     cleanLineTrimmed.Contains("****") ||
                                                     cleanLineTrimmed.Contains("samsung", StringComparison.OrdinalIgnoreCase) ||
                                                     cleanLineTrimmed.Contains("restarting in USB mode", StringComparison.OrdinalIgnoreCase) ||
                                                     cleanLineTrimmed.Contains("<<") ||
                                                     cleanLineTrimmed.StartsWith("shell:", StringComparison.OrdinalIgnoreCase) ||
                                                     cleanLineTrimmed.StartsWith("/data/local/tmp", StringComparison.OrdinalIgnoreCase);

                    bool isDeviceInAdb = isInteractiveShellActive || _isInsideFileSyncTransfer || isAdbHeader || isAdbStream || isAdbRilIpc || isAdbInteractiveCmd || hasAdbOrPrintableKeywords || isSocketBridgeChannel;

                    double mtkConf = (chunk.Length > 0 && !isDeviceInAdb && !hasAdbOrPrintableKeywords)
                        ? PhoenixGSM.OmniTrace.Decoders.MtkProtocolDecoder.EvaluateMtk(chunk)
                        : 0.0;
                    bool isMtk = mtkConf >= 0.70;

                    // Absolute rule: Multi-byte buffer starting with 'P' (0x50) is NEVER MTK
                    if (chunk.Length > 1 && (chunk[0] == 0x50 || chunk[0] == (byte)'P'))
                    {
                        isMtk = false;
                        if (cleanLineTrimmed.StartsWith("Product Name", StringComparison.OrdinalIgnoreCase) || rawAsciiPreview.Contains("Product Name"))
                        {
                            isAdbStream = true;
                        }
                    }

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
                    else if (chunk.Length > 0 && isSocketBridgeChannel && !isAdbHeader && dir == "OUT")
                    {
                        // Requirement 2: ADB Socket Bridge (tcp, localabstract, abb, etc.)
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
                    else if (chunk.Length > 0 && isAppPrivilegeCmd && !isAdbHeader)
                    {
                        // Requirement 2: App Launching and Permission Granting (am start, pm grant, appops set, etc.)
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
                    else if (chunk.Length > 0 && (isAdbRilIpc || isAdbInteractiveCmd))
                    {
                        // Requirement 1 & 3: Zero-Drop Interactive and RIL IPC Commands Sent to Tool / Shell
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
                    else if (chunk.Length > 0 && isGetpropOutput)
                    {
                        // Requirement 3: Aggregate fragmented getprop property output lines into a unified block
                        _getpropAggregator.IngestChunk(cleanLine + "\n");
                        _isAggregatingGetprop = true;
                        _lastGetpropChunkTime = DateTime.UtcNow;

                        // If prompt follows getprop or output terminated, flush unified summary
                        if (cleanLineTrimmed.EndsWith("#") || cleanLineTrimmed.EndsWith("OK") || cleanLineTrimmed == "]")
                        {
                            FlushGetpropSummary(epHex, dir);
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
                                    else if (PhoenixGSM.OmniTrace.Decoders.AdbSmartSocketDecoder.IsSocketBridgeChannel(payloadPreview) ||
                                             PhoenixGSM.OmniTrace.Decoders.AdbSmartSocketDecoder.IsModernAndroidService(payloadPreview))
                                    {
                                        _activeSocketBridgeChannel = payloadPreview.Trim();
                                    }
                                }

                                // Requirement 4: Prevent printing duplicate ADB hex wire headers
                                string pTrim = payloadPreview.Trim();
                                bool isDuplicateWireHeader = pTrim.Contains("43 4C 53 45") ||
                                                             pTrim.Contains("4F 4B 41 59") ||
                                                             pTrim.Contains("57 52 54 45") ||
                                                             pTrim.Contains("F7 2D E6 F4") ||
                                                             pTrim.Contains("4E 45 50 4F") ||
                                                             pTrim.Contains("4E 58 4E 43") ||
                                                             pTrim.EndsWith("bytes total)") ||
                                                             pTrim.Contains("OPEN CLSE");

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
                            // 1. If this is a 24-byte ADB wire header (CNXN, OPEN, OKAY, WRTE, CLSE), do NOT print duplicate RAW-BULK (24B) line
                            if (chunk.Length == 24 && isAdbHeader)
                            {
                                // Already buffered or processed by ADB decoder — suppress duplicate raw dump
                            }
                            else
                            {
                                // 2. Check if chunk is a binary data chunk (> 30% non-printable characters or dots)
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

                                // Requirement 4: ADB SEND handling inside sync: channel
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

                                    lock (_transferLock)
                                    {
                                        _activeUploadStream.SetLength(0);
                                        _activeUploadFilePath = targetPath;
                                        _activeUploadFileMode = mode;
                                        _activeTransferFile = targetPath;
                                        _isInsideFileSyncTransfer = true;
                                        _activeTransferDir = dir;
                                        _activeTransferTotalBytes = 0;
                                        _activeTransferChunkCount = 0;
                                        _activeTransferStartTime = DateTime.UtcNow;

                                        // If chunk already has DATA payload after SEND header, capture it
                                        int dataHeaderIdx = -1;
                                        for (int i = 0; i < chunk.Length - 4; i++)
                                        {
                                            if (chunk[i] == 'D' && chunk[i+1] == 'A' && chunk[i+2] == 'T' && chunk[i+3] == 'A')
                                            {
                                                dataHeaderIdx = i + 8; // skip "DATA" (4B) + length (4B)
                                                break;
                                            }
                                        }
                                        if (dataHeaderIdx >= 0 && dataHeaderIdx < chunk.Length)
                                        {
                                            _activeUploadStream.Write(chunk, dataHeaderIdx, chunk.Length - dataHeaderIdx);
                                            _activeTransferTotalBytes += (chunk.Length - dataHeaderIdx);
                                        }
                                    }
                                }
                                else if (rawAsciiPreview.StartsWith("DONE", StringComparison.Ordinal) ||
                                         rawAsciiPreview.StartsWith("OKAY", StringComparison.Ordinal) ||
                                         rawAsciiPreview.StartsWith("CLSE", StringComparison.Ordinal) ||
                                         (chunk.Length >= 4 && chunk[0] == 0x44 && chunk[1] == 0x4F && chunk[2] == 0x4E && chunk[3] == 0x45)) // "DONE" token
                                {
                                    _isInsideFileSyncTransfer = false;
                                    lock (_transferLock)
                                    {
                                        if (!string.IsNullOrEmpty(_activeTransferFile) && _activeUploadStream.Length > 0)
                                        {
                                            byte[] fileBytes = _activeUploadStream.ToArray();
                                            string fname = Path.GetFileName(_activeUploadFilePath);
                                            if (string.IsNullOrWhiteSpace(fname)) fname = "AT";

                                            string artifactsDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "CapturedArtifacts");
                                            string savePath = Path.Combine(artifactsDir, fname);
                                            try
                                            {
                                                Directory.CreateDirectory(artifactsDir);
                                                File.WriteAllBytes(savePath, fileBytes);
                                            }
                                            catch { }

                                            // Forensic inspection
                                            string inspectionReport;
                                            if (fileBytes.Length >= 4 && fileBytes[0] == 0x7F && fileBytes[1] == 0x45 && fileBytes[2] == 0x4C && fileBytes[3] == 0x46)
                                            {
                                                var elfRes = _elfInspector.InspectElf(fileBytes);
                                                inspectionReport = !string.IsNullOrEmpty(elfRes.ForensicClassification)
                                                    ? elfRes.ForensicClassification
                                                    : $"ELF {elfRes.Architecture} (Symbols: {elfRes.DangerousSymbolsFound.Length})";
                                            }
                                            else if (fileBytes.Length >= 4 && fileBytes[0] == 0x50 && fileBytes[1] == 0x4B)
                                            {
                                                var apkRes = _apkInspector.InspectApk(fileBytes);
                                                inspectionReport = !string.IsNullOrEmpty(apkRes.ForensicDescription)
                                                    ? apkRes.ForensicDescription
                                                    : "ZIP/APK Archive";
                                            }
                                            else
                                            {
                                                var elfRes = _elfInspector.InspectElf(fileBytes);
                                                inspectionReport = elfRes.IsValidElf ? elfRes.ForensicClassification : $"Binary Payload ({fileBytes.Length:N0} B)";
                                            }

                                            string singleSummary = $"[ADB-SYNC] Transfer Completed: {_activeUploadFilePath} ({fileBytes.Length:N0} bytes) | Forensic: {inspectionReport} | Saved: CapturedArtifacts/{fname}";

                                            EmitEvent(new LiveEventItem
                                            {
                                                Timestamp = DateTime.UtcNow,
                                                Category = EventSourceCategory.UsbDriver,
                                                SourceTag = "ADB-SYNC",
                                                Direction = dir,
                                                EndpointOrTarget = $"EP {epHex}",
                                                Protocol = "ADB-SYNC",
                                                Command = $"PUSH {_activeUploadFilePath}",
                                                Summary = singleSummary,
                                                RawPayload = fileBytes.Take(128).ToArray(),
                                                PayloadAscii = singleSummary,
                                                PayloadHex = LiveEventItem.FormatHexDump(fileBytes.Take(64).ToArray()),
                                                AdditionalDetails = $"Target Path: {_activeUploadFilePath}\nMode: {_activeUploadFileMode}\nTotal Bytes: {fileBytes.Length:N0}\nForensic Classification: {inspectionReport}\nLocal Artifact: {savePath}"
                                            });

                                            _activeTransferFile = null;
                                            _activeUploadStream.SetLength(0);
                                            _activeUploadFilePath = string.Empty;
                                        }
                                    }
                                }
                                else if (isRepeatedBinaryPattern || nonPrintableRatio > 0.30 || _isInsideFileSyncTransfer || !string.IsNullOrEmpty(_activeTransferFile))
                                {
                                    // Requirement 4: Suppress individual 1024B / 4096B line flooding for binary chunks during SEND
                                    lock (_transferLock)
                                    {
                                        int chunkOffset = 0;
                                        if (chunk.Length >= 8 && chunk[0] == 'D' && chunk[1] == 'A' && chunk[2] == 'T' && chunk[3] == 'A')
                                        {
                                            chunkOffset = 8;
                                        }
                                        if (chunk.Length > chunkOffset)
                                        {
                                            _activeUploadStream.Write(chunk, chunkOffset, chunk.Length - chunkOffset);
                                        }
                                        _activeTransferTotalBytes += chunk.Length;
                                        _activeTransferChunkCount++;
                                    }
                                }
                                else
                                {
                                    // Requirement 4: Suppress RAW-BULK | DATA IN (1B) and (5B) whose content is just '.' or '[1].'
                                    if (chunk.Length <= 5 && (cleanLineTrimmed == "." || cleanLineTrimmed == "[1]." || cleanLineTrimmed == "" || cleanLineTrimmed == "[1]" || cleanLineTrimmed == ".."))
                                    {
                                        continue;
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
                    // If queue is empty, check if pending getprop aggregator needs to be flushed
                    if (_isAggregatingGetprop && (DateTime.UtcNow - _lastGetpropChunkTime).TotalMilliseconds > 300)
                    {
                        FlushGetpropSummary("0x81", "IN");
                    }

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

    private void FlushGetpropSummary(string epHex, string dir)
    {
        if (!_isAggregatingGetprop) return;
        _isAggregatingGetprop = false;

        string summary = _getpropAggregator.BuildUnifiedSummary();
        if (_getpropAggregator.ExtractedCount > 0)
        {
            EmitEvent(new LiveEventItem
            {
                Timestamp = DateTime.UtcNow,
                Category = EventSourceCategory.AdbProxy,
                SourceTag = "ADB-GETPROP",
                Direction = dir,
                EndpointOrTarget = $"EP {epHex}",
                Protocol = "ADB-STREAM",
                Command = "GETPROP SUMMARY",
                Summary = summary,
                RawPayload = Encoding.UTF8.GetBytes(summary),
                PayloadAscii = summary,
                PayloadHex = LiveEventItem.FormatHexDump(Encoding.UTF8.GetBytes(summary)),
                AdditionalDetails = string.Join("\n", _getpropAggregator.GetAllProperties().Select(kv => $"{kv.Key} = {kv.Value}"))
            });
        }
        _getpropAggregator.Reset();
    }

    private static readonly string KernelDiagFile = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PhoenixGSM", "Logs", "kernel_packets.log");

    private static void KernelDiagLog(string line)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(KernelDiagFile)!);
            File.AppendAllText(KernelDiagFile, $"{DateTime.Now:HH:mm:ss.fff} {line}\n");
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
