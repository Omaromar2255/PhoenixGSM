using System;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using PhoenixGSM.MonitoringStudio.Models;

namespace PhoenixGSM.MonitoringStudio.Services;

public partial class MonitoringEngine
{
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
                    bool isFastboot = rawAsciiPreview.StartsWith("getvar:", StringComparison.OrdinalIgnoreCase) ||
                                      rawAsciiPreview.StartsWith("flash:", StringComparison.OrdinalIgnoreCase) ||
                                      rawAsciiPreview.StartsWith("erase:", StringComparison.OrdinalIgnoreCase) ||
                                      rawAsciiPreview.StartsWith("download:", StringComparison.OrdinalIgnoreCase) ||
                                      (dir == "IN" && (rawAsciiPreview.StartsWith("OKAY", StringComparison.Ordinal) || rawAsciiPreview.StartsWith("FAIL", StringComparison.Ordinal)));

                    bool isAdbShellPayload = rawAsciiPreview.StartsWith("shell:", StringComparison.OrdinalIgnoreCase) ||
                                             rawAsciiPreview.StartsWith("Result: Parcel(", StringComparison.OrdinalIgnoreCase) ||
                                             rawAsciiPreview.StartsWith("[DEVICE_PROVISIONED]", StringComparison.OrdinalIgnoreCase) ||
                                             rawAsciiPreview.StartsWith("while [ \"$(getprop", StringComparison.OrdinalIgnoreCase) ||
                                             (rawAsciiPreview.StartsWith("[") && rawAsciiPreview.Contains("]: [")) ||
                                             (rawAsciiPreview.Contains(" D RIL") || rawAsciiPreview.Contains(" V RIL") || rawAsciiPreview.Contains(" I RIL") || rawAsciiPreview.Contains(" E RIL")) ||
                                             rawAsciiPreview.Contains("OEM_HOOK_RAW", StringComparison.OrdinalIgnoreCase) ||
                                             rawAsciiPreview.StartsWith("/data/local/tmp", StringComparison.OrdinalIgnoreCase) ||
                                             rawAsciiPreview.StartsWith("STAT", StringComparison.Ordinal) ||
                                             rawAsciiPreview.StartsWith("SEND", StringComparison.Ordinal) ||
                                             rawAsciiPreview.StartsWith("RECV", StringComparison.Ordinal);

                    bool isUpperFilterPort = (pkt.TransferType == 4) || (pkt.EndpointAddress == 0x02 || pkt.EndpointAddress == 0x81);
                    bool isNonAtUsbProtocol = !isUpperFilterPort && (isAdbHeader || isAdbShellPayload || isSahara || isFirehose || isFastboot);

                    double atConf = chunk.Length > 0 
                        ? PhoenixGSM.OmniTrace.Detection.ProtocolDetector.EvaluateSerialAt(chunk, PhoenixGSM.OmniTrace.Models.SensorType.Serial, PhoenixGSM.OmniTrace.Models.TransportType.SERIAL) 
                        : 0.0;
                    bool isAsciiText = chunk.Length > 0 && chunk.All(b => b == 0 || b == 10 || b == 13 || (b >= 32 && b < 127));
                    string cleanLine = chunk.Length > 0 ? Encoding.ASCII.GetString(chunk).Trim('\r', '\n', '\t', '\0', ' ') : "";

                    double mtkConf = chunk.Length > 0 ? PhoenixGSM.OmniTrace.Decoders.MtkProtocolDecoder.EvaluateMtk(chunk) : 0.0;
                    bool isMtk = mtkConf >= 0.70;

                    bool isAt = !isMtk && (isUpperFilterPort || (!isNonAtUsbProtocol && (
                        atConf >= 0.70 ||
                        (isAsciiText && atConf >= 0.30)
                    )));

                    KernelDiagLog($"PKT {dir} EP={epHex} TT={pkt.TransferType} len={pkt.ActualLength} cap={chunk.Length} isMtk={isMtk}({mtkConf:F2}) isAt={isAt} isUF={isUpperFilterPort} atConf={atConf:F2} ascii={isAsciiText} adb={isAdbHeader} sahara={isSahara} fh={isFirehose} fb={isFastboot} | {Encoding.ASCII.GetString(chunk[..Math.Min(chunk.Length, 64)].Select(b => b >= 32 && b < 127 ? b : (byte)'.').ToArray())}");

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
                                string cmdDisplay = (!string.IsNullOrEmpty(frame.PayloadPreview) && (frame.Command == "OPEN" || frame.Command == "WRTE"))
                                    ? $"{frame.Command} -> {frame.PayloadPreview}"
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
                                    PayloadAscii = frame.PayloadPreview ?? "",
                                    PayloadHex = LiveEventItem.FormatHexDump(frame.Payload ?? Array.Empty<byte>()),
                                    AdditionalDetails = $"Arg0=0x{frame.Arg0:X8}, Arg1=0x{frame.Arg1:X8}, Length={frame.DataLength} B, Checksum=0x{frame.DataCheck:X8}"
                                });
                            }
                        }
                        else if (chunk.Length > 0)
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
