using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.Sensors;

public sealed partial class TempFileAtSensor
{
    public void ProcessFileBytesDirect(
        string filePath,
        byte[] fileBytes,
        string? overrideProcessName = null,
        int overridePid = 0)
    {
        // 3. Inspect if file is in an AT/staging folder or named AT/payload
        string dirName = Path.GetDirectoryName(filePath) ?? "";
        string fileName = Path.GetFileName(filePath);
        string[] dirSegments = dirName.Split(
            new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar },
            StringSplitOptions.RemoveEmptyEntries);

        bool isAtSpecificPath = dirSegments.Any(s =>
            s.Equals("AT", StringComparison.OrdinalIgnoreCase) ||
            s.StartsWith("AT_", StringComparison.OrdinalIgnoreCase) ||
            s.StartsWith("AT-", StringComparison.OrdinalIgnoreCase) ||
            s.Equals("staging", StringComparison.OrdinalIgnoreCase) ||
            s.Equals("Temp", StringComparison.OrdinalIgnoreCase) ||
            s.Equals("Tmp", StringComparison.OrdinalIgnoreCase)) ||
            dirName.Contains(@"\mac\tmp", StringComparison.OrdinalIgnoreCase) ||
            dirName.Contains(@"/mac/tmp", StringComparison.OrdinalIgnoreCase) ||
            dirName.Contains(@"\mac\5", StringComparison.OrdinalIgnoreCase) ||
            dirName.Contains(@"/mac/5", StringComparison.OrdinalIgnoreCase) ||
            (dirName.EndsWith(@"\mac", StringComparison.OrdinalIgnoreCase) || dirName.EndsWith("/mac", StringComparison.OrdinalIgnoreCase)) ||
            fileName.StartsWith("AT", StringComparison.OrdinalIgnoreCase) ||
            fileName.StartsWith("QTMP", StringComparison.OrdinalIgnoreCase) ||
            fileName.Equals("ndx", StringComparison.OrdinalIgnoreCase) ||
            fileName.StartsWith("SRV", StringComparison.OrdinalIgnoreCase) ||
            fileName.StartsWith("athun", StringComparison.OrdinalIgnoreCase) ||
            fileName.StartsWith("trd", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".at", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".atcmd", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".seq", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".bat", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".cmd", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".script", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".modem", StringComparison.OrdinalIgnoreCase);

        // Check if content is binary modem payload vs text
        bool isBinary = IsBinaryBuffer(fileBytes);
        List<string> atCommands = [];
        string targetHint = "USB Modem Interface";
        string contentText = string.Empty;

        if (isBinary)
        {
            if (!isAtSpecificPath) return; // Ignore binary files in non-staging folders

            string formatDesc = IdentifyBinaryFormat(fileBytes, fileName);
            contentText = $"[{formatDesc}: {fileName} ({fileBytes.Length:N0} BYTES)]";

            // Specialized GSM Servicing Staged Payloads (Global Unlocker Direct Method 1 & 2)
            if (fileName.Equals("AT", StringComparison.OrdinalIgnoreCase))
            {
                targetHint = "Android /dev/shm & RIL Interface (Global Unlocker Direct Method 1)";
                atCommands.Add("[STAGED-ELF: AT (ARM64 Executable - Direct AT Command runner via /dev/shm / libril)]");
            }
            else if (fileName.StartsWith("SRV", StringComparison.OrdinalIgnoreCase))
            {
                targetHint = "Android RIL Injection Service (Carrier Unlock APK)";
                atCommands.Add("[STAGED-APK: SRV4_64 (Carrier unlock helper containing native libril.so)]");
            }
            else if (fileName.Equals("ndx", StringComparison.OrdinalIgnoreCase))
            {
                targetHint = "Android Device Admin Payload";
                atCommands.Add("[STAGED-APK: ndx (Device management service helper)]");
            }
            else if (fileName.StartsWith("QTMP", StringComparison.OrdinalIgnoreCase))
            {
                targetHint = "Global Unlocker Temp Payload";
                atCommands.Add($"[STAGED-QTMP: {fileName} ({fileBytes.Length:N0}B)]");
            }

            // Deep carve embedded strings for AT commands, shell commands, and tool markers
            var carvedStrings = ExtractPrintableStrings(fileBytes);
            foreach (var str in carvedStrings)
            {
                if (IsAtCommand(str))
                {
                    if (!atCommands.Contains(str)) atCommands.Add(str);
                }
                else if (str.Contains("/data/local/tmp/") || str.StartsWith("chmod ") || str.StartsWith("su ") || str.StartsWith("sh ") || str.StartsWith("setprop ") || str.StartsWith("pm install "))
                {
                    string shellCmd = $"[STAGED-SHELL] {str}";
                    if (!atCommands.Contains(shellCmd)) atCommands.Add(shellCmd);
                }
                else if (str.Contains("/dev/shm") || str.Contains("libril.so") || str.Contains("rild"))
                {
                    string rilCmd = $"[STAGED-RIL] {str}";
                    if (!atCommands.Contains(rilCmd)) atCommands.Add(rilCmd);
                }
                else if (str.Contains("KEY-Tool", StringComparison.OrdinalIgnoreCase) || str.Contains("SimUnlocker", StringComparison.OrdinalIgnoreCase) || str.Contains("UnlockTool", StringComparison.OrdinalIgnoreCase) || str.Contains("Global Unlocker", StringComparison.OrdinalIgnoreCase))
                {
                    string toolMarker = $"[TOOL-SIG] {str}";
                    if (!atCommands.Contains(toolMarker)) atCommands.Add(toolMarker);
                }
            }

            if (atCommands.Count == 0)
            {
                atCommands.Add($"[STAGED-PAYLOAD: {fileName} ({fileBytes.Length:N0}B) - {formatDesc}]");
            }
        }
        else
        {
            // Decode multi-format text (UTF-8, UTF-8 BOM, UTF-16, ASCII)
            contentText = DecodeText(fileBytes);
            bool hasAt = ExtractAtCommands(contentText, out atCommands, out targetHint);

            if (!hasAt && !isAtSpecificPath) return;

            // If file is in staging/AT folder or a temp file, extract all script/instruction lines without length truncation
            if (isAtSpecificPath)
            {
                var allLines = contentText.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var line in allLines)
                {
                    string trimmed = line.Trim();
                    if (string.IsNullOrWhiteSpace(trimmed)) continue;
                    if (trimmed.StartsWith('#') || trimmed.StartsWith("//") || trimmed.StartsWith(';')) continue;
                    if (!atCommands.Contains(trimmed))
                    {
                        atCommands.Add(trimmed);
                    }
                }
                // If all lines were comments or single block, preserve non-empty lines so file content is never lost
                if (atCommands.Count == 0)
                {
                    foreach (var line in allLines)
                    {
                        string trimmed = line.Trim();
                        if (!string.IsNullOrWhiteSpace(trimmed) && !atCommands.Contains(trimmed))
                        {
                            atCommands.Add(trimmed);
                        }
                    }
                }
            }
        }

        // 4. Active Process Attribution
        AttributionResult attribution;
        if (!string.IsNullOrEmpty(overrideProcessName))
        {
            attribution = new AttributionResult(overrideProcessName, overridePid);
        }
        else if (filePath.Contains(@"\mac\", StringComparison.OrdinalIgnoreCase) || filePath.Contains("/mac/", StringComparison.OrdinalIgnoreCase))
        {
            attribution = new AttributionResult("Global Unlocker.exe", 0);
        }
        else
        {
            attribution = AttributeCreatingProcess(filePath);
        }

        // 5. Ingest into OmniTrace Pipeline
        IngestCapturedTempFile(filePath, fileBytes, contentText, atCommands, targetHint, attribution.ProcessName, attribution.ProcessId, isBinary);
    }

    public void IngestCapturedTempFile(
        string filePath,
        byte[] fileBytes,
        string contentText,
        List<string> atCommands,
        string targetHint,
        string processName,
        int processId,
        bool isBinary = false)
    {
        // Deduplication check
        string contentHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(fileBytes));
        DateTime now = DateTime.UtcNow;

        if (_dedupCache.TryGetValue(filePath, out var cached))
        {
            if (now < cached.Expiration && cached.Hash == contentHash)
            {
                return; // Already processed this exact payload
            }
        }
        _dedupCache[filePath] = (now.AddSeconds(4), contentHash);

        // Periodic cleanup of deduplication cache
        if (_dedupCache.Count > 1000)
        {
            foreach (var kvp in _dedupCache)
            {
                if (now > kvp.Value.Expiration) _dedupCache.TryRemove(kvp.Key, out _);
            }
        }

        Interlocked.Increment(ref _atFilesCaptured);
        Interlocked.Add(ref _atCommandsExtracted, atCommands.Count);
        Interlocked.Add(ref _bytesCaptured, fileBytes.Length);

        string fileName = Path.GetFileName(filePath);
        string dirPath = Path.GetDirectoryName(filePath) ?? "";

        var evt = new TempFileAtEvent
        {
            FilePath = filePath,
            FileName = fileName,
            DirectoryPath = dirPath,
            FileSize = fileBytes.Length,
            ProcessName = processName,
            ProcessId = processId,
            AtCommands = atCommands,
            RawContent = isBinary ? $"[BINARY MODEM PAYLOAD: {fileBytes.Length} BYTES]" : contentText,
            RawBytes = fileBytes,
            TargetHint = targetHint,
            Timestamp = now,
            SourceTag = "TEMP-AT",
            IsBinaryPayload = isBinary
        };

        // 1. Emit RawCaptureEvent into OmniTrace Event Bus
        ulong seq = Interlocked.Increment(ref _sequence);
        var rawEvt = RawCaptureEvent.Create(
            sequence: seq,
            sensor: SensorType.FileSystem,
            transport: TransportType.FILE,
            direction: PacketDirection.HOST_TO_DEVICE,
            device: filePath,
            session: $"TEMP_AT_{fileName}",
            iface: 0,
            endpoint: fileName,
            payload: fileBytes,
            timestampSource: "TempFileAtSensor"
        );

        rawEvt.Metadata["FilePath"] = filePath;
        rawEvt.Metadata["FileName"] = fileName;
        rawEvt.Metadata["Directory"] = dirPath;
        rawEvt.Metadata["ProcessName"] = processName;
        rawEvt.Metadata["ProcessId"] = processId.ToString();
        rawEvt.Metadata["CommandCount"] = atCommands.Count.ToString();
        rawEvt.Metadata["SourceTag"] = "TEMP-AT";
        rawEvt.Metadata["TargetHint"] = targetHint;
        rawEvt.Metadata["ExecutionPhase"] = "StagedTempFile";
        rawEvt.Metadata["IsBinary"] = isBinary.ToString();

        _bus.Publish(rawEvt);

        // 2. Correlate logical commands for each staged AT command / payload
        if (isBinary)
        {
            // If binary contained extracted AT commands, report them as SerialAt
            var actualAtCmds = atCommands.Where(c => !c.StartsWith("[")).ToList();
            foreach (var atCmd in actualAtCmds)
            {
                var cmd = _bus.Correlation.Correlate(
                    atCmd,
                    KnownProtocol.SerialAt,
                    "modem-file-staged",
                    TransportType.FILE,
                    filePath,
                    $"TEMP_AT_{fileName}",
                    PacketDirection.HOST_TO_DEVICE,
                    [rawEvt.SequenceNumber],
                    [rawEvt.PayloadHash],
                    confidence: 0.98,
                    suspectedPid: processId,
                    suspectedToolName: processName
                );
                _bus.ReportLogicalCommand(cmd);
            }

            // Report any carved shell / ADB commands
            var shellCmds = atCommands.Where(c => c.StartsWith("[STAGED-SHELL]")).ToList();
            foreach (var sCmd in shellCmds)
            {
                var cmd = _bus.Correlation.Correlate(
                    sCmd,
                    KnownProtocol.ADB,
                    "adb:staged-script",
                    TransportType.FILE,
                    filePath,
                    $"TEMP_AT_{fileName}",
                    PacketDirection.HOST_TO_DEVICE,
                    [rawEvt.SequenceNumber],
                    [rawEvt.PayloadHash],
                    confidence: 0.96,
                    suspectedPid: processId,
                    suspectedToolName: processName
                );
                _bus.ReportLogicalCommand(cmd);
            }

            // Report any carved RIL / /dev/shm / baseband commands
            var rilCmds = atCommands.Where(c => c.StartsWith("[STAGED-RIL]")).ToList();
            foreach (var rCmd in rilCmds)
            {
                var cmd = _bus.Correlation.Correlate(
                    rCmd,
                    KnownProtocol.SerialAt,
                    "ril-shm-staged",
                    TransportType.FILE,
                    filePath,
                    $"TEMP_AT_{fileName}",
                    PacketDirection.HOST_TO_DEVICE,
                    [rawEvt.SequenceNumber],
                    [rawEvt.PayloadHash],
                    confidence: 0.98,
                    suspectedPid: processId,
                    suspectedToolName: processName
                );
                _bus.ReportLogicalCommand(cmd);
            }

            // Report any carved tool signatures
            var toolMarkers = atCommands.Where(c => c.StartsWith("[TOOL-SIG]")).ToList();
            foreach (var tMark in toolMarkers)
            {
                var cmd = _bus.Correlation.Correlate(
                    tMark,
                    KnownProtocol.SerialAt,
                    "gsm-tool-signature",
                    TransportType.FILE,
                    filePath,
                    $"TEMP_AT_{fileName}",
                    PacketDirection.HOST_TO_DEVICE,
                    [rawEvt.SequenceNumber],
                    [rawEvt.PayloadHash],
                    confidence: 0.95,
                    suspectedPid: processId,
                    suspectedToolName: processName
                );
                _bus.ReportLogicalCommand(cmd);
            }

            // Primary staged payload indicator
            var primaryCmd = _bus.Correlation.Correlate(
                $"[MODEM-DATA] {fileName} ({fileBytes.Length:N0}B)",
                KnownProtocol.SerialAt,
                "modem-data-staged",
                TransportType.FILE,
                filePath,
                $"TEMP_AT_{fileName}",
                PacketDirection.HOST_TO_DEVICE,
                [rawEvt.SequenceNumber],
                [rawEvt.PayloadHash],
                confidence: 0.95,
                suspectedPid: processId,
                suspectedToolName: processName
            );
            _bus.ReportLogicalCommand(primaryCmd);
        }
        else
        {
            foreach (var cmdText in atCommands)
            {
                var cmd = _bus.Correlation.Correlate(
                    cmdText,
                    KnownProtocol.SerialAt,
                    "modem-file-staged",
                    TransportType.FILE,
                    filePath,
                    $"TEMP_AT_{fileName}",
                    PacketDirection.HOST_TO_DEVICE,
                    [rawEvt.SequenceNumber],
                    [rawEvt.PayloadHash],
                    confidence: 0.98,
                    suspectedPid: processId,
                    suspectedToolName: processName
                );
                _bus.ReportLogicalCommand(cmd);
            }
        }

        // 3. Notify direct subscribers
        OnTempFileAtCaptured?.Invoke(evt);
    }

    /// <summary>
    /// Headless programmatic injection for unit tests and simulation.
    /// </summary>
    public void SimulateTempFileAtCapture(
        string filePath,
        string content,
        string processName = "Tool.exe",
        int pid = 4321,
        string targetHint = "USB Modem Interface")
    {
        byte[] bytes = Encoding.UTF8.GetBytes(content);
        ExtractAtCommands(content, out var atCommands, out string extractedHint);
        if (extractedHint != "USB Modem Interface") targetHint = extractedHint;

        IngestCapturedTempFile(filePath, bytes, content, atCommands, targetHint, processName, pid);
    }

    /// <summary>
    /// Headless programmatic injection for unit tests and simulation of binary staged payloads.
    /// </summary>
    public void SimulateTempFileAtCapture(
        string filePath,
        byte[] fileBytes,
        string? processName = null,
        int pid = 0)
    {
        ProcessFileBytesDirect(filePath, fileBytes, processName, pid);
    }
}
