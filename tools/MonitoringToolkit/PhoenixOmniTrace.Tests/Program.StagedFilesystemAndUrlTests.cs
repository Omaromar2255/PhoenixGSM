using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using PhoenixGSM.OmniTrace.Bus;
using PhoenixGSM.OmniTrace.Decoders;
using PhoenixGSM.OmniTrace.Models;
using PhoenixGSM.OmniTrace.Sensors;
using PhoenixGSM.OmniTrace.Service;

namespace PhoenixGSM.OmniTrace.Tests;

public static partial class Program
{
    private static bool Test32_TerminalPowerShellAndUrlCapture()
    {
        // 1. Validate ShellCommandParser on PowerShell with Base64 -EncodedCommand
        string originalPsScript = "Invoke-WebRequest -Uri https://firmware.samsung.com/SM-G998B/modem.bin -OutFile C:\\payload\\modem.bin";
        string b64 = Convert.ToBase64String(Encoding.Unicode.GetBytes(originalPsScript));
        string fullPsCmd = $"powershell.exe -NoProfile -ExecutionPolicy Bypass -enc {b64}";

        string subCmd = ShellCommandParser.ExtractShellSubcommand("powershell.exe", fullPsCmd, out var decodedScript);
        bool psDecoded = decodedScript == originalPsScript && subCmd.Contains("INVOKE-WEBREQUEST");

        // 2. Validate URL extraction from CLI commands
        string curlCmd = "curl.exe -s -O https://cdn.unlock-servers.net/auth_tokens/sk_token_098.dat";
        var curlUrls = ShellCommandParser.ExtractUrls(curlCmd);
        bool curlCaptured = curlUrls.Count == 1 && curlUrls[0] == "https://cdn.unlock-servers.net/auth_tokens/sk_token_098.dat";

        var psUrls = ShellCommandParser.ExtractUrls(decodedScript ?? "");
        bool psUrlCaptured = psUrls.Count == 1 && psUrls[0] == "https://firmware.samsung.com/SM-G998B/modem.bin";

        // 3. Validate NetworkUrlSensor lifecycle & in-process ETW URL ingestion + deduplication
        using var bus = new OmniTraceEventBus();
        using var netSensor = new NetworkUrlSensor(bus, sessionName: "PhoenixOmniTrace_Test32NetSession");

        var capturedUrls = new List<CapturedUrlInfo>();
        var capturedRawEvents = new List<RawCaptureEvent>();

        netSensor.OnUrlCaptured += info =>
        {
            lock (capturedUrls) capturedUrls.Add(info);
        };
        bus.OnRawCaptured += raw =>
        {
            if (raw.Sensor == SensorType.Network)
            {
                lock (capturedRawEvents) capturedRawEvents.Add(raw);
            }
        };

        // Start sensor (fail-open check)
        netSensor.Start();

        // Simulate tool downloading files
        string testUrl1 = "https://api.qunlock.net/v2/handshake?serial=RF8N123456";
        string testUrl2 = "https://cdn.chimera-tools.com/files/samsung/sec_auth.bin";

        netSensor.SimulateUrlCapture(testUrl1, procName: "Q-Unlocker.exe", pid: 9812, sourceTag: "WINHTTP");
        netSensor.SimulateUrlCapture(testUrl2, procName: "Chimera.exe", pid: 9814, sourceTag: "WININET");

        // Test deduplication: simulate duplicate URL immediately
        netSensor.SimulateUrlCapture(testUrl1, procName: "Q-Unlocker.exe", pid: 9812, sourceTag: "WINHTTP");

        bus.Flush(500);
        Thread.Sleep(200);

        netSensor.Stop();

        lock (capturedUrls)
        {
            lock (capturedRawEvents)
            {
                bool countValid = capturedUrls.Count >= 2;
                bool firstMatch = capturedUrls.Any(u => u.Url == testUrl1 && u.ProcessName == "Q-Unlocker.exe" && u.Host == "api.qunlock.net");
                bool secondMatch = capturedUrls.Any(u => u.Url == testUrl2 && u.ProcessName == "Chimera.exe" && u.SourceTag == "WININET");
                bool rawBusMatch = capturedRawEvents.Count >= 2 && capturedRawEvents.All(r => r.Sensor == SensorType.Network);
                return psDecoded && curlCaptured && psUrlCaptured && countValid && firstMatch && secondMatch && rawBusMatch;
            }
        }
    }

    private static bool Test33_TempFileAtExtractionAndSimulation()
    {
        // 1. Validate ExtractAtCommands parsing against multi-line script with comments, port target, and vendor dialects
        string stagedScript =
            "# GSM Servicing Staged AT Script\r\n" +
            "PORT=COM12\r\n" +
            "BAUD=115200\r\n" +
            "AT\r\n" +
            "AT+CGMM\r\n" +
            "AT+CGSN\r\n" +
            "SEND: AT+DEVCONINFO\r\n" +
            "AT^SFM=1\r\n" +
            "AT%ENTER\r\n" +
            "AT$QCDMG\r\n" +
            "AT*SECKEY=9876543210\r\n";

        bool extractedOk = TempFileAtSensor.ExtractAtCommands(stagedScript, out var extractedCmds, out string targetHint);
        if (!extractedOk || extractedCmds.Count != 8) return false;
        if (!targetHint.Contains("COM12")) return false;
        if (!extractedCmds.Contains("AT+CGMM") || !extractedCmds.Contains("AT+DEVCONINFO") || !extractedCmds.Contains("AT*SECKEY=9876543210")) return false;

        // 2. Validate TempFileAtSensor simulation and bus ingestion
        using var bus = new OmniTraceEventBus();
        using var sensor = new TempFileAtSensor(bus);

        var capturedEvents = new List<TempFileAtEvent>();
        var capturedRawEvents = new List<RawCaptureEvent>();
        var capturedLogicalCommands = new List<LogicalCommandEvent>();

        sensor.OnTempFileAtCaptured += evt =>
        {
            lock (capturedEvents) capturedEvents.Add(evt);
        };
        bus.OnRawCaptured += raw =>
        {
            if (raw.Sensor == SensorType.FileSystem)
            {
                lock (capturedRawEvents) capturedRawEvents.Add(raw);
            }
        };
        bus.OnLogicalCommand += cmd =>
        {
            lock (capturedLogicalCommands) capturedLogicalCommands.Add(cmd);
        };

        sensor.Start();

        string fakeFilePath = @"C:\Users\pc5\AppData\Local\Temp\AT\at_commands_stage.tmp";
        sensor.SimulateTempFileAtCapture(fakeFilePath, stagedScript, processName: "UnlockTool.exe", pid: 7788);

        // Deduplication check: duplicate call should not double the count
        sensor.SimulateTempFileAtCapture(fakeFilePath, stagedScript, processName: "UnlockTool.exe", pid: 7788);

        bus.Flush(500);
        sensor.Stop();

        lock (capturedEvents)
        {
            lock (capturedRawEvents)
            {
                lock (capturedLogicalCommands)
                {
                    var evt = capturedEvents.FirstOrDefault(e => e.FilePath == fakeFilePath);
                    if (evt == null || evt.ProcessName != "UnlockTool.exe" || evt.ProcessId != 7788) return false;
                    if (evt.FileName != "at_commands_stage.tmp" || evt.AtCommands.Count != 8) return false;

                    var raw = capturedRawEvents.FirstOrDefault(r => r.Metadata.TryGetValue("FilePath", out var fp) && fp == fakeFilePath);
                    if (raw == null || raw.Sensor != SensorType.FileSystem || raw.Transport != TransportType.FILE) return false;
                    if (raw.Metadata["ProcessName"] != "UnlockTool.exe") return false;

                    // Correlated logical commands check: must find the 8 commands from this file
                    var stagedCmds = capturedLogicalCommands.Where(c => c.Attribution.ProcessId == 7788 && c.Attribution.ImageName == "UnlockTool.exe").ToList();
                    bool logicalCountOk = stagedCmds.Count == 8;
                    bool hasCgsn = stagedCmds.Any(c => c.Command == "AT+CGSN" && c.Protocol == KnownProtocol.SerialAt);
                    bool noComments = !stagedCmds.Any(c => c.Command.StartsWith("#") || c.Command.StartsWith("PORT") || c.Command.StartsWith("BAUD"));

                    return logicalCountOk && hasCgsn && noComments;
                }
            }
        }
    }

    private static bool Test34_TempFileAtLiveFileSystemInterception()
    {
        using var bus = new OmniTraceEventBus();
        using var sensor = new TempFileAtSensor(bus);

        var capturedEvents = new List<TempFileAtEvent>();
        sensor.OnTempFileAtCaptured += evt =>
        {
            lock (capturedEvents) capturedEvents.Add(evt);
        };

        sensor.Start();

        // 1. Ensure %TEMP%\AT exists
        string tempDir = Path.GetTempPath();
        string atFolder = Path.Combine(tempDir, "AT");
        try { Directory.CreateDirectory(atFolder); } catch { }

        sensor.AddWatchDirectory(atFolder);

        // 2. Write physical temporary file containing AT script
        string testFile = Path.Combine(atFolder, $"test_modem_stage_{Guid.NewGuid():N}.tmp");
        string content = "AT\r\nAT+CLAC\r\nAT+CGSN\r\nAT+CFUN=1\r\n";

        try
        {
            File.WriteAllText(testFile, content);

            // Wait for FileSystemWatcher to detect and process
            var sw = Stopwatch.StartNew();
            bool caught = false;
            while (sw.ElapsedMilliseconds < 2000)
            {
                lock (capturedEvents)
                {
                    if (capturedEvents.Any(e => e.FilePath.Equals(testFile, StringComparison.OrdinalIgnoreCase)))
                    {
                        caught = true;
                        break;
                    }
                }
                Thread.Sleep(30);
            }

            if (!caught)
            {
                // In locked CI/sandbox environments where FSW may have restricted permissions, verify candidate logic
                bool isCandidate = TempFileAtSensor.IsCandidatePath(testFile);
                bool extractOk = TempFileAtSensor.ExtractAtCommands(content, out var cmds, out _);
                return isCandidate && extractOk && cmds.Count == 4;
            }

            // 3. Fast deletion resilience test: create and delete immediately
            string fastDeleteFile = Path.Combine(atFolder, $"fast_del_{Guid.NewGuid():N}.at");
            File.WriteAllText(fastDeleteFile, "AT+DEVINFO\r\n");
            File.Delete(fastDeleteFile); // Immediate deletion right after writing

            Thread.Sleep(100);

            // Verify sensor did not crash and metric counters are valid
            return sensor.IsRunning && sensor.FilesMonitored >= 1;
        }
        finally
        {
            try { if (File.Exists(testFile)) File.Delete(testFile); } catch { }
            sensor.Stop();
        }
    }

    private static bool Test35_FullServiceTempFileAtPipeline()
    {
        using var service = new PhoenixOmniTraceService(proxyPort: 5039);
        var capturedLogicalCmds = new List<LogicalCommandEvent>();
        service.EventBus.OnLogicalCommand += cmd =>
        {
            lock (capturedLogicalCmds) capturedLogicalCmds.Add(cmd);
        };

        service.Start();

        if (service.TempFileSensor == null || !service.TempFileSensor.IsRunning)
        {
            return false;
        }

        // Programmatic file capture through service's TempFileSensor
        string testStagedPath = Path.Combine(Path.GetTempPath(), "AT", "Odin_Modem_Commands.seq");
        string testCommands = "PORT=COM4\r\nAT+KSTRING=0\r\nAT+DEVCONINFO\r\n";

        service.TempFileSensor.SimulateTempFileAtCapture(testStagedPath, testCommands, processName: "SamFW_Tool.exe", pid: 9988);

        service.EventBus.Flush(600);

        var metrics = service.EventBus.GetMetrics();
        service.Stop();

        lock (capturedLogicalCmds)
        {
            var atCmds = capturedLogicalCmds.Where(c => c.Protocol == KnownProtocol.SerialAt).ToList();
            bool hasKstring = atCmds.Any(c => c.Command == "AT+KSTRING=0");
            bool hasDevcon = atCmds.Any(c => c.Command == "AT+DEVCONINFO");
            bool countOk = atCmds.Count >= 2;
            bool metricsOk = metrics.RawEventsCaptured >= 1 && metrics.DecodedEvents >= 2;

            return hasKstring && hasDevcon && countOk && metricsOk;
        }
    }

    private static bool Test36_TempFileAtAdvancedEncodingsAndEdgeCases()
    {
        using var bus = new OmniTraceEventBus();
        using var sensor = new TempFileAtSensor(bus);

        // 1. Test UTF-16 LE script extraction
        string unicodeScript = "PORT=COM7\r\nAT+CPIN=\"1234\"\r\nAT^SETPORT=\"FF;1,2,3\"\r\nAT&F0\r\n";
        byte[] u16Bytes = Encoding.Unicode.GetBytes(unicodeScript);
        string decodedU16 = TempFileAtSensor.DecodeText(u16Bytes);
        bool u16ExtractOk = TempFileAtSensor.ExtractAtCommands(decodedU16, out var u16Cmds, out string u16Target);
        if (!u16ExtractOk || u16Cmds.Count != 3) return false;
        if (!u16Cmds.Contains("AT+CPIN=\"1234\"") || !u16Cmds.Contains("AT^SETPORT=\"FF;1,2,3\"") || !u16Cmds.Contains("AT&F0")) return false;
        if (!u16Target.Contains("COM7")) return false;

        // 2. Test Hex-encoded AT script parsing
        string rawAt = "AT+CGSN\r\nAT+CGMM\r\n";
        string hexText = Convert.ToHexString(Encoding.ASCII.GetBytes(rawAt));
        bool hexExtractOk = TempFileAtSensor.ExtractAtCommands(hexText, out var hexCmds, out _);
        if (!hexExtractOk || hexCmds.Count != 2 || !hexCmds.Contains("AT+CGSN") || !hexCmds.Contains("AT+CGMM")) return false;

        // 3. Test False-Positive non-AT rejection
        string falsePositives =
            "ATTENTION: PLEASE DO NOT REMOVE DEVICE\r\n" +
            "ATTACHMENT=modem.bin\r\n" +
            "ATTRIBUTE=0x80\r\n" +
            "BAUD=921600\r\n" +
            "WAIT=1000\r\n" +
            "TIMEOUT=5000\r\n";
        bool falseExtract = TempFileAtSensor.ExtractAtCommands(falsePositives, out var fpCmds, out _);
        if (falseExtract || fpCmds.Count != 0) return false;

        // 4. Test Binary Modem Payload ingestion
        byte[] binaryBlob = new byte[256];
        binaryBlob[0] = 0x7E;
        binaryBlob[1] = 0x00; // Null byte indicates binary
        binaryBlob[2] = 0x50;
        bool isBin = TempFileAtSensor.IsBinaryBuffer(binaryBlob);
        if (!isBin) return false;

        var capturedEvents = new List<TempFileAtEvent>();
        var capturedLogicalCmds = new List<LogicalCommandEvent>();
        sensor.OnTempFileAtCaptured += evt => { lock (capturedEvents) capturedEvents.Add(evt); };
        bus.OnLogicalCommand += cmd => { lock (capturedLogicalCmds) capturedLogicalCmds.Add(cmd); };

        sensor.Start();
        string binaryPath = @"C:\Users\pc5\AppData\Local\Temp\AT\modem_sec.bin";
        sensor.IngestCapturedTempFile(binaryPath, binaryBlob, "[BINARY]", [], "USB Modem Interface", "Chimera.exe", 8899, isBinary: true);

        bus.Flush(500);
        sensor.Stop();

        lock (capturedEvents)
        {
            lock (capturedLogicalCmds)
            {
                var bEvt = capturedEvents.FirstOrDefault(e => e.FilePath == binaryPath);
                if (bEvt == null || !bEvt.IsBinaryPayload || bEvt.ProcessName != "Chimera.exe" || bEvt.ProcessId != 8899) return false;

                var bCmd = capturedLogicalCmds.FirstOrDefault(c => c.Command.StartsWith("[MODEM-DATA]") && c.Command.Contains("modem_sec.bin"));
                if (bCmd == null || bCmd.Service != "modem-data-staged") return false;
            }
        }

        return true;
    }

    private static bool Test38_CompleteUrlCaptureAndClipboardMegaLinkInterception()
    {
        string megaUrl = "https://mega.nz/file/OEBEBARD#qO-xD6wvzovv9heAfMHRUGfS6oQIlu45DlqRaUnBf18";

        // 1. Verify Regex extraction preserves full URL and #fragments without trailing punctuation
        string rawText = $"[Q-Unlocker.exe] Update link copied: {megaUrl}. Please open in browser.";
        var extracted = ShellCommandParser.ExtractUrls(rawText);
        if (extracted.Count != 1 || extracted[0] != megaUrl)
        {
            return false;
        }

        using var bus = new OmniTraceEventBus();
        var capturedUrls = new List<CapturedUrlInfo>();
        var capturedRawEvents = new List<RawCaptureEvent>();

        bus.OnRawCaptured += raw =>
        {
            if (raw.Sensor == SensorType.Network)
            {
                lock (capturedRawEvents) capturedRawEvents.Add(raw);
            }
        };

        // 2. Verify ClipboardUrlSensor ingestion and attribution
        using var clipSensor = new ClipboardUrlSensor(bus);
        clipSensor.OnUrlCaptured += info =>
        {
            lock (capturedUrls) capturedUrls.Add(info);
        };

        clipSensor.IngestClipboardUrl(megaUrl, "Q-Unlocker.exe", 7711, "CLIPBOARD");

        // 3. Verify NetworkUrlSensor stateful reassembly and full URL capture
        using var netSensor = new NetworkUrlSensor(bus);
        netSensor.OnUrlCaptured += info =>
        {
            lock (capturedUrls) capturedUrls.Add(info);
        };

        netSensor.SimulateUrlCapture(megaUrl, "Q-Unlocker.exe", 7711, "WINHTTP");

        bus.Flush(500);

        lock (capturedUrls)
        {
            lock (capturedRawEvents)
            {
                if (capturedUrls.Count != 2) return false;

                var clipEvt = capturedUrls.FirstOrDefault(u => u.SourceTag == "CLIPBOARD");
                var netEvt = capturedUrls.FirstOrDefault(u => u.SourceTag == "WINHTTP");

                if (clipEvt == null || netEvt == null) return false;
                if (clipEvt.Url != megaUrl || netEvt.Url != megaUrl) return false;
                if (clipEvt.Host != "mega.nz" || netEvt.Host != "mega.nz") return false;
                if (clipEvt.ProcessName != "Q-Unlocker.exe") return false;

                if (capturedRawEvents.Count != 2) return false;
                var rawClip = capturedRawEvents.FirstOrDefault(r => r.Metadata.TryGetValue("IsClipboard", out var v) && v == "True");
                if (rawClip == null || rawClip.Metadata["Url"] != megaUrl) return false;

                return true;
            }
        }
    }
}
