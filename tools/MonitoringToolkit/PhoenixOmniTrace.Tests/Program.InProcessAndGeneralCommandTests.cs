using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using PhoenixGSM.OmniTrace.Bus;
using PhoenixGSM.OmniTrace.Decoders;
using PhoenixGSM.OmniTrace.Detection;
using PhoenixGSM.OmniTrace.Models;
using PhoenixGSM.OmniTrace.Sensors;
using PhoenixGSM.OmniTrace.Service;

namespace PhoenixGSM.OmniTrace.Tests;

public static partial class Program
{
    /// <summary>
    /// TEST 39: Full URL Preservation (Query Parameters & #Fragments) & WebIO / DNS Correlation
    /// Verifies that full download links (e.g. Mega.nz with #encryption fragments, query strings, WebIO)
    /// are completely preserved without stripping and correlated with DNS resolution events.
    /// </summary>
    public static bool Test39_FullUrlPreservationWithFragmentsAndWebIo()
    {
        // 1. Verify ShellCommandParser.ExtractUrls preserves full #fragment and query strings
        string megaUrl = "https://mega.nz/file/OEBEBARD#qO-xD6wvzovv9heAfMHRUGfS6oQIlu45DlqRaUnBf18";
        string cliText = $"curl.exe -L \"{megaUrl}\" -o firmware.zip";
        var extractedUrls = ShellCommandParser.ExtractUrls(cliText);

        if (extractedUrls.Count != 1) return false;
        if (extractedUrls[0] != megaUrl) return false;

        string queryAndFragUrl = "https://firmware.gem-flash.com/download.php?id=83921&token=a8f9c#section-download";
        var queryUrls = ShellCommandParser.ExtractUrls($"powershell.exe -c \"Invoke-WebRequest -Uri '{queryAndFragUrl}'\"");
        if (queryUrls.Count != 1 || queryUrls[0] != queryAndFragUrl) return false;

        // 2. Verify NetworkUrlSensor captures full URL, extracts Fragment, and correlates DNS
        using var bus = new OmniTraceEventBus();
        using var netSensor = new NetworkUrlSensor(bus);

        CapturedUrlInfo? capturedInfo = null;
        RawCaptureEvent? rawBusEvent = null;
        string? dnsCorrelatedHost = null;

        netSensor.OnUrlCaptured += info => capturedInfo = info;
        netSensor.OnDnsCorrelated += (info, host) => dnsCorrelatedHost = host;
        bus.OnRawCaptured += raw => rawBusEvent = raw;

        // Pre-record DNS resolution for mega.nz
        netSensor.RecordDnsResolution("mega.nz", "Q-Unlocker.exe", 4321);
        if (!netSensor.IsHostCorrelatedFromDns("mega.nz")) return false;

        // Simulate URL capture for the mega link
        netSensor.SimulateUrlCapture(megaUrl, "Q-Unlocker.exe", 4321, "TEST-WEBIO");
        bus.Flush();

        if (capturedInfo == null) return false;
        if (capturedInfo.Url != megaUrl) return false;
        if (capturedInfo.Host != "mega.nz") return false;
        if (capturedInfo.Fragment != "#qO-xD6wvzovv9heAfMHRUGfS6oQIlu45DlqRaUnBf18") return false;
        if (!capturedInfo.WasDnsCorrelated) return false;
        if (capturedInfo.CorrelatedDnsHost != "mega.nz") return false;
        if (dnsCorrelatedHost != "mega.nz") return false;

        // Verify EventBus RawCaptureEvent received with rich metadata
        if (rawBusEvent == null) return false;
        if (rawBusEvent.Sensor != SensorType.Network) return false;
        if (!rawBusEvent.Metadata.TryGetValue("Fragment", out var rawFrag) || rawFrag != "#qO-xD6wvzovv9heAfMHRUGfS6oQIlu45DlqRaUnBf18") return false;
        if (!rawBusEvent.Metadata.TryGetValue("CorrelatedFromDns", out var rawDns) || rawDns != "True") return false;

        return true;
    }

    /// <summary>
    /// TEST 40: General CMD, PowerShell, Batch & Host Utility Command Tracking via EventBus
    /// Verifies that non-ADB shell executions (cmd.exe /c, powershell -enc / -Command, sc.exe, net.exe)
    /// are parsed, detected as KnownProtocol.HostCommand, and emitted as rich LogicalCommandEvents.
    /// </summary>
    public static bool Test40_GeneralCmdAndPowerShellExecutionDispatch()
    {
        // 1. Verify ShellCommandParser.ParseShellExecution across diverse shells and utilities
        var cmdParsed = ShellCommandParser.ParseShellExecution("cmd.exe", "cmd.exe /c sc start UsbDriver");
        if (!cmdParsed.IsShellWrapper || cmdParsed.Subcommand != "SC START" || cmdParsed.NormalizedCommand != "sc start UsbDriver")
        {
            return false;
        }

        var netParsed = ShellCommandParser.ParseShellExecution("cmd.exe", "cmd.exe /c net stop SpdModemService");
        if (netParsed.Subcommand != "NET STOP") return false;

        // PowerShell -Command
        var psCmdParsed = ShellCommandParser.ParseShellExecution("powershell.exe", "powershell.exe -ExecutionPolicy Bypass -Command \"Get-Service | Where-Object Status -eq Running\"");
        if (!psCmdParsed.IsPowerShell || !psCmdParsed.Subcommand.StartsWith("PS: GET-SERVICE")) return false;

        // PowerShell Base64 EncodedCommand
        string originalScript = "Start-Process Q-Unlocker.exe -ArgumentList '--silent'";
        string b64 = Convert.ToBase64String(Encoding.Unicode.GetBytes(originalScript));
        var psEncParsed = ShellCommandParser.ParseShellExecution("powershell.exe", $"powershell.exe -enc {b64}");
        if (!psEncParsed.IsPowerShell || psEncParsed.DecodedScript != originalScript) return false;
        if (!psEncParsed.Subcommand.Contains("START-PROCESS")) return false;

        // Batch script direct execution
        var batParsed = ShellCommandParser.ParseShellExecution("service_helper.bat", "service_helper.bat install /force");
        if (!batParsed.IsBatchFile || batParsed.Subcommand != "SERVICE_HELPER INSTALL") return false;

        // 2. Verify ProtocolDetector identifies KnownProtocol.HostCommand
        var detector = new ProtocolDetector();
        var candidatesFromProc = detector.DetectCandidates(Encoding.UTF8.GetBytes("cmd.exe /c sc start UsbDriver"), SensorType.Process, TransportType.BULK, PacketDirection.HOST_TO_DEVICE);
        if (candidatesFromProc.Count == 0 || candidatesFromProc[0].Protocol != KnownProtocol.HostCommand) return false;

        var candidatesFromBuffer = detector.DetectCandidates(Encoding.UTF8.GetBytes("net.exe stop SpdService"), SensorType.SyntheticTest, TransportType.BULK, PacketDirection.HOST_TO_DEVICE);
        if (!candidatesFromBuffer.Exists(c => c.Protocol == KnownProtocol.HostCommand)) return false;

        // 3. Verify OmniTraceEventBus dispatches LogicalCommandEvent for general host commands
        using var bus = new OmniTraceEventBus();
        LogicalCommandEvent? receivedCmd = null;
        bus.OnLogicalCommand += cmd => receivedCmd = cmd;

        var rawCmdEvt = RawCaptureEvent.Create(
            sequence: 1,
            sensor: SensorType.Process,
            transport: TransportType.BULK,
            direction: PacketDirection.HOST_TO_DEVICE,
            device: "Host",
            session: "cmd.exe",
            iface: 0,
            endpoint: "CMD",
            payload: Encoding.UTF8.GetBytes("cmd.exe /c sc start UsbDriver"),
            timestampSource: "ProcessAudit"
        );
        rawCmdEvt.Metadata["CommandLine"] = "cmd.exe /c sc start UsbDriver";
        rawCmdEvt.Metadata["ImageName"] = "cmd.exe";
        rawCmdEvt.Metadata["ProcessId"] = "7788";
        rawCmdEvt.Metadata["ParentProcessId"] = "1122";

        bus.Publish(rawCmdEvt);
        bus.Flush();

        if (receivedCmd == null) return false;
        if (receivedCmd.Protocol != KnownProtocol.HostCommand) return false;
        if (receivedCmd.Service != "CMD") return false;
        if (receivedCmd.Command != "SC START") return false;
        if (!receivedCmd.Details.TryGetValue("CommandLine", out var cLine) || cLine != "cmd.exe /c sc start UsbDriver") return false;
        if (receivedCmd.Attribution.ProcessId != 7788) return false;
        if (receivedCmd.Attribution.ParentProcessId != 1122) return false;
        if (receivedCmd.Attribution.ImageName != "cmd.exe") return false;

        return true;
    }

    /// <summary>
    /// TEST 41: In-Process Execution Sensor Layer Direct Capture & Pipeline Dispatch
    /// Verifies that internal GSM tool servicing operations that bypass cmd/powershell entirely
    /// (e.g. direct WinUSB / AdbWinUsbApi in-process API calls, memory-staged routines)
    /// are intercepted, attributed, and emitted as KnownProtocol.InProcess logical events.
    /// </summary>
    public static bool Test41_InProcessExecutionSensorPipelineDispatch()
    {
        using var bus = new OmniTraceEventBus();
        using var inProcSensor = new InProcessExecutionSensor(bus);

        InProcessOperationEvent? capturedOp = null;
        LogicalCommandEvent? receivedLogical = null;
        RawCaptureEvent? receivedRaw = null;

        inProcSensor.OnInProcessOperationCaptured += op => capturedOp = op;
        bus.OnLogicalCommand += cmd => receivedLogical = cmd;
        bus.OnRawCaptured += raw => receivedRaw = raw;

        inProcSensor.Start();
        if (!inProcSensor.IsRunning) return false;

        byte[] payload = [0x55, 0xAA, 0x01, 0x02, 0x03, 0x04];
        var details = new Dictionary<string, string>
        {
            ["Chipset"] = "Snapdragon 8 Gen 1 (SM8450)",
            ["ApiLayer"] = "Direct WinUsb_ControlTransfer",
            ["OperationType"] = "BROM_HANDSHAKE_INTERNAL"
        };

        // Ingest an in-process servicing operation from GlobalUnlocker
        inProcSensor.IngestInProcessOperation(
            toolName: "GlobalUnlocker.exe",
            pid: 6540,
            operationName: "WinUsb_ControlTransfer(BROM_AUTH)",
            targetDevice: "Qualcomm HS-USB QDLoader 9008",
            payload: payload,
            details: details
        );

        bus.Flush();

        // 1. Verify InProcessOperationEvent
        if (capturedOp == null) return false;
        if (capturedOp.ToolName != "GlobalUnlocker.exe") return false;
        if (capturedOp.ProcessId != 6540) return false;
        if (capturedOp.OperationName != "WinUsb_ControlTransfer(BROM_AUTH)") return false;
        if (capturedOp.TargetDevice != "Qualcomm HS-USB QDLoader 9008") return false;
        if (capturedOp.Payload.Length != 6) return false;
        if (!capturedOp.Details.TryGetValue("Chipset", out var chip) || !chip.Contains("SM8450")) return false;

        // 2. Verify RawCaptureEvent emitted to bus
        if (receivedRaw == null) return false;
        if (receivedRaw.Sensor != SensorType.Process) return false;
        if (receivedRaw.Direction != PacketDirection.INTERNAL) return false;
        if (!receivedRaw.Metadata.TryGetValue("ExecutionType", out var execType) || execType != "InProcessDirect") return false;

        // 3. Verify LogicalCommandEvent correlated with KnownProtocol.InProcess
        if (receivedLogical == null) return false;
        if (receivedLogical.Protocol != KnownProtocol.InProcess) return false;
        if (receivedLogical.Service != "GlobalUnlocker.exe") return false;
        if (receivedLogical.Command != "WinUsb_ControlTransfer(BROM_AUTH)") return false;
        if (receivedLogical.DeviceIdentity != "Qualcomm HS-USB QDLoader 9008") return false;
        if (receivedLogical.Direction != PacketDirection.INTERNAL) return false;
        if (receivedLogical.Confidence < 0.99) return false;
        if (receivedLogical.Attribution.ProcessId != 6540) return false;
        if (receivedLogical.Attribution.ImageName != "GlobalUnlocker.exe") return false;
        if (!receivedLogical.Details.TryGetValue("Chipset", out var logicalChip) || !logicalChip.Contains("SM8450")) return false;

        // 4. Verify metrics
        if (inProcSensor.OperationsCaptured < 1) return false;
        if (inProcSensor.BytesCaptured < 6) return false;

        // 5. Verify Full PhoenixOmniTraceService includes InProcessSensor
        using var fullService = new PhoenixOmniTraceService(proxyPort: 59141, pipeName: "OmniTrace_Test41_Pipe");
        if (fullService.InProcessSensor == null) return false;
        fullService.Start();
        if (!fullService.InProcessSensor.IsRunning) return false;
        fullService.Stop();

        return true;
    }
}
