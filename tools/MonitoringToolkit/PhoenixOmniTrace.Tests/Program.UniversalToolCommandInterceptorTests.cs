using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using PhoenixGSM.OmniTrace.Bus;
using PhoenixGSM.OmniTrace.Commands;
using PhoenixGSM.OmniTrace.Models;

namespace PhoenixGSM.OmniTrace.Tests;

public static partial class Program
{
    public static bool Test57_UniversalToolCommandInterceptorDomainParsing()
    {
        // 1. MTK libusb filter install (must NEVER produce "WAITING FOR MTK BROM")
        var mtkFilter = UniversalToolCommandInterceptor.AnalyzeCommand(
            "filter-x64.exe",
            @"C:\UnlockTool\filter-x64.exe",
            @"filter-x64.exe install --device=USB\VID_0E8D&PID_0003",
            "UnlockTool.exe",
            1234,
            5678,
            "WMI",
            DateTime.UtcNow);

        if (mtkFilter.Category != "MediaTek") return false;
        if (!mtkFilter.CommandAction.Contains("FILTER INSTALL")) return false;
        if (!mtkFilter.CommandAction.Contains("VID_0E8D")) return false;
        if (mtkFilter.CommandAction.Contains("WAITING FOR MTK BROM")) return false; // Verify static waiting badge is completely absent
        if (mtkFilter.SourceTag != "MTK-FILTER") return false;
        if (mtkFilter.Protocol != KnownProtocol.MtkBrom) return false;

        // 2. Qualcomm EDL filter install
        var qcomFilter = UniversalToolCommandInterceptor.AnalyzeCommand(
            "filter-x64.exe",
            @"C:\Chimera\filter-x64.exe",
            @"filter-x64.exe install --device=USB\VID_05C6&PID_9008",
            "Chimera.exe",
            2001,
            2002,
            "WMI",
            DateTime.UtcNow);

        if (qcomFilter.Category != "QualcommEdl") return false;
        if (!qcomFilter.CommandAction.Contains("QUALCOMM EDL 9008")) return false;
        if (qcomFilter.SourceTag != "QCOM-FILTER") return false;
        if (qcomFilter.Protocol != KnownProtocol.QualcommSahara) return false;

        // 3. Unisoc/SPD filter install
        var spdFilter = UniversalToolCommandInterceptor.AnalyzeCommand(
            "filter-x64.exe",
            @"C:\DFTPro\filter-x64.exe",
            @"filter-x64.exe install --device=USB\VID_1782&PID_4D00",
            "DFT_Pro.exe",
            3001,
            3002,
            "WMI",
            DateTime.UtcNow);

        if (spdFilter.Category != "UnisocSpd") return false;
        if (!spdFilter.CommandAction.Contains("SPD DIAG/FDL")) return false;
        if (spdFilter.SourceTag != "SPD-FILTER") return false;
        if (spdFilter.Protocol != KnownProtocol.SpreadtrumFdl) return false;

        // 4. WMIC MTK Hardware Query
        var wmicMtk = UniversalToolCommandInterceptor.AnalyzeCommand(
            "wmic.exe",
            @"C:\Windows\System32\wbem\wmic.exe",
            @"wmic path Win32_PnPEntity where ""DeviceID like '%VID_0E8D%'"" get DeviceID,Name",
            "UnlockTool.exe",
            1234,
            5680,
            "WMI",
            DateTime.UtcNow);

        if (wmicMtk.Category != "MediaTek") return false;
        if (!wmicMtk.CommandAction.Contains("WMIC QUERY: PNP (VID_0E8D MTK)")) return false;
        if (wmicMtk.SourceTag != "WMIC-QUERY") return false;

        // 5. WMIC Serial / COM Port Query
        var wmicPorts = UniversalToolCommandInterceptor.AnalyzeCommand(
            "wmic.exe",
            @"C:\Windows\System32\wbem\wmic.exe",
            @"wmic path Win32_SerialPort get DeviceID,Description",
            "MiracleBox.exe",
            4001,
            4002,
            "WMI",
            DateTime.UtcNow);

        if (wmicPorts.Category != "Cmd") return false;
        if (!wmicPorts.CommandAction.Contains("SERIAL/COM PORTS")) return false;

        // 6. DevCon MTK device query
        var devcon = UniversalToolCommandInterceptor.AnalyzeCommand(
            "devcon.exe",
            @"C:\Tools\devcon.exe",
            @"devcon.exe status ""USB\VID_0E8D*""",
            "UnlockTool.exe",
            1234,
            5681,
            "WMI",
            DateTime.UtcNow);

        if (devcon.Category != "MediaTek") return false;
        if (!devcon.CommandAction.Contains("DEVCON: STATUS USB\\VID_0E8D* (MTK)")) return false;
        if (devcon.SourceTag != "DEVCON") return false;

        // 7. PnPUtil enum devices
        var pnputil = UniversalToolCommandInterceptor.AnalyzeCommand(
            "pnputil.exe",
            @"C:\Windows\System32\pnputil.exe",
            @"pnputil /enum-devices /class Ports",
            "DFT_Pro.exe",
            3001,
            3003,
            "WMI",
            DateTime.UtcNow);

        if (pnputil.Category != "Cmd") return false;
        if (pnputil.SourceTag != "PNPUTIL") return false;

        // 8. Fastboot getvar all
        var fastboot = UniversalToolCommandInterceptor.AnalyzeCommand(
            "fastboot.exe",
            @"C:\Platform-tools\fastboot.exe",
            @"fastboot.exe getvar all",
            "cmd.exe",
            5001,
            5002,
            "WMI",
            DateTime.UtcNow);

        if (fastboot.Category != "AdbProxy") return false;
        if (fastboot.Protocol != KnownProtocol.Fastboot) return false;
        if (!fastboot.CommandAction.Contains("FASTBOOT GETVAR ALL")) return false;

        // 9. ADB getprop
        var adb = UniversalToolCommandInterceptor.AnalyzeCommand(
            "adb.exe",
            @"C:\Platform-tools\adb.exe",
            @"adb.exe shell getprop ro.product.model",
            "UnlockTool.exe",
            1234,
            5682,
            "WMI",
            DateTime.UtcNow);

        if (adb.Category != "AdbProxy") return false;
        if (adb.Protocol != KnownProtocol.ADB) return false;
        if (!adb.CommandAction.Contains("ADB")) return false;

        // 10. CMD /C wrapper unwrapping
        var cmdWrapper = UniversalToolCommandInterceptor.AnalyzeCommand(
            "cmd.exe",
            @"C:\Windows\System32\cmd.exe",
            @"cmd.exe /c filter-x64.exe install --device=USB\VID_0E8D&PID_0003",
            "UnlockTool.exe",
            1234,
            5683,
            "WMI",
            DateTime.UtcNow);

        if (cmdWrapper.Category != "MediaTek") return false;
        if (!cmdWrapper.CommandAction.Contains("FILTER INSTALL")) return false;
        if (cmdWrapper.SourceTag != "MTK-FILTER" && cmdWrapper.SourceTag != "CMD-EXEC") return false;

        // 11. PowerShell Base64 EncodedCommand decoding
        string script = "Get-PnpDevice -PresentOnly | Where-Object HardwareID -like '*VID_0E8D*'";
        string b64 = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        var psEnc = UniversalToolCommandInterceptor.AnalyzeCommand(
            "powershell.exe",
            @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            $"powershell.exe -enc {b64}",
            "Chimera.exe",
            2001,
            2003,
            "WMI",
            DateTime.UtcNow);

        if (psEnc.Category != "Shell") return false;
        if (psEnc.DecodedScript != script) return false;
        if (!psEnc.CommandAction.Contains("GET-PNPDEVICE")) return false;

        // 12. GSM Tool Child Process execution
        var childProc = UniversalToolCommandInterceptor.AnalyzeCommand(
            "mtk_flasher.exe",
            @"C:\UnlockTool\modules\mtk_flasher.exe",
            @"mtk_flasher.exe --da DA_PL.bin --scatter MT6765_scatter.txt",
            "UnlockTool.exe",
            1234,
            5684,
            "WMI",
            DateTime.UtcNow);

        if (childProc.Category != "MediaTek") return false;
        if (childProc.SourceTag != "MTK-TOOL") return false;

        return true;
    }

    public static bool Test58_UniversalToolInterceptorBusDispatchAndDeduplication()
    {
        using var bus = new OmniTraceEventBus();
        using var interceptor = new UniversalToolCommandInterceptor(bus);

        var capturedCommands = new List<LogicalCommandEvent>();
        bus.OnLogicalCommand += cmd =>
        {
            capturedCommands.Add(cmd);
        };

        // Register GSM Tool PID
        interceptor.RegisterToolPid(9999);

        // First execution: should be dispatched
        interceptor.ProcessIncomingProcessEvent(
            "filter-x64.exe",
            1001,
            9999,
            @"filter-x64.exe install --device=USB\VID_0E8D&PID_0003",
            @"C:\UnlockTool\filter-x64.exe",
            "WMI",
            DateTime.UtcNow,
            "UnlockTool.exe");

        if (capturedCommands.Count != 1) return false;

        var cmd = capturedCommands[0];
        if (!cmd.Command.Contains("FILTER INSTALL")) return false;
        if (!cmd.Command.Contains("VID_0E8D")) return false;
        if (cmd.Command.Contains("WAITING FOR MTK BROM")) return false; // Verify no static waiting badge
        if (cmd.Confidence < 0.95) return false;
        if (!cmd.Details.TryGetValue("SourceTag", out var tag) || tag != "MTK-FILTER") return false;
        if (!cmd.Details.TryGetValue("Category", out var cat) || cat != "MediaTek") return false;
        if (!cmd.Details.TryGetValue("Caller", out var caller) || caller != "UnlockTool.exe") return false;
        if (!cmd.Details.TryGetValue("Summary", out var summary) || !summary.Contains("UnlockTool.exe")) return false;

        // Process attribution check in bus
        var meta = bus.Correlation.GetProcess(1001);
        if (meta == null || meta.ImageName != "filter-x64.exe") return false;

        // Second execution: DUPLICATE within 3 seconds -> must be suppressed by sliding window deduplication
        interceptor.ProcessIncomingProcessEvent(
            "filter-x64.exe",
            1001,
            9999,
            @"filter-x64.exe install --device=USB\VID_0E8D&PID_0003",
            @"C:\UnlockTool\filter-x64.exe",
            "WMI",
            DateTime.UtcNow,
            "UnlockTool.exe");

        if (capturedCommands.Count != 1) return false; // Duplicate was correctly dropped!

        // Third execution: DIFFERENT command -> must be immediately dispatched
        interceptor.ProcessIncomingProcessEvent(
            "wmic.exe",
            1002,
            9999,
            @"wmic path Win32_PnPEntity where ""DeviceID like '%VID_0E8D%'"" get DeviceID",
            @"C:\Windows\System32\wbem\wmic.exe",
            "WMI",
            DateTime.UtcNow,
            "UnlockTool.exe");

        if (capturedCommands.Count != 2) return false;

        var cmd2 = capturedCommands[1];
        if (!cmd2.Command.Contains("WMIC QUERY: PNP (VID_0E8D MTK)")) return false;
        if (!cmd2.Details.TryGetValue("SourceTag", out var tag2) || tag2 != "WMIC-QUERY") return false;

        return true;
    }

    public static bool Test59_PhoneCommandsPipelineAndFalsePositiveImmunity()
    {
        // 1. Verify MTK-DA False Positive Immunity on ASCII Text Strings
        byte[] getpropProp = Encoding.ASCII.GetBytes("[ro.product.model]: [SM-G715A]");
        double mtkConf1 = PhoenixGSM.OmniTrace.Decoders.MtkProtocolDecoder.EvaluateMtk(getpropProp);
        if (mtkConf1 > 0.0) return false;

        byte[] logcatLine = Encoding.ASCII.GetBytes("10-14 12:12:37.478  5199  5199 D RILJ : OEM_HOOK_RAW");
        double mtkConf2 = PhoenixGSM.OmniTrace.Decoders.MtkProtocolDecoder.EvaluateMtk(logcatLine);
        if (mtkConf2 > 0.0) return false;

        byte[] authPrompt = Encoding.ASCII.GetBytes("AuthKey: C547ED9D1E5A75D1");
        double mtkConf3 = PhoenixGSM.OmniTrace.Decoders.MtkProtocolDecoder.EvaluateMtk(authPrompt);
        if (mtkConf3 > 0.0) return false;

        // 2. Verify Genuine MTK BROM Sync Sequence is still detected with high confidence
        byte[] realBromSync = [0xA0, 0x0A, 0x50, 0x05];
        double realBromConf = PhoenixGSM.OmniTrace.Decoders.MtkProtocolDecoder.EvaluateMtk(realBromSync);
        if (realBromConf < 0.95) return false;

        // 3. Verify Dedicated Phone-Directed Commands Tube (Host ➔ Device)
        if (!PhoneCommandClassifier.IsPhoneDirectedCommand(
            "OPEN -> shell:reboot debug0x494d",
            "OPEN: LocalID=77 | Destination: shell:reboot debug0x494d",
            "OUT",
            "ADB",
            "AdbProxy")) return false;

        if (!PhoneCommandClassifier.IsPhoneDirectedCommand(
            "ARTIFACT PUSH",
            "Pushed /data/local/tmp/AT (ELF Executable)",
            "OUT",
            "ADB-SYNC",
            "ArtifactVault")) return false;

        if (!PhoneCommandClassifier.IsPhoneDirectedCommand(
            "0601000e00005841410000584141",
            "Samsung RIL OEM_HOOK_RAW",
            "OUT",
            "SERIAL-AT",
            "SerialPort")) return false;

        // 4. Verify False Inclusions are strictly filtered out from Phone Commands Tube
        if (PhoneCommandClassifier.IsPhoneDirectedCommand(
            "GoogleUpdater.exe --crash-handler",
            "[updater.exe] updater.exe --crash-handler",
            "OUT",
            "PROCESS",
            "Process")) return false;

        if (PhoneCommandClassifier.IsPhoneDirectedCommand(
            "[ro.boot.em.model]: [SM-G715A]",
            "Device property dump",
            "IN",
            "SERIALAT",
            "SerialPort")) return false;

        if (PhoneCommandClassifier.IsPhoneDirectedCommand(
            "OKAY",
            "OKAY ACK packet",
            "IN",
            "ADB",
            "AdbProxy")) return false;

        // 5. Verify Pure Command Extraction (Zero Framing, 100% Clean Phone Executables)
        string? pureAdb = PhoneCommandClassifier.ExtractPureCommand(
            "OPEN -> shell:reboot debug0x494d", "OPEN shell", "OUT", "ADB", "AdbProxy");
        if (pureAdb != "reboot debug0x494d") return false;

        string? purePush = PhoneCommandClassifier.ExtractPureCommand(
            "ARTIFACT PUSH", "Pushed /data/local/tmp/AT (ELF Executable)", "OUT", "ADB-SYNC", "ArtifactVault");
        if (purePush != "/data/local/tmp/AT") return false;

        string? pureRil = PhoneCommandClassifier.ExtractPureCommand(
            "0601000e00005841410000584141", "Samsung RIL OEM_HOOK_RAW", "OUT", "SERIAL-AT", "SerialPort");
        if (pureRil != "0601000e00005841410000584141") return false;

        string? pureAdbPm = PhoneCommandClassifier.ExtractPureCommand(
            "OPEN -> shell:pm disable-user com.sec.android.AutoPreconfig", "OPEN shell", "OUT", "ADB", "AdbProxy");
        if (pureAdbPm != "pm disable-user com.sec.android.AutoPreconfig") return false;

        // Verify that noise and handshakes return null
        string? pureNoise = PhoneCommandClassifier.ExtractPureCommand(
            "GoogleUpdater.exe --crash-handler", "updater", "OUT", "PROCESS", "Process");
        if (pureNoise != null) return false;

        string? pureAck = PhoneCommandClassifier.ExtractPureCommand(
            "OKAY", "ACK", "IN", "ADB", "AdbProxy");
        if (pureAck != null) return false;

        return true;
    }
}
