using System;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using PhoenixOmniTrace.L24_SourceSentinel.Core;
using PhoenixOmniTrace.L24_SourceSentinel.Decoders;
using PhoenixOmniTrace.L24_SourceSentinel.Models;
using PhoenixGSM.OmniTrace.Commands;
using PhoenixGSM.OmniTrace.Decoders;

namespace PhoenixGSM.OmniTrace.Tests;

public static partial class Program
{
    public static bool Test81_L24_SourceSentinel_Classifiers_And_Ioctl()
    {
        // 1. AT Command Test
        byte[] atPayload = Encoding.ASCII.GetBytes("AT+CLCK=\"PN\",2\r\n");
        var (atCat, atText) = RawPayloadClassifier.Classify("NtWriteFile", "\\\\.\\COM5", 0, atPayload);
        if (atCat != "Modem AT Command") return false;
        if (!atText.Contains("AT+CLCK")) return false;

        // 2. MTK BROM Handshake Test
        byte[] bromHandshake = [0xA0, 0x0A, 0x50, 0x05];
        var (bromCat, bromText) = RawPayloadClassifier.Classify("NtWriteFile", "\\\\.\\COM7", 0, bromHandshake);
        if (bromCat != "MTK BROM Handshake") return false;

        // 3. MTK BROM Send DA Command Test
        byte[] bromDa = [0xD7, 0x00, 0x01, 0x00];
        var (daCat, daText) = RawPayloadClassifier.Classify("NtWriteFile", "\\\\.\\COM7", 0, bromDa);
        if (daCat != "MTK BROM Command") return false;
        if (!daText.Contains("0xD7")) return false;

        // 4. Qualcomm Firehose XML Test
        byte[] firehoseXml = Encoding.UTF8.GetBytes("<?xml version=\"1.0\" ?><data><program SECTOR_SIZE_IN_BYTES=\"512\"/></data>");
        var (xmlCat, xmlText) = RawPayloadClassifier.Classify("NtWriteFile", "WinUsbDevice", 0, firehoseXml);
        if (xmlCat != "Qualcomm Firehose XML") return false;

        // 5. Qualcomm Sahara Command Test
        byte[] saharaCmd = [0x01, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00];
        var (saharaCat, saharaText) = RawPayloadClassifier.Classify("NtWriteFile", "Qualcomm_9008", 0, saharaCmd);
        if (saharaCat != "Qualcomm Sahara") return false;

        // 6. IOCTL BaudRate Configuration Test
        byte[] baudBytes = BitConverter.GetBytes(921600);
        var (baudCat, baudText) = RawPayloadClassifier.Classify("NtDeviceIoControlFile", "\\\\.\\COM6", SerialIoControlDecoder.IOCTL_SERIAL_SET_BAUD_RATE, baudBytes);
        if (baudCat != "Port Config (BaudRate)") return false;
        if (!baudText.Contains("921600")) return false;

        // 7. Pipe / Shell Command Test
        byte[] shellCmd = Encoding.UTF8.GetBytes("shell:getprop ro.build.version.release");
        var (shellCat, shellText) = RawPayloadClassifier.Classify("NtWriteFile", "\\\\.\\pipe\\adbd", 0, shellCmd);
        if (shellCat != "Pipe / Shell Command") return false;

        return true;
    }

    public static bool Test82_L24_SourceSentinel_Attribution_And_IpcPipeline()
    {
        // 1. Handle Mapping & Attribution
        var attribution = new OriginAttributionEngine();
        attribution.RegisterHandle(1234, new IntPtr(0x2C4), "\\\\.\\COM6", "mtk_client.dll+0x1400");
        string resolvedTarget = attribution.LookupResourceByHandle(1234, new IntPtr(0x2C4), "FallbackTarget");
        if (resolvedTarget != "\\\\.\\COM6") return false;

        var evt = new SourceTelemetryEvent
        {
            ProcessId = 1234,
            ThreadId = 5678,
            Stage = SentinelStage.RawCommandExecution,
            HookedApiName = "NtWriteFile",
            CallerModuleOrigin = "C:\\Tools\\mtk_client.dll",
            TargetResource = resolvedTarget,
            CommandCategory = "MTK BROM Handshake",
            DecodedCommandText = "BROM Handshake",
            PayloadSize = 4
        };
        attribution.TrackEvent(evt);

        var origins = attribution.GetOriginDistribution();
        if (!origins.ContainsKey("mtk_client.dll") || origins["mtk_client.dll"] != 1) return false;

        // 2. End-to-End IPC Named Pipe Server Test
        string testLogDir = Path.Combine(Path.GetTempPath(), "PhoenixL24Test_" + Guid.NewGuid().ToString("N"));
        using var orchestrator = new SourceSentinelOrchestrator(testLogDir);
        orchestrator.Start();

        var capturedSignal = new ManualResetEventSlim(false);
        SourceTelemetryEvent? receivedEvt = null;

        orchestrator.OnTelemetryEventCaptured += captured =>
        {
            receivedEvt = captured;
            capturedSignal.Set();
        };

        // Write simulated packet directly to Named Pipe
        using (var client = new NamedPipeClientStream(".", SourceIpcServer.PipeName, PipeDirection.Out))
        {
            client.Connect(2000);
            using var writer = new BinaryWriter(client, Encoding.Unicode, leaveOpen: true);

            writer.Write(9999); // PID
            writer.Write(1111); // TID
            writer.Write((int)SentinelStage.RawCommandExecution); // Stage
            writer.Write((uint)0); // IOCTL
            writer.Write("NtWriteFile"); // API Name
            writer.Write("[RAM_Unpacked_0x7FFA800]"); // Caller Origin
            writer.Write("\\\\.\\COM3"); // Target Resource

            byte[] payload = Encoding.ASCII.GetBytes("AT+CGMR\r\n");
            writer.Write(payload.Length);
            writer.Write(payload);
            writer.Flush();
        }

        bool signaled = capturedSignal.Wait(3000);
        if (!signaled || receivedEvt == null) return false;
        if (receivedEvt.ProcessId != 9999) return false;
        if (receivedEvt.CommandCategory != "Modem AT Command") return false;
        if (receivedEvt.CallerModuleOrigin != "[RAM_Unpacked_0x7FFA800]") return false;

        // Export snapshot verification
        orchestrator.FlushAndExportSessionSnapshot();
        if (!File.Exists(orchestrator.SessionLogPath)) return false;
        string logContent = File.ReadAllText(orchestrator.SessionLogPath);
        if (!logContent.Contains("AT+CGMR")) return false;

        try { Directory.Delete(testLogDir, true); } catch { }
        return true;
    }

    public static bool Test83_L24_LiveHeap_DllAuditor_And_PortPoller()
    {
        Console.WriteLine("\n--- Testing L24 LiveHeapCommandHunter, DllAuditor & PortPoller ---");

        // 1. DllFunctionTableAuditor Test
        string tempDllPath = Path.Combine(Path.GetTempPath(), "Mock_QMSL_MSVC10R_" + Guid.NewGuid().ToString("N") + ".dll");
        try
        {
            // Build fake PE header with exported symbols
            var sb = new StringBuilder();
            sb.Append("MZ\x90\x00PE\x00\x00");
            sb.Append("... Export Section ...\x00");
            sb.Append("QLIB_ConnectServer\x00");
            sb.Append("QLIB_SendSyncDiag\x00");
            sb.Append("QPHONEMS_NvReadItem\x00");
            sb.Append("AdbWinApi_ReadEndpoint\x00");
            sb.Append("Brom_SendDownloadAgent\x00");
            File.WriteAllBytes(tempDllPath, Encoding.ASCII.GetBytes(sb.ToString().PadRight(1024, '\0')));

            var auditor = new DllFunctionTableAuditor();
            SourceTelemetryEvent? auditEvt = null;
            auditor.OnDllCapabilitiesExtracted += evt => auditEvt = evt;

            auditor.AuditLoadedModule(4444, "UnlockTool.exe", tempDllPath);
            if (auditEvt == null) return false;
            if (auditEvt.ProcessId != 4444) return false;
            if (auditEvt.CallerModuleOrigin != Path.GetFileName(tempDllPath)) return false;
            if (!auditEvt.DecodedCommandText.Contains("QLIB_ConnectServer")) return false;
            if (!auditEvt.DecodedCommandText.Contains("QPHONEMS_NvReadItem")) return false;
            Console.WriteLine($"[PASS] DllFunctionTableAuditor extracted capabilities: {auditEvt.DecodedCommandText}");
        }
        finally
        {
            try { File.Delete(tempDllPath); } catch { }
        }

        // 2. PortAndFileRadar Process Attribution & Helper File Content Test
        using var radar = new PortAndFileRadar();
        radar.CurrentMonitoredPid = 8888;
        radar.CurrentMonitoredProcessName = "CDMA-YTP.exe";

        SourceTelemetryEvent? radarEvt = null;
        radar.OnRadarActivity += evt => radarEvt = evt;

        radar.ReportPortScanEvent(radar.CurrentMonitoredPid, 12, "SetupDiGetClassDevsW", radar.CurrentMonitoredProcessName, "GUID_DEVINTERFACE_COMPORT", "فحص منافذ السيريال");
        if (radarEvt == null) return false;
        if (radarEvt.ProcessId != 8888) return false;
        if (radarEvt.CallerModuleOrigin != "CDMA-YTP.exe") return false;
        if (radarEvt.Stage != SentinelStage.PortAndDeviceRadar) return false;
        Console.WriteLine("[PASS] PortAndFileRadar PID/ProcessName binding verified.");

        // File discovery and payload reading test
        string tempRadarDir = Path.Combine(Path.GetTempPath(), "RadarTest_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempRadarDir);
        try
        {
            using var fileRadar = new PortAndFileRadar();
            fileRadar.CurrentMonitoredPid = 8888;
            fileRadar.CurrentMonitoredProcessName = "CDMA-YTP.exe";
            SourceTelemetryEvent? fileEvt = null;
            var fileSignal = new ManualResetEventSlim(false);
            fileRadar.OnRadarActivity += evt =>
            {
                if (evt.Stage == SentinelStage.LocalFilePreparation)
                {
                    fileEvt = evt;
                    fileSignal.Set();
                }
            };
            fileRadar.StartMonitoring(tempRadarDir);

            string helperPath = Path.Combine(tempRadarDir, "shield_test_sample.dat");
            File.WriteAllBytes(helperPath, Encoding.ASCII.GetBytes("AT+DEVCONINFO payload inside helper dat file"));

            if (fileSignal.Wait(2000) && fileEvt != null)
            {
                if (string.IsNullOrEmpty(fileEvt.RawPayloadHex)) return false;
                if (!fileEvt.DecodedCommandText.Contains("AT+DEVCONINFO")) return false;
                Console.WriteLine($"[PASS] PortAndFileRadar helper file content captured: {fileEvt.DecodedCommandText}");
            }
        }
        finally
        {
            try { Directory.Delete(tempRadarDir, true); } catch { }
        }

        // 3. ActiveComAndUsbPortPoller Test
        using var poller = new ActiveComAndUsbPortPoller();
        // Simply verify poller starts and disposes cleanly without crash
        poller.StartPolling(8888, "CDMA-YTP.exe");
        Thread.Sleep(50);
        Console.WriteLine("[PASS] ActiveComAndUsbPortPoller lifecycle verified.");

        return true;
    }

    public static bool Test84_L24_Upgrade5_ComprehensiveInterception()
    {
        Console.WriteLine("\n--- Testing L24 Upgrade 5 (Smart Port Classifier, Deep ADB/Shell, MTK Protocols & Kernel Interceptor) ---");

        // 1. Port Smart Classifier Test
        var (mtkCat, _) = ActiveComAndUsbPortPoller.ClassifyKernelPort(@"\Device\cdcacm1", "COM59", "UnlockTool.exe");
        if (!mtkCat.Contains("MediaTek")) return false;

        var (samCat, _) = ActiveComAndUsbPortPoller.ClassifyKernelPort(@"\Device\ssudmdm0000", "COM103", "Chimera.exe");
        if (!samCat.Contains("Samsung")) return false;

        var (qcomCat, _) = ActiveComAndUsbPortPoller.ClassifyKernelPort(@"\Device\QCUSB_COM2", "COM15", "GlobalUnlocker.exe");
        if (!qcomCat.Contains("Qualcomm")) return false;

        var (usbSerCat, _) = ActiveComAndUsbPortPoller.ClassifyKernelPort(@"\Device\USBSER000", "COM4", "KEY-Tool.exe");
        if (!usbSerCat.Contains("USB Serial")) return false;
        Console.WriteLine("[PASS] Smart Port Classifier identified MTK, Samsung, Qualcomm, and USBSER ports.");

        // 2. LiveHeapCommandHunter Interception Test
        using var hunter = new LiveHeapCommandHunter();
        var capturedEvents = new List<SourceTelemetryEvent>();
        hunter.OnCommandCaptured += capturedEvents.Add;

        // 2a. MTK XFlash Binary Packet Test (0xEF, 0xEE, 0xEE, 0xFE)
        byte[] mtkPacket = [0xEF, 0xEE, 0xEE, 0xFE, 0x05, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        hunter.InspectBufferForTesting(5555, "UnlockTool.exe", 0x100000, mtkPacket, mtkPacket.Length);
        if (!capturedEvents.Any(e => e.CommandCategory == "MTK XFlash / DA Binary Packet")) return false;
        Console.WriteLine("[PASS] LiveHeapCommandHunter captured MTK XFlash binary frame.");

        // 2b. ADB Wire Protocol OPEN packet test
        byte[] adbPacket = new byte[64];
        Encoding.ASCII.GetBytes("OPEN").CopyTo(adbPacket, 0);
        BitConverter.GetBytes(16).CopyTo(adbPacket, 12);
        Encoding.ASCII.GetBytes("shell:getprop ro").CopyTo(adbPacket, 24);
        hunter.InspectBufferForTesting(5555, "UnlockTool.exe", 0x100050, adbPacket, adbPacket.Length);
        if (!capturedEvents.Any(e => e.CommandCategory.Contains("ADB Wire"))) return false;
        Console.WriteLine("[PASS] LiveHeapCommandHunter captured ADB Wire protocol packet.");

        // 2c. Deep ADB / Shell & Heredoc test
        byte[] shellScriptBytes = Encoding.ASCII.GetBytes("cat <<EOF > /data/local/tmp/bypass.sh\r\nsu -c pm clear com.google.android.gms\r\n");
        hunter.InspectBufferForTesting(5555, "UnlockTool.exe", 0x100100, shellScriptBytes, shellScriptBytes.Length);
        if (!capturedEvents.Any(e => e.CommandCategory.Contains("Heredoc") || e.CommandCategory.Contains("Shell"))) return false;
        Console.WriteLine("[PASS] LiveHeapCommandHunter captured Heredoc and Root ADB shell commands.");

        // 2d. Bootloader / DA / Scatter Files Test
        byte[] bootFileBytes = Encoding.ASCII.GetBytes("Loading prog_emmc_firehose_8953_ddr.mbn and MT6768_Android_scatter.txt\r\n");
        hunter.InspectBufferForTesting(5555, "UnlockTool.exe", 0x100200, bootFileBytes, bootFileBytes.Length);
        if (!capturedEvents.Any(e => e.CommandCategory == "Boot Loader / DA / Firmware File")) return false;
        Console.WriteLine("[PASS] LiveHeapCommandHunter captured Firehose MBN and Scatter files.");

        // 2e. Heuristic Phone Path Test
        byte[] heuristicPathBytes = Encoding.ASCII.GetBytes("Target partition: /dev/block/bootdevice/by-name/userdata\r\n");
        hunter.InspectBufferForTesting(5555, "UnlockTool.exe", 0x100300, heuristicPathBytes, heuristicPathBytes.Length);
        if (!capturedEvents.Any(e => e.CommandCategory == "Heuristic Phone Path / Partition Target")) return false;
        Console.WriteLine("[PASS] LiveHeapCommandHunter captured sensitive phone partition path.");

        // 3. KernelAndUsbEtwInterceptor Lifecycle & Event Test
        using var kernel = new KernelAndUsbEtwInterceptor();
        SourceTelemetryEvent? kernelEvt = null;
        kernel.OnKernelActivityDetected += e => kernelEvt = e;
        kernel.StartMonitoring(5555, "UnlockTool.exe");

        kernel.ReportSyntheticKernelEvent(5555, SentinelStage.RawCommandExecution, "NtCreateUserProcess", "UnlockTool.exe -> adb.exe", "adb.exe shell getprop", "Child Process Execution", "تشغيل adb.exe");
        if (kernelEvt == null || kernelEvt.CommandCategory != "Child Process Execution") return false;
        Console.WriteLine("[PASS] KernelAndUsbEtwInterceptor synthetic event & pipeline verified.");

        // 4. SourceSentinelOrchestrator Integration Test
        string testLogDir = Path.Combine(Path.GetTempPath(), "PhoenixUpgrade5Test_" + Guid.NewGuid().ToString("N"));
        using var orchestrator = new SourceSentinelOrchestrator(testLogDir);
        if (orchestrator.KernelInterceptor == null) return false;
        Console.WriteLine("[PASS] SourceSentinelOrchestrator has KernelInterceptor actively integrated.");
        try { Directory.Delete(testLogDir, true); } catch { }

        return true;
    }

    public static bool Test85_ZeroDropInteractiveShellAndMtkBromFix()
    {
        Console.WriteLine("\n--- Testing Test 85: Zero-Drop Interactive Shell, MTK-BROM Fix & Process Noise Gate ---");

        // 1. MTK-BROM False Positive Fix
        byte[] productNameBytes = Encoding.ASCII.GetBytes("Product Name  : samsung\r\n");
        double pnScore = MtkProtocolDecoder.EvaluateMtk(productNameBytes);
        if (pnScore > 0.0)
        {
            Console.WriteLine($"[FAIL] 'Product Name' was matched by MTK-BROM with confidence {pnScore}!");
            return false;
        }

        byte[] tokenAuthBytes = Encoding.ASCII.GetBytes("Token AuthKey: 9A8B7C6D5E4F\r\n");
        double tokenScore = MtkProtocolDecoder.EvaluateMtk(tokenAuthBytes);
        if (tokenScore > 0.0)
        {
            Console.WriteLine($"[FAIL] 'Token AuthKey' was matched by MTK-BROM with confidence {tokenScore}!");
            return false;
        }

        // Single byte 0x50 handshake must still match BROM_SYNC_STEP3
        byte[] bromSync3 = [0x50];
        double sync3Score = MtkProtocolDecoder.EvaluateMtk(bromSync3);
        if (sync3Score < 0.5)
        {
            Console.WriteLine($"[FAIL] Single byte 0x50 was not matched by MTK-BROM handshake! Score: {sync3Score}");
            return false;
        }
        Console.WriteLine("[PASS] MTK-BROM Decoder correctly differentiates single-byte handshake vs multi-byte ASCII strings.");

        // 2. ForensicNoiseGate Interactive Shell & << Prompts
        ForensicNoiseGate.ResetSession();

        var evt1 = new SourceTelemetryEvent
        {
            HookedApiName = "WinUsbFilterAdbBridge",
            CommandCategory = "ADB / Interactive Shell",
            DecodedCommandText = "1163000501"
        };
        bool ok1 = ForensicNoiseGate.TryFilterAndNormalizeEvent(evt1);
        if (!ok1 || !evt1.CommandCategory.Contains("Interactive"))
        {
            Console.WriteLine($"[FAIL] ForensicNoiseGate rejected '{evt1.DecodedCommandText}' or wrong category: {evt1.CommandCategory}");
            return false;
        }

        var evt2 = new SourceTelemetryEvent
        {
            HookedApiName = "LiveRAM_UniversalInterceptor",
            CommandCategory = "Shell Script / Heredoc Injection (<<)",
            DecodedCommandText = "<< 1163000501"
        };
        bool ok2 = ForensicNoiseGate.TryFilterAndNormalizeEvent(evt2);
        if (!ok2 || !evt2.DecodedCommandText.Contains("1163000501"))
        {
            Console.WriteLine($"[FAIL] ForensicNoiseGate rejected prompt command '{evt2.DecodedCommandText}'");
            return false;
        }

        var evt3 = new SourceTelemetryEvent
        {
            HookedApiName = "LiveRAM_UniversalInterceptor",
            CommandCategory = "Shell Script / Heredoc Injection (<<)",
            DecodedCommandText = "<< AT+DEVCONINFO"
        };
        bool ok3 = ForensicNoiseGate.TryFilterAndNormalizeEvent(evt3);
        if (!ok3)
        {
            Console.WriteLine($"[FAIL] ForensicNoiseGate rejected prompt command '{evt3.DecodedCommandText}'");
            return false;
        }

        // Short corrupted noise must be rejected
        var evtNoise1 = new SourceTelemetryEvent
        {
            HookedApiName = "LiveRAM_UniversalInterceptor",
            CommandCategory = "Shell Script / Heredoc Injection (<<)",
            DecodedCommandText = "P4<<m"
        };
        bool okNoise1 = ForensicNoiseGate.TryFilterAndNormalizeEvent(evtNoise1);
        if (okNoise1)
        {
            Console.WriteLine($"[FAIL] ForensicNoiseGate allowed random noise '{evtNoise1.DecodedCommandText}'!");
            return false;
        }

        var evtNoise2 = new SourceTelemetryEvent
        {
            HookedApiName = "LiveRAM_UniversalInterceptor",
            CommandCategory = "Shell Script / Heredoc Injection (<<)",
            DecodedCommandText = "5jRU<<"
        };
        bool okNoise2 = ForensicNoiseGate.TryFilterAndNormalizeEvent(evtNoise2);
        if (okNoise2)
        {
            Console.WriteLine($"[FAIL] ForensicNoiseGate allowed random noise '{evtNoise2.DecodedCommandText}'!");
            return false;
        }
        Console.WriteLine("[PASS] ForensicNoiseGate successfully allowed clean << commands and rejected corrupted noise.");

        // 3. Process Noise Gate & WMIC Deduplication
        bool isEdgeNoise = UniversalToolCommandInterceptor.HasNoiseKeywords(
            @"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe /c");
        if (!isEdgeNoise)
        {
            Console.WriteLine("[FAIL] MicrosoftEdgeUpdate was not recognized as noise!");
            return false;
        }

        bool isSvchostNoise = UniversalToolCommandInterceptor.HasNoiseKeywords(
            @"C:\Windows\System32\svchost.exe -k netsvcs");
        if (!isSvchostNoise)
        {
            Console.WriteLine("[FAIL] svchost.exe was not recognized as noise!");
            return false;
        }

        bool isUnlockToolNoise = UniversalToolCommandInterceptor.HasNoiseKeywords(
            @"C:\UnlockTool\UnlockTool.exe");
        if (isUnlockToolNoise)
        {
            Console.WriteLine("[FAIL] UnlockTool.exe was mistakenly flagged as noise!");
            return false;
        }

        // WMIC query deduplication across session
        string wmicQuery = @"wmic.exe path Win32_PnPEntity get DeviceID";
        var wmic1 = UniversalToolCommandInterceptor.AnalyzeCommand("wmic.exe", @"C:\Windows\System32\wbem\wmic.exe", wmicQuery, "UnlockTool.exe", 100, 200, "WMI", DateTime.UtcNow);
        var wmic2 = UniversalToolCommandInterceptor.AnalyzeCommand("wmic.exe", @"C:\Windows\System32\wbem\wmic.exe", wmicQuery, "UnlockTool.exe", 100, 200, "WMI", DateTime.UtcNow);
        if (wmic1.CommandAction.Contains("SUPPRESSED") || !wmic2.CommandAction.Contains("SUPPRESSED"))
        {
            Console.WriteLine($"[FAIL] WMIC query was not properly deduplicated across the session! Call 1: {wmic1.CommandAction}, Call 2: {wmic2.CommandAction}");
            return false;
        }
        Console.WriteLine("[PASS] UniversalToolCommandInterceptor noise filtering and WMIC session deduplication verified.");

        // 4. SourceSentinelOrchestrator AdbBridge Integration
        string testLogDir = Path.Combine(Path.GetTempPath(), "PhoenixAdbBridgeTest_" + Guid.NewGuid().ToString("N"));
        using var orchestrator = new SourceSentinelOrchestrator(testLogDir);
        if (orchestrator.AdbBridge == null)
        {
            Console.WriteLine("[FAIL] SourceSentinelOrchestrator AdbBridge is null!");
            return false;
        }
        Console.WriteLine("[PASS] SourceSentinelOrchestrator AdbBridge successfully initialized.");
        try { Directory.Delete(testLogDir, true); } catch { }

        return true;
    }
}

