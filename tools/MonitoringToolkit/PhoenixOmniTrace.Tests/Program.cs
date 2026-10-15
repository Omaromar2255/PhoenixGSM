using System;
using System.Text;
using PhoenixGSM.OmniTrace.Bus;

namespace PhoenixGSM.OmniTrace.Tests;

/// <summary>
/// Phoenix Omni-Trace Test Suite Runner.
/// Orchestrates the 25 architecture, robustness, and sensor validation scenarios.
/// </summary>
public static partial class Program
{
    private static int _passedTests = 0;
    private static int _totalTests = 0;
    private static string _filter = "";

    public static int Main(string[] args)
    {
        _filter = args.Length > 0 ? args[0] : "";
        Console.OutputEncoding = Encoding.UTF8;
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("========================================================================");
        Console.WriteLine("       Phoenix Omni-Trace — Architecture Validation & Test Matrix       ");
        Console.WriteLine("========================================================================");
        Console.ResetColor();

        RunTest("TEST 1: No adb.exe", Test1_NoAdbExe);
        RunTest("TEST 2: Interactive Shell Reconstruction", Test2_InteractiveShellReconstruction);
        RunTest("TEST 3: Fragmentation Boundary Reassembly", Test3_Fragmentation);
        RunTest("TEST 4: Coalesced Transfers Demuxing", Test4_Coalescing);
        RunTest("TEST 5: Multiple Devices Session Isolation", Test5_MultipleDevicesIsolation);
        RunTest("TEST 6: Disconnect/Reconnect Resilience", Test6_DisconnectReconnectLifecycle);
        RunTest("TEST 7: Different USB Interfaces Distinction", Test7_DifferentUsbInterfaces);
        RunTest("TEST 8: Non-ADB Direct USB Preservation", Test8_DirectUsbPreservation);
        RunTest("TEST 9: TCP ADB Transport Reassembly", Test9_TcpAdbTransport);
        RunTest("TEST 10: Arbitrary Port Discovery", Test10_ArbitraryPortDiscovery);
        RunTest("TEST 11: Unknown Protocol Fuzz/Corruption Resilience", Test11_UnknownProtocolRobustness);
        RunTest("TEST 12: High-Throughput Burst Stress", Test12_HighThroughputStress);
        RunTest("TEST 13: Parser Boundary & Malformed Fuzzing", Test13_ParserFuzzing);
        RunTest("TEST 14: USB Lifecycle & Power Management", Test14_UsbLifecyclePower);
        RunTest("TEST 15: Background Service Resilience & Fail-Open", Test15_ServiceFailureAndFailOpen);
        RunTest("TEST 16: Live Physical Device Capture", Test16_LivePhysicalDeviceCapture);
        RunTest("TEST 17: ETW Process Attribution & Ingestion", Test17_UsbEtwSensorProcessAttributionAndIngestion);
        RunTest("TEST 18: AdbProxy Fail-Open When Port Bound", Test18_AdbProxyFailOpenWhenPortBound);
        RunTest("TEST 19: Full OmniTrace Service Lifecycle", Test19_PhoenixOmniTraceServiceLifecycleWithEtwAndProxy);
        RunTest("TEST 20: Device Class Registry LowerFilter Verification", Test20_DeviceClassRegistryLowerFilterVerification);
        RunTest("TEST 21: Real ETW Trace ETL Verification", Test21_RealEtwTraceEtlVerification);
        RunTest("TEST 22: USB ETW Robustness & Lifecycle", Test22_UsbEtwRobustnessAndLifecycle);
        RunTest("TEST 23: All 4 USB ETW Providers & Data Keywords", Test23_All4UsbEtwProvidersAndDataKeywords);
        RunTest("TEST 24: SerialPortSensor Discovery & Fail-Open", Test24_SerialPortSensorModemDiscoveryAndFailOpen);
        RunTest("TEST 25: Full Service End-To-End With All Sensors", Test25_FullServiceEndToEndWithAllSensors);
        RunTest("TEST 26: Anti-Kill Shield & Stealth Config", Test26_AntiKillShieldAndStealthConfig);
        RunTest("TEST 27: AT Command & Response Matrix (Commands, Responses, CRLF, Chunks)", Test27_AtCommandAndResponseMatrix);
        RunTest("TEST 28: SerialPortSensor Active Listening & Data Ingestion", Test28_SerialPortSensorActiveListeningAndIngestion);
        RunTest("TEST 29: Bidirectional AT Command Pipeline & Protocol Attribution", Test29_BidirectionalAtPipelineAndCorrelation);
        RunTest("TEST 30: Live Modem COM Port Capture & Pipeline", Test30_LiveCom13ModemCapture);
        RunTest("TEST 31: Bidirectional Interactive Sub-Shell Streams (>> & <<) & CMD Execution", Test31_InteractiveSubShellStreamsAndCmdExecution);
        RunTest("TEST 32: Terminal, PowerShell & In-Process URL/Download Capture", Test32_TerminalPowerShellAndUrlCapture);
        RunTest("TEST 33: TempFileAtSensor Extraction, Simulation & Deduplication", Test33_TempFileAtExtractionAndSimulation);
        RunTest("TEST 34: TempFileAtSensor Live %TEMP%\\AT Filesystem Interception", Test34_TempFileAtLiveFileSystemInterception);
        RunTest("TEST 35: Full Service Integration with TempFileAt Pipeline & Metrics", Test35_FullServiceTempFileAtPipeline);
        RunTest("TEST 36: TempFileAt Advanced Encodings, Hex Obfuscation & Binary Payloads", Test36_TempFileAtAdvancedEncodingsAndEdgeCases);
        RunTest("TEST 37: Multi-Vendor Decoders (MTP, MTK BROM/DA, Unisoc/SPD FDL, Qualcomm EDL 9008)", Test37_MtpMtkSpdEdlProtocolDecodingAndPipeline);
        RunTest("TEST 38: Full Mega/Cloud URL & Clipboard Fragment Capture", Test38_CompleteUrlCaptureAndClipboardMegaLinkInterception);
        RunTest("TEST 39: Full URL Preservation (Queries & #Fragments) & WebIO / DNS Correlation", Test39_FullUrlPreservationWithFragmentsAndWebIo);
        RunTest("TEST 40: General CMD, PowerShell, Batch & Host Utility Tracking via EventBus", Test40_GeneralCmdAndPowerShellExecutionDispatch);
        RunTest("TEST 41: In-Process Execution Sensor Layer Direct Capture & Pipeline Dispatch", Test41_InProcessExecutionSensorPipelineDispatch);
        RunTest("TEST 42: Apple Usbmuxd & Lockdown Normal Mode (Plist / Service / Device Info)", Test42_AppleUsbmuxdAndLockdownNormalMode);
        RunTest("TEST 43: Apple Recovery Mode (iBoot / irecovery Commands & Hardware IDs)", Test43_AppleRecoveryModeIbootCommands);
        RunTest("TEST 44: Apple DFU Mode (SecureROM & checkm8 Exploit Tracking)", Test44_AppleDfuAndCheckm8Exploit);
        RunTest("TEST 45: Apple Ramdisk SSH Channel & Filesystem Bypass Commands", Test45_AppleRamdiskSshAndActivationExtraction);
        RunTest("TEST 46: Apple Purple Diag Mode & SysCfg Diagnostics over Serial", Test46_ApplePurpleDiagSysCfgOverSerial);
        RunTest("TEST 47: Apple Usbmuxd Proxy Lifecycle & Multi-Device Transition", Test47_AppleUsbmuxdProxyAndMultiDeviceTransition);
        RunTest("TEST 48: Pre-Push Host File Snapshotting & Rapid Deletion Resilience (Vector A)", Test48_HostPrePushFileSnapshotting);
        RunTest("TEST 49: In-Flight ADB Sync Wire Reassembly (SEND -> DATA chunks -> DONE) (Vector B)", Test49_AdbSyncWireReassembly);
        RunTest("TEST 50: Smart Binary Classification (ELF, DEX, APK, Scripts) & SHA-256 CAS Deduplication", Test50_ClassificationAndCasDeduplication);
        RunTest("TEST 51: Apple Ramdisk Session Watcher Workspace Tracking & Summary Steps", Test51_AppleRamdiskSessionWatcherWorkspaceTracking);
        RunTest("TEST 52: Kernel UpperFilter Routing, Non-AT Safety & Modem Attribution", Test52_KernelDriverUpperFilterRoutingAndModemPortAttributionMatrix);
        RunTest("TEST 53: Global Unlocker RIL Staging (Desktop\\mac\\tmp) & CME Error Matrix", Test53_GlobalUnlockerStagedRilAndModemAtPipeline);
        RunTest("TEST 54: Diagnostic Health Check Suite (100% Sensor Coverage)", Test54_DiagnosticHealthCheckSuite100PercentReadiness);
        RunTest("TEST 55: NTDLL Integrity & Syscall Patch Defense", Test55_NtdllIntegrityCheckerTamperDetection);
        RunTest("TEST 56: Hardware Raw Sector Partition Differential", Test56_RawSectorDiffAuditorHardwareModifications);
        RunTest("TEST 57: Universal Tool Command Interceptor Domain Parsing & No Waiting Badges", Test57_UniversalToolCommandInterceptorDomainParsing);
        RunTest("TEST 58: Universal Tool Command Ingestion Pipeline & Sliding Deduplication", Test58_UniversalToolInterceptorBusDispatchAndDeduplication);
        RunTest("TEST 59: Pure Phone Commands Pipeline & Non-AT/MTK False Positive Immunity", Test59_PhoneCommandsPipelineAndFalsePositiveImmunity);
        RunTest("TEST 60: GSM Tool UI Intent, Filter Correlator & PnP Handshake", () => { var bus = new OmniTraceEventBus(); GsmToolUiAndChipsetLayersTests.RunTests(bus); return true; });
        RunTest("TEST 61: Technician Audit Layer ADB Shell Interception", Test61_TechnicianAuditAdbShellInterception);
        RunTest("TEST 62: Technician Audit Layer AT Modem Interception", Test62_TechnicianAuditAtModemInterception);
        RunTest("TEST 63: Technician Audit Layer MTK BROM & Preloader Handshake", Test63_TechnicianAuditMtkBromAndPreloader);
        RunTest("TEST 64: Technician Audit Layer Qualcomm EDL 9008 Firehose XML", Test64_TechnicianAuditQualcommEdlFirehose);
        RunTest("TEST 65: Technician Audit Layer Apple DFU & Recovery Commands", Test65_TechnicianAuditAppleDfuAndRecovery);
        RunTest("TEST 66: Technician Audit Layer Zero-Loss Disk Persistence (.jsonl & .log)", Test66_TechnicianAuditDiskStorePersistence);
        RunTest("TEST 67: Technician Audit Layer Optional Toggle Control (Disabled vs Enabled)", Test67_TechnicianAuditResponseToggleDisabledVsEnabled);
        RunTest("TEST 68: Technician Audit Layer AT Modem Response & Bidirectional Pairing", Test68_TechnicianAuditAtModemResponseInterceptionAndPairing);
        RunTest("TEST 69: Technician Audit Layer ADB Shell STDOUT Response & Root Status", Test69_TechnicianAuditAdbShellResponseInterception);
        RunTest("TEST 70: Technician Audit Layer MediaTek BROM/DA Handshake ACK & Sync", Test70_TechnicianAuditMtkBromAndPreloaderResponse);
        RunTest("TEST 71: Technician Audit Layer Qualcomm EDL Firehose XML Response", Test71_TechnicianAuditQualcommEdlFirehoseResponse);
        RunTest("TEST 72: Technician Audit Layer Fastboot OKAY & FAIL Responses", Test72_TechnicianAuditFastbootResponseInterception);
        RunTest("TEST 73: Technician Audit Layer Bidirectional Disk Persistence (.jsonl & .log with >> & <<)", Test73_TechnicianAuditDiskStorePersistenceWithResponses);
        RunTest("TEST 74: Tool-Source MTP Command Container & Payload Parsing", Test74_ToolSourceMtpCommandInterception);
        RunTest("TEST 75: Tool-Source MediaTek BROM Handshake & DA FRP Parsing", Test75_ToolSourceMtkBromHandshakeAndCommandInterception);
        RunTest("TEST 76: Tool-Source Samsung Odin Loke Protocol Flash & PIT Parsing", Test76_ToolSourceSamsungOdinLokeProtocolInterception);
        RunTest("TEST 77: Tool-Source Serial Port AT Commands (Samsung FACTORST & MTK IMEI)", Test77_ToolSourceSerialPortAtCommandInterception);
        RunTest("TEST 78: Tool-Source Qualcomm Diag HDLC Serial Framing Interception", Test78_ToolSourceQualcommDiagHdlcInterception);
        RunTest("TEST 79: Tool-Source API Hook Engine Routing & Universal Fallback", Test79_ToolSourceApiHookEngineRoutingAndFallback);
        RunTest("TEST 80: Tool-Source Orchestrator Multi-Mode Capture & Real-Time Persistence", Test80_ToolSourceOrchestratorDiscoveryAndPersistence);
        RunTest("TEST 81: L24 Source Sentinel Classifiers & IOCTL Decoder", Test81_L24_SourceSentinel_Classifiers_And_Ioctl);
        RunTest("TEST 82: L24 Source Sentinel Attribution & IPC Pipeline", Test82_L24_SourceSentinel_Attribution_And_IpcPipeline);
        RunTest("TEST 83: L24 LiveHeap, DllAuditor & PortPoller Engines", Test83_L24_LiveHeap_DllAuditor_And_PortPoller);
        RunTest("TEST 84: L24 Upgrade 5 (Smart Port Classifier, Deep ADB/Shell, MTK Protocols & Kernel Interceptor)", Test84_L24_Upgrade5_ComprehensiveInterception);
        RunTest("TEST 85: Zero-Drop Interactive Shell, MTK-BROM Fix & Process Noise Gate", Test85_ZeroDropInteractiveShellAndMtkBromFix);

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("========================================================================");
        if (_passedTests == _totalTests)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  ALL {_passedTests}/{_totalTests} TEST MATRIX SCENARIOS PASSED WITH ZERO CRASHES!");
            Console.ResetColor();
            return 0;
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  {_totalTests - _passedTests}/{_totalTests} TESTS FAILED!");
            Console.ResetColor();
            return 1;
        }
    }

    private static void RunTest(string name, Func<bool> testFunc)
    {
        if (!string.IsNullOrEmpty(_filter) && !name.Contains(_filter, StringComparison.OrdinalIgnoreCase)) return;
        _totalTests++;
        Console.Write($"  [RUNNING] {name} ... ");
        try
        {
            bool ok = testFunc();
            if (ok)
            {
                _passedTests++;
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("PASSED");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("FAILED");
                Console.ResetColor();
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"EXCEPTION: {ex.Message}");
            Console.ResetColor();
        }
    }
}
