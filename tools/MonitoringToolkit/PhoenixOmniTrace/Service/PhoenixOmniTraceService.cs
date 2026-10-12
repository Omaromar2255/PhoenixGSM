using System;
using PhoenixGSM.OmniTrace.Bus;
using PhoenixGSM.OmniTrace.Ipc;
using PhoenixGSM.OmniTrace.Sensors;

namespace PhoenixGSM.OmniTrace.Service;

/// <summary>
/// LAYER 15 — Phoenix Omni-Trace Background Capture Service
/// Runs independently of the GUI to guarantee fail-open operation.
/// Manages the capture fabric, ADB proxy, sensors, and IPC Named Pipe server.
/// </summary>
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public sealed class PhoenixOmniTraceService : IDisposable
{
    public OmniTraceEventBus EventBus { get; }
    public AdbTransparentProxy AdbProxy { get; }
    public UsbDeviceSensor UsbSensor { get; }
    public UsbEtwSensor UsbEtwSensor { get; }
    public UsbPcapSensor UsbPcapSensor { get; }
    public SerialPortSensor SerialSensor { get; }
    public NetworkUrlSensor NetworkSensor { get; }
    public TempFileAtSensor TempFileSensor { get; }
    public ClipboardUrlSensor ClipboardSensor { get; }
    public ProcessAttributionSensor ProcessSensor { get; }
    public InProcessExecutionSensor InProcessSensor { get; }
    public AdbPushArtifactSensor ArtifactSensor { get; }
    public ExtractionDecryptionSensor ExtractionDecryptionSensor { get; }
    public SubProcessCommandSensor SubProcessCommandSensor { get; }
    public LibUsbCommandSensor LibUsbCommandSensor { get; }
    public GsmToolSessionStreamSensor ToolSessionSensor { get; }
    public GsmToolUiActionSensor ToolUiActionSensor { get; }
    public FilterDriverCommandCorrelatorSensor FilterDriverCorrelator { get; }
    public DevicePnpArrivalCommandSensor DevicePnpArrivalSensor { get; }
    public PhoenixGSM.OmniTrace.Apple.Sensors.AppleUsbmuxdProxy UsbmuxdProxy { get; }
    public PhoenixGSM.OmniTrace.Apple.Sensors.AppleRamdiskSessionWatcher RamdiskWatcher { get; }
    public OmniTraceIpcServer IpcServer { get; }

    // Security & Vetting Extensions (الطبقات الأمنية ونظام التراجع)
    public Rollback.SystemRollbackManager RollbackManager { get; } = new();
    public KernelTelemetry.KernelTelemetryOrchestrator KernelTelemetry { get; }
    public SecurityEngine.BehavioralRulesEngine BehavioralEngine { get; } = new();

    // 🚀 Deep Interceptors (أجهزة الاعتراض العميقة: الأوامر المخفية، التنزيلات من الشبكة، والفك في الرام)
    public Commands.ProcessCommandLineSniffer CommandLineSniffer { get; } = new();
    public Commands.PowerShellScriptBlockMonitor PowerShellMonitor { get; } = new();
    public Commands.AndroidShellStdinInterceptor AndroidStdinInterceptor { get; } = new();
    public Commands.UniversalToolCommandInterceptor UniversalToolInterceptor { get; }
    public NetworkInterception.NetworkStreamPayloadDumper NetworkPayloadDumper { get; }
    public MemoryForensics.DotNetClrMemoryLoaderSensor DotNetClrLoader { get; } = new();
    public MemoryForensics.InRamMemoryPayloadDumper RamPayloadDumper { get; } = new();

    // 🛡️ Integrity, Hardware Diff & Diagnostic Health Suites
    public SyscallDefense.NtdllIntegrityChecker NtdllChecker { get; } = new();
    public HardwareDiff.RawSectorDiffAuditor RawSectorAuditor { get; } = new();
    public ValidationSuite.DiagnosticHealthCheckSuite HealthSuite { get; } = new();

    // 🎯 Technician-to-Client Phone Audit Layer
    public TechnicianAudit.TechnicianPhoneCommandAuditLayer TechnicianAuditLayer { get; }
    public bool CaptureDeviceResponses
    {
        get => TechnicianAuditLayer.CaptureDeviceResponses;
        set => TechnicianAuditLayer.CaptureDeviceResponses = value;
    }

    public bool IsRunning { get; private set; }

    public PhoenixOmniTraceService(int proxyPort = 5037, string pipeName = OmniTraceIpcServer.DefaultPipeName)
    {
        EventBus = new OmniTraceEventBus();
        UsbSensor = EventBus.UsbSensor;
        AdbProxy = new AdbTransparentProxy(EventBus, listenPort: proxyPort, targetPort: 5038);
        UsbEtwSensor = new UsbEtwSensor(EventBus, UsbSensor);
        UsbPcapSensor = new UsbPcapSensor(EventBus, UsbSensor);
        SerialSensor = new SerialPortSensor(EventBus);
        NetworkSensor = new NetworkUrlSensor(EventBus);
        TempFileSensor = new TempFileAtSensor(EventBus);
        ClipboardSensor = new ClipboardUrlSensor(EventBus);
        ProcessSensor = new ProcessAttributionSensor(EventBus.Correlation);
        InProcessSensor = new InProcessExecutionSensor(EventBus);
        ArtifactSensor = new AdbPushArtifactSensor(EventBus);
        ExtractionDecryptionSensor = new ExtractionDecryptionSensor(EventBus);
        SubProcessCommandSensor = new SubProcessCommandSensor(EventBus);
        LibUsbCommandSensor = new LibUsbCommandSensor(EventBus);
        ToolSessionSensor = new GsmToolSessionStreamSensor(EventBus);
        ToolUiActionSensor = new GsmToolUiActionSensor(EventBus);
        FilterDriverCorrelator = new FilterDriverCommandCorrelatorSensor(EventBus, ToolUiActionSensor);
        DevicePnpArrivalSensor = new DevicePnpArrivalCommandSensor(EventBus, ToolUiActionSensor);
        EventBus.ArtifactSensor = ArtifactSensor;
        UsbmuxdProxy = new PhoenixGSM.OmniTrace.Apple.Sensors.AppleUsbmuxdProxy(EventBus);
        RamdiskWatcher = new PhoenixGSM.OmniTrace.Apple.Sensors.AppleRamdiskSessionWatcher(EventBus);
        IpcServer = new OmniTraceIpcServer(EventBus, pipeName: pipeName);
        KernelTelemetry = new KernelTelemetry.KernelTelemetryOrchestrator(EventBus);
        UniversalToolInterceptor = new Commands.UniversalToolCommandInterceptor(EventBus);
        NetworkPayloadDumper = new NetworkInterception.NetworkStreamPayloadDumper(ArtifactSensor.Vault.VaultDirectory);
        TechnicianAuditLayer = new TechnicianAudit.TechnicianPhoneCommandAuditLayer(EventBus);

        // ربط محرك الكشف السلوكي بالأوامر المنطقية
        EventBus.OnLogicalCommand += cmd =>
        {
            try { BehavioralEngine.EvaluateCommand(cmd); } catch { }
        };

        // ربط ملتقط سطر الأوامر بناقل الأحداث
        CommandLineSniffer.OnProcessCommandCaptured += (sender, cmd) =>
        {
            EventBus.Correlation.RegisterProcess(new Models.ProcessAttributionMetadata
            {
                ProcessId = cmd.ProcessId,
                ImageName = cmd.ProcessName,
                CommandLine = cmd.CommandLine
            });
        };
    }

    public void Start()
    {
        if (IsRunning) return;
        IpcServer.Start();
        // Transparent proxy starts on configured port
        try
        {
            AdbProxy.Start();
        }
        catch { }

        // Start real-time ETW USB capture sensor
        try
        {
            UsbEtwSensor.Start();
        }
        catch { }

        // Start USBPcap fallback sensor if present
        try
        {
            UsbPcapSensor.Start();
        }
        catch { }

        // Start serial & modem port sensor
        try
        {
            SerialSensor.Start();
        }
        catch { }

        // Start network & URL download sensor (WinHTTP / WinINet / DNS ETW)
        try
        {
            NetworkSensor.Start();
        }
        catch { }

        // Start temporary file & AT script sensor (%TEMP%\AT* and staged modem scripts)
        try
        {
            TempFileSensor.Start();
        }
        catch { }

        // Start clipboard URL sensor (captures Mega/cloud download links copied by tools)
        try
        {
            ClipboardSensor.Start();
        }
        catch { }

        // Start in-process execution sensor
        try
        {
            InProcessSensor.Start();
        }
        catch { }

        // Start ADB push artifact and exploit interception sensor
        try
        {
            ArtifactSensor.Start();
        }
        catch { }

        // Start Apple usbmuxd transparent proxy
        try
        {
            UsbmuxdProxy.Start();
        }
        catch { }

        // Start file extraction and decryption monitoring sensor
        try
        {
            ExtractionDecryptionSensor.Start();
        }
        catch { }

        // Start sub-process execution command sensor
        try
        {
            SubProcessCommandSensor.Start();
        }
        catch { }

        // Start LibUsb/WinUSB hooking sensor for MediaTek commands
        try
        {
            LibUsbCommandSensor.Start();
        }
        catch { }

        // Start Live GSM Tool Session & Execution Stream Sensor (MediaTek/UnlockTool)
        try
        {
            ToolSessionSensor.Start();
        }
        catch { }

        // Start GSM UI Action & Intent Sensor (Pre-Connection Click Detection)
        try { ToolUiActionSensor.Start(); } catch { }

        // Start Filter Driver & Chipset Correlator Sensor
        try { FilterDriverCorrelator.Start(); } catch { }

        // Start Device PnP Hardware Arrival & Handshake Sensor
        try { DevicePnpArrivalSensor.Start(); } catch { }

        // Start kernel telemetry & ETW security orchestration
        try
        {
            KernelTelemetry.Start();
        }
        catch { }

        // Start deep command, network, and in-RAM interceptors
        try { CommandLineSniffer.Start(); } catch { }
        try { UniversalToolInterceptor.Start(); } catch { }
        try { PowerShellMonitor.Start(); } catch { }
        try { NetworkPayloadDumper.Start(); } catch { }
        try { DotNetClrLoader.Start(); } catch { }

        IsRunning = true;
    }

    public void Stop()
    {
        if (!IsRunning) return;
        IsRunning = false;
        try { DotNetClrLoader.Stop(); } catch { }
        try { NetworkPayloadDumper.Stop(); } catch { }
        try { PowerShellMonitor.Stop(); } catch { }
        try { UniversalToolInterceptor.Stop(); } catch { }
        try { CommandLineSniffer.Stop(); } catch { }
        try { KernelTelemetry.Stop(); } catch { }
        ExtractionDecryptionSensor.Stop();
        SubProcessCommandSensor.Stop();
        LibUsbCommandSensor.Stop();
        ToolSessionSensor.Stop();
        try { ToolUiActionSensor.Stop(); } catch { }
        try { FilterDriverCorrelator.Stop(); } catch { }
        try { DevicePnpArrivalSensor.Stop(); } catch { }
        ArtifactSensor.Stop();
        RamdiskWatcher.Dispose();
        UsbmuxdProxy.Stop();
        InProcessSensor.Stop();
        ClipboardSensor.Stop();
        TempFileSensor.Stop();
        NetworkSensor.Stop();
        SerialSensor.Stop();
        UsbPcapSensor.Stop();
        UsbEtwSensor.Stop();
        AdbProxy.Stop();
        IpcServer.Stop();

        // 🛡️ Automatic Rollback: Revert any modified registry keys, files or services to pristine state
        try
        {
            RollbackManager.RevertAll();
        }
        catch { }
    }

    public void Dispose()
    {
        Stop();
        TechnicianAuditLayer.Dispose();
        HealthSuite.Dispose();
        RawSectorAuditor.Dispose();
        NtdllChecker.Dispose();
        DotNetClrLoader.Dispose();
        NetworkPayloadDumper.Dispose();
        PowerShellMonitor.Dispose();
        UniversalToolInterceptor.Dispose();
        CommandLineSniffer.Dispose();
        AndroidStdinInterceptor.Dispose();
        KernelTelemetry.Dispose();
        RollbackManager.Dispose();
        ExtractionDecryptionSensor.Dispose();
        SubProcessCommandSensor.Dispose();
        LibUsbCommandSensor.Dispose();
        ToolUiActionSensor.Dispose();
        FilterDriverCorrelator.Dispose();
        DevicePnpArrivalSensor.Dispose();
        ArtifactSensor.Dispose();
        IpcServer.Dispose();
        RamdiskWatcher.Dispose();
        UsbmuxdProxy.Dispose();
        InProcessSensor.Dispose();
        ClipboardSensor.Dispose();
        TempFileSensor.Dispose();
        NetworkSensor.Dispose();
        SerialSensor.Dispose();
        UsbPcapSensor.Dispose();
        UsbEtwSensor.Dispose();
        AdbProxy.Dispose();
        EventBus.Dispose();
    }
}
