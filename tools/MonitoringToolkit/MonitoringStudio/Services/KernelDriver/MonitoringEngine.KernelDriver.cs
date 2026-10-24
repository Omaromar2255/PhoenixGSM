using System;
using System.Threading;
using System.Threading.Tasks;
using PhoenixGSM.MonitoringStudio.Models;

namespace PhoenixGSM.MonitoringStudio.Services;

public partial class MonitoringEngine
{
    // Stateful Channel, PTY & Artifact Tracking
    private bool _isInsideFileSyncTransfer = false;
    private bool _isAdbSessionActive = false;
    private bool _isPtySessionActive = false;
    private bool _isShellV2SessionActive = false;
    private string _activeInteractiveShellCommand = string.Empty;
    private string _lastActiveAtBinaryCommand = string.Empty;
    private string _activeSocketBridgeChannel = string.Empty;
    private string _lastCompletedPtyCommand = string.Empty;
    private DateTime _lastPtyKeystrokeTime = DateTime.MinValue;

    private readonly object _ptyInputLock = new();
    private readonly PhoenixGSM.OmniTrace.Decoders.ShellStreamReconstructor _ptyInputReconstructor = new();
    private CancellationTokenSource? _ptyIdleFlushCts;

    private readonly PhoenixGSM.OmniTrace.Sensors.SmartFilePushArchiver _smartFileArchiver = new();

    private readonly PhoenixGSM.OmniTrace.BinaryAnalysis.ElfBinaryInspector _elfInspector = new();
    private readonly PhoenixGSM.OmniTrace.BinaryAnalysis.ApkManifestInspector _apkInspector = new();
    private readonly PhoenixGSM.OmniTrace.AdvancedExploits.PrivilegeBridgeDetector _bridgeDetector = new();

    private readonly PhoenixGSM.OmniTrace.Decoders.AdbGetpropAggregator _getpropAggregator = new();
    private bool _isAggregatingGetprop = false;
    private DateTime _lastGetpropChunkTime = DateTime.UtcNow;

    #region USB Driver Capture Loop
    private async Task DriverCaptureLoop(CancellationToken token)
    {
        try { PhoenixGSM.UsbMonitor.DriverManager.SanitizeWinUsbAndAndroidStack(); } catch { }
        _ = Task.Run(() => AutoDismissMinGwAssertionLoopAsync(token), token);

        string sessionFolder = _smartFileArchiver.CurrentSessionDirectory;

        EmitEvent(new LiveEventItem
        {
            Category = EventSourceCategory.ArtifactVault,
            SourceTag = "SESSION-DIR",
            Protocol = "ARCHIVE",
            Command = "NEW SESSION FOLDER",
            Summary = $"Created new session artifacts directory: CapturedArtifacts/{_smartFileArchiver.CurrentSessionFolderName}",
            AdditionalDetails = $"Full Session Folder Path: {sessionFolder}"
        });

        bool driverAvailable = false;
        int statsPollCounter = 0;

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
                        if (stats.HasValue)
                        {
                            _smartFileArchiver.UpdateKernelDroppedPacketsCount(stats.Value.TotalPacketsDropped);
                        }
                        OnDriverStatusChanged?.Invoke(true, $"Active (v{(stats?.DriverVersion >> 16) ?? 1}.0)");
                        EmitEvent(new LiveEventItem
                        {
                            Category = EventSourceCategory.UsbDriver,
                            SourceTag = "KERNEL",
                            Protocol = "KMDF",
                            Command = "ATTACHED",
                            Summary = $"Connected to \\\\.\\PhoenixUsbMonitor kernel device. Bulk filter active.",
                            AdditionalDetails = $"Queue Capacity: {stats?.MaxQueueCapacity ?? 512} packets\nSession Artifacts Folder: {sessionFolder}"
                        });
                    }
                    else
                    {
                        OnDriverStatusChanged?.Invoke(false, "Filter Off (ETW & CLI Capture Active)");
                        await Task.Delay(2000, token);
                        continue;
                    }
                }

                // Drain queued packets in a burst loop so 15MB+ file transfers minimize ring-buffer pressure
                int drainedCount = 0;
                while (!token.IsCancellationRequested && drainedCount < 512)
                {
                    var kPacket = _driverClient.DequeuePacket();
                    if (!kPacket.HasValue) break;

                    drainedCount++;
                    var pkt = kPacket.Value;
                    string dir = pkt.Direction == 0 ? "OUT" : "IN";
                    byte[] chunk = new byte[pkt.CapturedLength];
                    if (pkt.CapturedLength > 0 && pkt.Data != null)
                    {
                        Array.Copy(pkt.Data, chunk, Math.Min((int)pkt.CapturedLength, pkt.Data.Length));
                    }

                    string epHex = $"0x{pkt.EndpointAddress:X2}";
                    var pDir = pkt.Direction == 0
                        ? PhoenixGSM.OmniTrace.Models.PacketDirection.HOST_TO_DEVICE
                        : PhoenixGSM.OmniTrace.Models.PacketDirection.DEVICE_TO_HOST;
                    bool isUpperFilterPort = (pkt.TransferType == 4);

                    ProcessCapturedKernelPacket(pkt, chunk, dir, epHex, pDir, isUpperFilterPort);
                }

                if (drainedCount > 0 || (++statsPollCounter % 25 == 0))
                {
                    var currentStats = _driverClient.GetStats();
                    if (currentStats.HasValue)
                    {
                        _smartFileArchiver.UpdateKernelDroppedPacketsCount(currentStats.Value.TotalPacketsDropped);
                    }
                }

                if (drainedCount == 0)
                {
                    if (_isAggregatingGetprop && (DateTime.UtcNow - _lastGetpropChunkTime).TotalMilliseconds > 300)
                    {
                        FlushGetpropSummary("0x81", "IN");
                    }

                    await Task.Delay(4, token);
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
    #endregion
}
