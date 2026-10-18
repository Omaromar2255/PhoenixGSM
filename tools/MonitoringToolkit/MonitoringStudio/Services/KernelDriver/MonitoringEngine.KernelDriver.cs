using System;
using System.Threading;
using System.Threading.Tasks;
using PhoenixGSM.MonitoringStudio.Models;

namespace PhoenixGSM.MonitoringStudio.Services;

public partial class MonitoringEngine
{
    // Stateful Channel & Artifact Tracking
    private bool _isInsideFileSyncTransfer = false;
    private bool _isAdbSessionActive = false;
    private string _activeInteractiveShellCommand = string.Empty;
    private string _lastActiveAtBinaryCommand = string.Empty;
    private string _activeSocketBridgeChannel = string.Empty;
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
        _smartFileArchiver.OnFileArchivedAsync -= EmitCapturedPushedFile;
        _smartFileArchiver.OnFileArchivedAsync += EmitCapturedPushedFile;
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
                    var pDir = pkt.Direction == 0
                        ? PhoenixGSM.OmniTrace.Models.PacketDirection.HOST_TO_DEVICE
                        : PhoenixGSM.OmniTrace.Models.PacketDirection.DEVICE_TO_HOST;
                    bool isUpperFilterPort = (pkt.TransferType == 4);

                    ProcessCapturedKernelPacket(pkt, chunk, dir, epHex, pDir, isUpperFilterPort);
                }
                else
                {
                    if (_isAggregatingGetprop && (DateTime.UtcNow - _lastGetpropChunkTime).TotalMilliseconds > 300)
                    {
                        FlushGetpropSummary("0x81", "IN");
                    }

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
    #endregion
}
