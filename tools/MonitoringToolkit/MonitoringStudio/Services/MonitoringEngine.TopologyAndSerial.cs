using System;
using System.Collections.Generic;
using System.IO.Ports;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using PhoenixGSM.MonitoringStudio.Models;

namespace PhoenixGSM.MonitoringStudio.Services;

public partial class MonitoringEngine
{
    #region USB Topology Loop (Device Plug / Unplug Emitter)
    private async Task TopologyWatcherLoop(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                var devices = _usbScanner.ScanAllDevices();
                OnTopologyChanged?.Invoke(devices);

                var currentPhoneInstances = new HashSet<string>();
                foreach (var dev in devices.Where(d => d.IsAndroidAdb || d.IsPhoneOrModem))
                {
                    currentPhoneInstances.Add(dev.InstanceId);
                    if (!_seenDeviceInstances.Contains(dev.InstanceId))
                    {
                        _seenDeviceInstances.Add(dev.InstanceId);
                        string serial = dev.InstanceId.Split('\\').Last();

                        string proto = dev.IsAndroidAdb ? "USB-ADB" : (dev.IsModemInterface ? "USB-MODEM" : "USB-SERIAL");
                        var cat = dev.IsAndroidAdb ? EventSourceCategory.UsbDriver : EventSourceCategory.SerialPort;
                        string modeHint = dev.DeviceModeHint ?? (dev.IsAndroidAdb ? "ADB Mode" : "Normal Mode / Modem");
                        string summary = dev.IsAndroidAdb
                            ? $"Android Device Connected: {dev.DeviceName} (Serial: {serial})"
                            : $"Phone Connected ({modeHint}): {dev.DeviceName} (Serial: {serial})";

                        EmitEvent(new LiveEventItem
                        {
                            Category = cat,
                            SourceTag = dev.IsAndroidAdb ? "USB-PNP" : "MODEM-PNP",
                            Direction = "SYS",
                            EndpointOrTarget = !string.IsNullOrEmpty(dev.AttachedPort) ? dev.AttachedPort : $"{dev.VidHex}:{dev.PidHex}",
                            Protocol = proto,
                            Command = "PHONE CONNECTED",
                            Summary = summary,
                            PayloadAscii = $"Device Name: {dev.DeviceName}\nVID: 0x{dev.VidHex} | PID: 0x{dev.PidHex}\nDriver: {dev.Driver}\nInstance ID: {dev.InstanceId}\nAttached Port: {dev.AttachedPort ?? "N/A"}\nMode: {modeHint}\n" +
                                           $"Endpoints: {string.Join(", ", dev.Interfaces.SelectMany(i => i.Endpoints).Select(e => $"{e.EndpointHex} {e.Direction} {e.TransferType}"))}",
                            PayloadHex = LiveEventItem.FormatHexDump(Encoding.UTF8.GetBytes(dev.InstanceId)),
                            AdditionalDetails = $"Hardware Instance: {dev.InstanceId}\nMode Hint: {modeHint}\nAttached Port: {dev.AttachedPort ?? "Auto"}\nClass: {dev.Class}"
                        });
                    }
                }

                // Detect unplugged phones
                var removed = _seenDeviceInstances.Where(i => !currentPhoneInstances.Contains(i)).ToList();
                foreach (var inst in removed)
                {
                    _seenDeviceInstances.Remove(inst);
                    EmitEvent(new LiveEventItem
                    {
                        Category = EventSourceCategory.UsbDriver,
                        SourceTag = "USB-PNP",
                        Direction = "SYS",
                        EndpointOrTarget = "DISCONNECT",
                        Protocol = "USB-DEV",
                        Command = "PHONE REMOVED",
                        Summary = $"Phone / Device Disconnected ({inst.Split('\\').Last()})",
                        AdditionalDetails = $"Device instance {inst} removed from USB bus."
                    });
                }

                await Task.Delay(2000, token);
            }
            catch (OperationCanceledException) { break; }
            catch { await Task.Delay(2500, token); }
        }
    }
    #endregion

    #region Serial / COM Ports Watcher Loop
    private async Task SerialWatcherLoop(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                var currentPorts = SerialPort.GetPortNames().OrderBy(p => p).ToArray();
                var currentSet = new HashSet<string>(currentPorts, StringComparer.OrdinalIgnoreCase);

                // Include any ports from OmniTrace SerialSensor
                if (_omniService?.SerialSensor != null)
                {
                    foreach (var p in _omniService.SerialSensor.AllDiscoveredPortNames)
                    {
                        currentSet.Add(p);
                    }
                }

                // Scan Modem Class in registry: {4D36E96D-E325-11CE-BFC1-08002BE10318}
                try
                {
                    using var modemKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Class\{4D36E96D-E325-11CE-BFC1-08002BE10318}");
                    if (modemKey != null)
                    {
                        foreach (var sub in modemKey.GetSubKeyNames())
                        {
                            if (sub.Length == 4 && int.TryParse(sub, out _))
                            {
                                using var devK = modemKey.OpenSubKey(sub);
                                var attached = devK?.GetValue("AttachedTo")?.ToString();
                                if (!string.IsNullOrWhiteSpace(attached) && attached.StartsWith("COM", StringComparison.OrdinalIgnoreCase))
                                {
                                    currentSet.Add(attached);
                                }
                            }
                        }
                    }
                }
                catch { }

                // Scan Ports Class in registry: {4D36E978-E325-11CE-BFC1-08002BE10318}
                try
                {
                    using var portsKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Class\{4D36E978-E325-11CE-BFC1-08002BE10318}");
                    if (portsKey != null)
                    {
                        foreach (var sub in portsKey.GetSubKeyNames())
                        {
                            if (sub.Length == 4 && int.TryParse(sub, out _))
                            {
                                using var devK = portsKey.OpenSubKey(sub);
                                using var paramsK = devK?.OpenSubKey("Device Parameters");
                                var pName = paramsK?.GetValue("PortName")?.ToString();
                                if (!string.IsNullOrWhiteSpace(pName) && pName.StartsWith("COM", StringComparison.OrdinalIgnoreCase))
                                {
                                    currentSet.Add(pName);
                                }
                            }
                        }
                    }
                }
                catch { }

                List<string> addedPorts = [];
                List<string> removedPorts = [];

                lock (_knownComPorts)
                {
                    // Detect newly plugged COM ports
                    foreach (var port in currentSet)
                    {
                        if (!_knownComPorts.Contains(port))
                        {
                            _knownComPorts.Add(port);
                            addedPorts.Add(port);
                        }
                    }

                    // Detect removed COM ports
                    var removed = _knownComPorts.Where(p => !currentSet.Contains(p)).ToList();
                    foreach (var port in removed)
                    {
                        _knownComPorts.Remove(port);
                        removedPorts.Add(port);
                    }
                }

                foreach (var port in addedPorts)
                {
                    string desc = GetPortDescription(port) ?? "Serial Port / Modem";
                    bool isModem = desc.Contains("Modem", StringComparison.OrdinalIgnoreCase) ||
                                  desc.Contains("HUAWEI", StringComparison.OrdinalIgnoreCase) ||
                                  desc.Contains("HONOR", StringComparison.OrdinalIgnoreCase) ||
                                  desc.Contains("SAMSUNG", StringComparison.OrdinalIgnoreCase);

                    EmitEvent(new LiveEventItem
                    {
                        Category = EventSourceCategory.SerialPort,
                        SourceTag = isModem ? "MODEM" : "SERIAL",
                        Direction = "SYS",
                        EndpointOrTarget = port,
                        Protocol = isModem ? "MODEM-PORT" : "COM-PORT",
                        Command = "PORT ATTACHED",
                        Summary = isModem
                            ? $"Phone Modem Port detected: {desc} ({port})"
                            : $"Serial Port detected / phone connected: {desc} ({port})",
                        AdditionalDetails = $"Port Name: {port}\nDescription: {desc}\nType: {(isModem ? "USB Modem Interface" : "Serial COM Port")}"
                    });
                }

                foreach (var port in removedPorts)
                {
                    EmitEvent(new LiveEventItem
                    {
                        Category = EventSourceCategory.SerialPort,
                        SourceTag = "SERIAL",
                        Direction = "SYS",
                        EndpointOrTarget = port,
                        Protocol = "COM-PORT",
                        Command = "PORT REMOVED",
                        Summary = $"Serial Port disconnected on {port}",
                        AdditionalDetails = $"Port Name: {port}"
                    });
                }

                OnComPortsChanged?.Invoke(GetAvailableComPorts());
                await Task.Delay(1500, token);
            }
            catch (OperationCanceledException) { break; }
            catch { await Task.Delay(2000, token); }
        }
    }
    #endregion
}
