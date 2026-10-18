using System;
using System.Collections.Generic;
using System.Linq;

namespace PhoenixGSM.MonitoringStudio.Services;

public partial class MonitoringEngine
{
    public bool SendAtCommandToPort(string portName, string command, out string error)
    {
        if (_omniService?.SerialSensor != null)
        {
            return _omniService.SerialSensor.SendAtCommandToPort(portName, command, out error);
        }
        error = "OmniTrace Serial Sensor is not running.";
        return false;
    }

    public bool SendAtCommandToAnyPort(string command, out string error)
    {
        if (_omniService?.SerialSensor != null)
        {
            return _omniService.SerialSensor.SendAtCommandToAnyPort(command, out error);
        }
        error = "OmniTrace Serial Sensor is not running.";
        return false;
    }

    public string[] GetAvailableComPorts()
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (_omniService?.SerialSensor != null)
        {
            foreach (var p in _omniService.SerialSensor.MonitoredPortNames)
            {
                if (!string.IsNullOrWhiteSpace(p)) result.Add(p);
            }
        }

        lock (_knownComPorts)
        {
            foreach (var p in _knownComPorts)
            {
                if (!string.IsNullOrWhiteSpace(p)) result.Add(p);
            }
        }

        try
        {
            foreach (var p in System.IO.Ports.SerialPort.GetPortNames())
            {
                if (!string.IsNullOrWhiteSpace(p)) result.Add(p);
            }
        }
        catch { }

        return result.OrderByDescending(p =>
        {
            var desc = GetPortDescription(p) ?? "";
            bool isModem = desc.Contains("modem", StringComparison.OrdinalIgnoreCase) ||
                           desc.Contains("samsung", StringComparison.OrdinalIgnoreCase) ||
                           desc.Contains("qualcomm", StringComparison.OrdinalIgnoreCase) ||
                           desc.Contains("mediatek", StringComparison.OrdinalIgnoreCase) ||
                           desc.Contains("diag", StringComparison.OrdinalIgnoreCase);
            return isModem ? 1 : 0;
        }).ThenBy(p => p).ToArray();
    }

    public string? GetPortDescription(string portName)
    {
        if (_omniService?.SerialSensor != null)
        {
            var desc = _omniService.SerialSensor.GetPortDescription(portName);
            if (!string.IsNullOrEmpty(desc)) return desc;
        }
        return null;
    }
}
