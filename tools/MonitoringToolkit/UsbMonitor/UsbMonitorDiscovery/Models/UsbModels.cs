using System.Text.Json.Serialization;

namespace PhoenixGSM.UsbMonitorDiscovery.Models;

public class UsbEndpointInfo
{
    public byte EndpointAddress { get; set; }
    public string Direction { get; set; } = "";
    public string TransferType { get; set; } = "";
    public ushort MaxPacketSize { get; set; }
    public byte Interval { get; set; }

    public string EndpointHex => $"0x{EndpointAddress:X2}";
}

public class UsbInterfaceInfo
{
    public byte InterfaceNumber { get; set; }
    public byte AlternateSetting { get; set; }
    public byte Class { get; set; }
    public byte SubClass { get; set; }
    public byte Protocol { get; set; }
    public string ClassDescription { get; set; } = "";
    public bool IsAdbInterface { get; set; }
    public List<UsbEndpointInfo> Endpoints { get; set; } = new();
}

public class UsbSubDevicePnpInfo
{
    public string InstanceId { get; set; } = "";
    public string FriendlyName { get; set; } = "";
    public string Class { get; set; } = "";
    public string DriverVersion { get; set; } = "";
    public string Service { get; set; } = "";
    public string? InterfaceNumber { get; set; }
}

public class UsbDeviceInfo
{
    public string DeviceName { get; set; } = "";
    public ushort Vid { get; set; }
    public ushort Pid { get; set; }
    public string VidHex => $"{Vid:X4}";
    public string PidHex => $"{Pid:X4}";
    public string InstanceId { get; set; } = "";
    public string Class { get; set; } = "";
    public string Driver { get; set; } = "";
    public string Service { get; set; } = "";
    public int PortNumber { get; set; }
    public string HubPath { get; set; } = "";
    public string Speed { get; set; } = "Unknown";
    public bool IsConnected { get; set; } = true;
    public bool IsAndroidAdb { get; set; }
    public bool IsPhoneOrModem { get; set; }
    public bool IsModemInterface { get; set; }
    public bool IsSerialPortInterface { get; set; }
    public string? AttachedPort { get; set; }
    public string? DeviceModeHint { get; set; }

    public List<UsbSubDevicePnpInfo> SubDevices { get; set; } = new();
    public List<UsbInterfaceInfo> Interfaces { get; set; } = new();
}
