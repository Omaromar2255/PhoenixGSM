using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using PhoenixGSM.UsbMonitor.Models;
using PhoenixGSM.UsbMonitor.Protocol;

namespace PhoenixGSM.UsbMonitor;

public class UsbDriverClient : IDisposable
{
    public const string DevicePath = @"\\.\PhoenixUsbMonitor";

    public const uint IOCTL_PHOENIX_GET_STATS = 0x88902004;
    public const uint IOCTL_PHOENIX_GET_PACKET = 0x88902008;
    public const uint IOCTL_PHOENIX_CLEAR_BUFFER = 0x8890200C;

    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint FILE_SHARE_READ = 1;
    private const uint FILE_SHARE_WRITE = 2;
    private const uint OPEN_EXISTING = 3;

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct DriverStats
    {
        public uint DriverVersion;
        public ulong TotalPacketsCaptured;
        public ulong TotalPacketsDropped;
        public ulong TotalBytesCaptured;
        public uint CurrentlyQueued;
        public uint MaxQueueCapacity;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct KernelUsbPacket
    {
        public long Timestamp;
        public uint Direction;
        public uint TransferType;
        public uint EndpointAddress;
        public uint ActualLength;
        public uint CapturedLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1024)]
        public byte[] Data;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern SafeFileHandle CreateFile(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition,
        uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(
        SafeFileHandle hDevice, uint dwIoControlCode,
        IntPtr lpInBuffer, uint nInBufferSize,
        IntPtr lpOutBuffer, uint nOutBufferSize,
        out uint lpBytesReturned, IntPtr lpOverlapped);

    private SafeFileHandle? _handle;
    private readonly IntPtr _statsBuffer = Marshal.AllocHGlobal(Marshal.SizeOf<DriverStats>());
    private readonly IntPtr _packetBuffer = Marshal.AllocHGlobal(Marshal.SizeOf<KernelUsbPacket>());
    private readonly int _statsSize = Marshal.SizeOf<DriverStats>();
    private readonly int _packetSize = Marshal.SizeOf<KernelUsbPacket>();
    private bool _disposed;

    public bool IsDriverAvailable()
    {
        try
        {
            using var h = CreateFile(DevicePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
            return !h.IsInvalid;
        }
        catch
        {
            return false;
        }
    }

    public bool Connect()
    {
        if (_handle != null && !_handle.IsInvalid) return true;

        _handle = CreateFile(DevicePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        return !_handle.IsInvalid;
    }

    public DriverStats? GetStats()
    {
        if (!Connect() || _handle == null) return null;

        lock (this)
        {
            if (DeviceIoControl(_handle, IOCTL_PHOENIX_GET_STATS, IntPtr.Zero, 0, _statsBuffer, (uint)_statsSize, out _, IntPtr.Zero))
            {
                return Marshal.PtrToStructure<DriverStats>(_statsBuffer);
            }
        }
        return null;
    }

    public KernelUsbPacket? DequeuePacket()
    {
        if (!Connect() || _handle == null) return null;

        lock (this)
        {
            if (DeviceIoControl(_handle, IOCTL_PHOENIX_GET_PACKET, IntPtr.Zero, 0, _packetBuffer, (uint)_packetSize, out uint returned, IntPtr.Zero))
            {
                if (returned >= 28) // header size
                {
                    return Marshal.PtrToStructure<KernelUsbPacket>(_packetBuffer);
                }
            }
        }
        return null;
    }

    public void ClearQueue()
    {
        if (!Connect() || _handle == null) return;
        DeviceIoControl(_handle, IOCTL_PHOENIX_CLEAR_BUFFER, IntPtr.Zero, 0, IntPtr.Zero, 0, out _, IntPtr.Zero);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        _handle?.Dispose();
        _handle = null;

        Marshal.FreeHGlobal(_statsBuffer);
        Marshal.FreeHGlobal(_packetBuffer);
        GC.SuppressFinalize(this);
    }
}
