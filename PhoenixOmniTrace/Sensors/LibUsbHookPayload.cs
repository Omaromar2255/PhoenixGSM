using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using EasyHook;

namespace PhoenixGSM.OmniTrace.Sensors
{
    public class LibUsbHookPayload : EasyHook.IEntryPoint
    {
        private string _channelName;
        private NamedPipeClientStream _pipe;
        private BinaryWriter _writer;
        private LocalHook _deviceIoControlHook;
        private LocalHook _libusbControlTransferHook;

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate bool DeviceIoControlDelegate(
            IntPtr hDevice,
            uint dwIoControlCode,
            IntPtr lpInBuffer,
            uint nInBufferSize,
            IntPtr lpOutBuffer,
            uint nOutBufferSize,
            out uint lpBytesReturned,
            IntPtr lpOverlapped);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl, SetLastError = true)]
        private delegate int LibusbControlTransferDelegate(
            IntPtr dev_handle,
            byte bmRequestType,
            byte bRequest,
            ushort wValue,
            ushort wIndex,
            IntPtr data,
            ushort wLength,
            uint timeout);

        public LibUsbHookPayload(EasyHook.RemoteHooking.IContext context, string channelName)
        {
            _channelName = channelName;
        }

        public void Run(EasyHook.RemoteHooking.IContext context, string channelName)
        {
            try
            {
                _pipe = new NamedPipeClientStream(".", channelName, PipeDirection.Out, PipeOptions.Asynchronous);
                _pipe.Connect(5000);
                _writer = new BinaryWriter(_pipe, Encoding.UTF8, leaveOpen: true);

                // Hook DeviceIoControl (kernel32.dll)
                try
                {
                    _deviceIoControlHook = LocalHook.Create(
                        LocalHook.GetProcAddress("kernel32.dll", "DeviceIoControl"),
                        new DeviceIoControlDelegate(DeviceIoControl_Hook),
                        this);
                    _deviceIoControlHook.ThreadACL.SetExclusiveACL(new int[] { 0 });
                }
                catch { }

                // Hook libusb_control_transfer if available
                try
                {
                    IntPtr libusbAddr = LocalHook.GetProcAddress("libusb-1.0.dll", "libusb_control_transfer");
                    if (libusbAddr != IntPtr.Zero)
                    {
                        _libusbControlTransferHook = LocalHook.Create(
                            libusbAddr,
                            new LibusbControlTransferDelegate(LibusbControlTransfer_Hook),
                            this);
                        _libusbControlTransferHook.ThreadACL.SetExclusiveACL(new int[] { 0 });
                    }
                }
                catch { }
                
                try
                {
                    IntPtr libusb0Addr = LocalHook.GetProcAddress("libusb0.dll", "usb_control_msg");
                    // Can hook usb_control_msg as well if needed
                }
                catch { }

                RemoteHooking.WakeUpProcess();

                while (true)
                {
                    Thread.Sleep(500);
                    if (!_pipe.IsConnected)
                        break;
                }
            }
            catch
            {
                // Silent fail in injected process
            }
            finally
            {
                _writer?.Dispose();
                _pipe?.Dispose();
            }
        }

        private bool DeviceIoControl_Hook(
            IntPtr hDevice,
            uint dwIoControlCode,
            IntPtr lpInBuffer,
            uint nInBufferSize,
            IntPtr lpOutBuffer,
            uint nOutBufferSize,
            out uint lpBytesReturned,
            IntPtr lpOverlapped)
        {
            if (lpInBuffer != IntPtr.Zero && nInBufferSize > 0)
            {
                try
                {
                    byte[] buffer = new byte[nInBufferSize];
                    Marshal.Copy(lpInBuffer, buffer, 0, (int)nInBufferSize);
                    SendToPipe("DeviceIoControl", "filter-x64", buffer);
                }
                catch { }
            }

            return DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, out lpBytesReturned, lpOverlapped);
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool DeviceIoControl(
            IntPtr hDevice,
            uint dwIoControlCode,
            IntPtr lpInBuffer,
            uint nInBufferSize,
            IntPtr lpOutBuffer,
            uint nOutBufferSize,
            out uint lpBytesReturned,
            IntPtr lpOverlapped);

        private int LibusbControlTransfer_Hook(
            IntPtr dev_handle,
            byte bmRequestType,
            byte bRequest,
            ushort wValue,
            ushort wIndex,
            IntPtr data,
            ushort wLength,
            uint timeout)
        {
            if (data != IntPtr.Zero && wLength > 0 && (bmRequestType & 0x80) == 0) // HOST_TO_DEVICE
            {
                try
                {
                    byte[] buffer = new byte[wLength];
                    Marshal.Copy(data, buffer, 0, wLength);
                    SendToPipe("libusb_control_transfer", "libusb", buffer);
                }
                catch { }
            }

            return LibusbControlTransfer(dev_handle, bmRequestType, bRequest, wValue, wIndex, data, wLength, timeout);
        }

        [DllImport("libusb-1.0.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int libusb_control_transfer(
            IntPtr dev_handle,
            byte bmRequestType,
            byte bRequest,
            ushort wValue,
            ushort wIndex,
            IntPtr data,
            ushort wLength,
            uint timeout);

        private int LibusbControlTransfer(IntPtr dev_handle, byte bmRequestType, byte bRequest, ushort wValue, ushort wIndex, IntPtr data, ushort wLength, uint timeout)
        {
            return libusb_control_transfer(dev_handle, bmRequestType, bRequest, wValue, wIndex, data, wLength, timeout);
        }

        private void SendToPipe(string apiName, string target, byte[] payload)
        {
            lock (this)
            {
                try
                {
                    if (_writer != null && _pipe != null && _pipe.IsConnected)
                    {
                        _writer.Write(Process.GetCurrentProcess().Id);
                        _writer.Write(apiName);
                        _writer.Write(target);
                        _writer.Write(payload.Length);
                        _writer.Write(payload);
                        _writer.Flush();
                    }
                }
                catch { }
            }
        }
    }
}
