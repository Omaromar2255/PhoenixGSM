using System;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using EasyHook;

namespace PhoenixOmniTrace.Payload
{
    /// <summary>
    /// The payload injected into the target tool (e.g. UnlockTool).
    /// Intercepts Windows API calls and forwards them to PhoenixOmniTrace via IPC Pipe.
    /// </summary>
    public class ApiInterceptorEntryPoint : IEntryPoint
    {
        private NamedPipeClientStream? _ipcClient;
        private readonly string _channelName;

        // Delegates matching the API signatures
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate bool DeviceIoControl_Delegate(
            IntPtr hDevice,
            uint dwIoControlCode,
            IntPtr lpInBuffer,
            uint nInBufferSize,
            IntPtr lpOutBuffer,
            uint nOutBufferSize,
            out uint lpBytesReturned,
            IntPtr lpOverlapped);

        public ApiInterceptorEntryPoint(RemoteHooking.IContext context, string channelName)
        {
            _channelName = channelName;
        }

        public void Run(RemoteHooking.IContext context, string channelName)
        {
            try
            {
                // Connect to the OmniTrace IPC Pipe
                _ipcClient = new NamedPipeClientStream(".", channelName, PipeDirection.Out, PipeOptions.Asynchronous);
                _ipcClient.Connect(5000); // 5 seconds timeout
            }
            catch (Exception)
            {
                // If IPC fails, we can't report anything, so exit quietly
                return;
            }

            LocalHook? deviceIoControlHook = null;

            try
            {
                // 1. Hook kernel32.dll -> DeviceIoControl
                deviceIoControlHook = LocalHook.Create(
                    LocalHook.GetProcAddress("kernel32.dll", "DeviceIoControl"),
                    new DeviceIoControl_Delegate(DeviceIoControl_Hook),
                    this);

                // Enable hook for all threads except the current thread
                deviceIoControlHook.ThreadACL.SetExclusiveACL([0]);

                // Keep the injected thread alive while hooked
                while (true)
                {
                    Thread.Sleep(1000);

                    // Check if IPC is still alive
                    if (_ipcClient != null && !_ipcClient.IsConnected)
                    {
                        break;
                    }
                }
            }
            catch (Exception ex)
            {
                ReportToHost("ERROR", "None", Encoding.UTF8.GetBytes(ex.Message));
            }
            finally
            {
                deviceIoControlHook?.Dispose();
                _ipcClient?.Dispose();
                LocalHook.Release();
            }
        }

        /// <summary>
        /// Hook Implementation for DeviceIoControl
        /// This method executes INSTEAD OF the real kernel32!DeviceIoControl in the tool's memory space.
        /// </summary>
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
            // First, capture the payload *before* passing it to the real API
            byte[] inPayload = [];
            if (lpInBuffer != IntPtr.Zero && nInBufferSize > 0)
            {
                // Limit max capture size to avoid massive memory spikes (e.g., 4MB limit)
                int captureSize = (int)Math.Min(nInBufferSize, 4 * 1024 * 1024);
                inPayload = new byte[captureSize];
                Marshal.Copy(lpInBuffer, inPayload, 0, captureSize);
            }

            // Construct an identifier for the IOCTL
            string apiDesc = $"DeviceIoControl (IOCTL: 0x{dwIoControlCode:X})";
            string targetHandle = $"Handle: 0x{hDevice.ToInt64():X}";

            // Report the captured command to OmniTrace
            ReportToHost(apiDesc, targetHandle, inPayload);

            // Call the original, un-hooked Windows API using pinvoke signature to ensure the tool functions normally
            return Real_DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, out lpBytesReturned, lpOverlapped);
        }

        // PInvoke mapping for the real function so we can call it inside the hook
        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "DeviceIoControl")]
        private static extern bool Real_DeviceIoControl(
            IntPtr hDevice,
            uint dwIoControlCode,
            IntPtr lpInBuffer,
            uint nInBufferSize,
            IntPtr lpOutBuffer,
            uint nOutBufferSize,
            out uint lpBytesReturned,
            IntPtr lpOverlapped);


        /// <summary>
        /// Serializes and sends the intercepted API data over the Named Pipe back to the ToolApiHookSensor.
        /// </summary>
        private void ReportToHost(string apiName, string targetDevice, byte[] payload)
        {
            if (_ipcClient == null || !_ipcClient.IsConnected) return;

            try
            {
                int pid = Process.GetCurrentProcess().Id;
                
                // Format matches the reader in ToolApiHookSensor:
                // [PID 4B] [ApiName] [Target] [PayloadLen 4B] [Payload X]
                // For strings, BinaryWriter prefixes them with a 7-bit encoded integer length
                
                using var ms = new System.IO.MemoryStream();
                using var writer = new System.IO.BinaryWriter(ms, Encoding.UTF8);

                writer.Write(pid);
                writer.Write(apiName);
                writer.Write(targetDevice);
                writer.Write(payload.Length);
                writer.Write(payload);

                byte[] packet = ms.ToArray();
                _ipcClient.Write(packet, 0, packet.Length);
                _ipcClient.Flush();
            }
            catch
            {
                // Ignore IPC transmission errors
            }
        }
    }
}
