using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using PhoenixOmniTrace.L24_SourceSentinel.Models;

namespace PhoenixOmniTrace.L24_SourceSentinel.Core;

public sealed partial class ToolExecutionMultiInterceptor
{
    private async Task AdbAndUsbmuxLoopbackProbeLoop(CancellationToken token)
    {
        string lastAdbDevices = string.Empty;
        while (!token.IsCancellationRequested && _isRunning)
        {
            if (!IsEnabled)
            {
                await Task.Delay(1500, token).ConfigureAwait(false);
                continue;
            }

            try
            {
                using var client = new System.Net.Sockets.TcpClient();
                var connectTask = client.ConnectAsync(System.Net.IPAddress.Loopback, 5037);
                if (await Task.WhenAny(connectTask, Task.Delay(250, token)).ConfigureAwait(false) == connectTask && client.Connected)
                {
                    using var stream = client.GetStream();
                    byte[] req = Encoding.ASCII.GetBytes("000Chost:devices");
                    await stream.WriteAsync(req, 0, req.Length, token).ConfigureAwait(false);

                    byte[] respBuf = new byte[512];
                    int read = await stream.ReadAsync(respBuf, 0, respBuf.Length, token).ConfigureAwait(false);
                    if (read > 4)
                    {
                        string status = Encoding.ASCII.GetString(respBuf, 0, 4);
                        string payload = Encoding.UTF8.GetString(respBuf, 4, read - 4).Trim();
                        if (status == "OKAY" && !string.IsNullOrWhiteSpace(payload) && payload != lastAdbDevices)
                        {
                            lastAdbDevices = payload;
                            EmitInterceptedCommand(
                                0,
                                SentinelStage.PortAndDeviceRadar,
                                "AdbLoopback5037Watcher",
                                "ADB Server (127.0.0.1:5037)",
                                "TCP:5037",
                                "ADB Device Connected",
                                $"🤖 خادم ADB المحلي رصد جهازاً متصلاً: {payload.Replace('\n', ' ').Replace('\r', ' ')}",
                                $"adb devices -> {payload}");
                        }
                    }
                }
            }
            catch { }

            try { await Task.Delay(2000, token).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }
    }

    private async Task NamedPipeActivityScannerLoop(CancellationToken token)
    {
        var seenPipes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        while (!token.IsCancellationRequested && _isRunning)
        {
            if (!IsEnabled)
            {
                await Task.Delay(2000, token).ConfigureAwait(false);
                continue;
            }

            try
            {
                string[] pipes = Directory.GetFiles(@"\\.\pipe\");
                foreach (var pipe in pipes)
                {
                    string pName = Path.GetFileName(pipe);
                    if (seenPipes.Contains(pName)) continue;

                    string lower = pName.ToLowerInvariant();
                    if (lower.Contains("adb") || lower.Contains("unlock") || lower.Contains("chimera") ||
                        lower.Contains("mtk") || lower.Contains("brom") || lower.Contains("edl") ||
                        lower.Contains("qcom") || lower.Contains("odin") || lower.Contains("apple") ||
                        lower.Contains("conpty") || lower.Contains("msys") || lower.Contains("cygwin"))
                    {
                        seenPipes.Add(pName);
                        EmitInterceptedCommand(
                            0,
                            SentinelStage.PortAndDeviceRadar,
                            "NamedPipeRadar",
                            "Windows IPC Pipe",
                            pipe,
                            "IPC Pipe / PTY Channel Created",
                            $"🔗 إنشاء قناة اتصال داخلية / جلسة طرفية (Named Pipe / ConPTY): {pipe}",
                            pipe);
                    }
                }
            }
            catch { }

            try { await Task.Delay(1500, token).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }
}
