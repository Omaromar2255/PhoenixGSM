using System;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using PhoenixGSM.OmniTrace.Sensors;
using PhoenixOmniTrace.L24_SourceSentinel.Models;

namespace PhoenixOmniTrace.L24_SourceSentinel.Core;

public sealed partial class ToolExecutionMultiInterceptor
{
    private static readonly string[] TargetCliBinaries =
    [
        "fh_loader", "qsahara_server", "edl", "spd_dump",
        "irecovery", "ideviceinfo", "ideviceactivation", "idevice_id", "idevicepair",
        "idevicerestore", "idevicebackup2", "ideviceinstaller", "iproxy", "gaster",
        "devcon", "pnputil", "filter-x64", "filter-x86"
    ];

    private static readonly Regex AdbSocketCommandRegex = new(
        @"^[0-9A-Fa-f]{4}(?:host|shell|exec|abb|abb_exec|sync|usb|reboot|remount|root|unroot|tcpip|forward|reverse|localabstract|localfilesystem|dev|jdwp|track-devices|version|kill)[^\x00]{0,400}",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private async Task FastPebProcessTreeLoop(CancellationToken token)
    {
        while (!token.IsCancellationRequested && _isRunning)
        {
            if (!IsEnabled)
            {
                await Task.Delay(500, token).ConfigureAwait(false);
                continue;
            }

            try
            {
                var procs = Process.GetProcesses();
                foreach (var p in procs)
                {
                    if (token.IsCancellationRequested) break;
                    try
                    {
                        int pid = p.Id;
                        if (_seenChildProcessCmds.ContainsKey(pid)) continue;

                        string pName = p.ProcessName;
                        string pNameLower = pName.ToLowerInvariant();

                        bool isTargetCli = TargetCliBinaries.Any(b => pNameLower.Equals(b, StringComparison.OrdinalIgnoreCase) || pNameLower.StartsWith(b + ".", StringComparison.OrdinalIgnoreCase));
                        if (!isTargetCli && _trackedToolPids.IsEmpty)
                        {
                            _seenChildProcessCmds[pid] = pName;
                            continue;
                        }

                        string? cmdLine = SmartFilePushArchiver.TryGetProcessCommandLineFast(pid, out int parentPid);

                        bool isChildOfTrackedTool = parentPid > 0 && _trackedToolPids.ContainsKey(parentPid);

                        if (!isChildOfTrackedTool && !isTargetCli)
                        {
                            _seenChildProcessCmds[pid] = pName;
                            continue;
                        }

                        // استبعاد أوامر ADB و Conhost وعمليات النظام غير المرتبطة بالهاتف
                        if (pNameLower is "adb" or "conhost" or "openconsole" or "svchost" or "dllhost" or "opencode" or "opencode-cli" or "git" or "powershell" or "pwsh" or "l24liveharness")
                        {
                            _seenChildProcessCmds[pid] = pName;
                            continue;
                        }

                        if (string.IsNullOrWhiteSpace(cmdLine))
                        {
                            try { cmdLine = p.MainModule?.FileName ?? pName; } catch { cmdLine = pName; }
                        }

                        _seenChildProcessCmds[pid] = cmdLine;

                        if (isChildOfTrackedTool)
                        {
                            _trackedToolPids[pid] = pName;
                        }

                        if (pNameLower is "adb" or "fastboot" or "cmd" or "powershell" or "pwsh" or "python" or "fh_loader" or "qsahara_server" or "spd_dump" or "irecovery")
                        {
                            OnChildProcessRegistered?.Invoke(pid, pName + ".exe");
                        }

                        string trimmedCmd = cmdLine.Trim().Trim('"');
                        if (pNameLower == "conhost" || trimmedCmd.Equals(pName, StringComparison.OrdinalIgnoreCase) || trimmedCmd.EndsWith($"\\{pName}.exe", StringComparison.OrdinalIgnoreCase))
                            continue;

                        string decodedExtra = TryDecodePowerShellOrBase64(cmdLine);
                        string effectiveCmd = !string.IsNullOrWhiteSpace(decodedExtra) ? $"{cmdLine} | [Decoded]: {decodedExtra}" : cmdLine;

                        string savedFile = TryExtractAndArchiveFileFromCommandLine(cmdLine, pName);

                        string parentName = _trackedToolPids.TryGetValue(parentPid, out var pn) ? pn : $"PID_{parentPid}";
                        string category = ClassifyInterceptedCommand(pNameLower, effectiveCmd);

                        EmitInterceptedCommand(
                            pid,
                            SentinelStage.RawCommandExecution,
                            "PEB_FastCommandLineSniffer",
                            $"{parentName} -> {pName}.exe",
                            pName + ".exe",
                            category,
                            $"⚡ أمر منفذ من الأداة عبر [{pName}.exe]: {effectiveCmd}",
                            effectiveCmd,
                            savedFile);
                    }
                    catch { }
                    finally
                    {
                        p.Dispose();
                    }
                }
            }
            catch { }

            try { await Task.Delay(1200, token).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }
    }

    private async Task InteractiveConsoleAndPtyLoop(CancellationToken token)
    {
        while (!token.IsCancellationRequested && _isRunning)
        {
            if (!IsEnabled)
            {
                await Task.Delay(800, token).ConfigureAwait(false);
                continue;
            }

            try
            {
                foreach (var kvp in _trackedToolPids.ToArray())
                {
                    if (token.IsCancellationRequested) break;
                    string procLower = kvp.Value.ToLowerInvariant();
                    if (procLower.Contains("cmd") || procLower.Contains("powershell") || procLower.Contains("adb") || procLower.Contains("python") || procLower.Contains("irecovery"))
                    {
                        ScanProcessSmallActiveIoBuffers(kvp.Key, kvp.Value);
                    }
                }
            }
            catch { }

            try { await Task.Delay(180, token).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }
    }

    private void ScanProcessSmallActiveIoBuffers(int pid, string procName)
    {
        IntPtr hProc = IntPtr.Zero;
        try
        {
            hProc = OpenProcess(0x0400 | 0x0010, false, pid);
            if (hProc == IntPtr.Zero) return;

            long addr = 0x10000;
            long maxAddr = Environment.Is64BitOperatingSystem ? 0x7FFFFFFEFFFFL : 0x7FFF0000L;
            uint mbiSize = (uint)System.Runtime.InteropServices.Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();
            byte[] buf = new byte[16384];
            int regionsScanned = 0;

            while (addr < maxAddr && regionsScanned < 180)
            {
                if (VirtualQueryEx(hProc, (IntPtr)addr, out var mbi, mbiSize) == 0) break;

                long regSize = mbi.RegionSize.ToInt64();
                if (mbi.State == 0x1000 && mbi.Type == 0x20000 && mbi.Protect == 0x04 && regSize is >= 4096 and <= 65536)
                {
                    regionsScanned++;
                    int toRead = (int)Math.Min(regSize, buf.Length);
                    if (ReadProcessMemory(hProc, mbi.BaseAddress, buf, toRead, out int read) && read > 8)
                    {
                        InspectInteractiveBufferForCommands(pid, procName, buf, read);
                    }
                }

                long next = mbi.BaseAddress.ToInt64() + Math.Max(regSize, 4096);
                if (next <= addr) break;
                addr = next;
            }
        }
        catch { }
        finally
        {
            if (hProc != IntPtr.Zero) CloseHandle(hProc);
        }
    }

    private void InspectInteractiveBufferForCommands(int pid, string procName, byte[] buf, int len)
    {
        string utf8 = Encoding.UTF8.GetString(buf, 0, len);
        foreach (Match m in AdbSocketCommandRegex.Matches(utf8))
        {
            string raw = m.Value.Trim();
            if (raw.Length > 6)
            {
                string cleanCmd = raw[4..].Trim();
                if (ForensicNoiseGate.IsCleanAscii(cleanCmd))
                {
                    EmitInterceptedCommand(
                        pid,
                        SentinelStage.RawCommandExecution,
                        "ADB_SmartSocket_PtyInterceptor",
                        $"{procName} (PID:{pid})",
                        "ADB SmartSocket / PTY Session",
                        "ADB / Interactive PTY Command",
                        $"⚡ أمر جلسة تفاعلية (ADB Socket/PTY) صادر من [{procName}]: {cleanCmd}",
                        cleanCmd);
                }
            }
        }
    }

    private static string ClassifyInterceptedCommand(string procNameLower, string cmdLine)
    {
        string lower = $"{procNameLower} {cmdLine}".ToLowerInvariant();
        if (lower.Contains("fastboot")) return "Fastboot Command";
        if (lower.Contains("adb")) return "ADB / Interactive Shell";
        if (lower.Contains("fh_loader") || lower.Contains("qsahara") || lower.Contains("9008") || lower.Contains("firehose"))
            return "Qualcomm EDL / Sahara Execution";
        if (lower.Contains("mtk") || lower.Contains("brom") || lower.Contains("0e8d") || lower.Contains("da_"))
            return "MediaTek BROM / Service Execution";
        if (lower.Contains("irecovery") || lower.Contains("idevice") || lower.Contains("iproxy") || lower.Contains("gaster") || lower.Contains("ramdisk"))
            return "Apple iOS CLI Execution";
        if (lower.Contains("spd_dump") || lower.Contains("fdl"))
            return "Unisoc / SPD BSL Frame";
        if (lower.Contains("7z") || lower.Contains("tar") || lower.Contains("unzip") || lower.Contains("lz4") || lower.Contains("simg2img"))
            return "Archive / Unpack Execution";
        if (lower.Contains("openssl") || lower.Contains("decrypt"))
            return "Crypto / Decryption Execution";
        return "Tool Command Execution";
    }

    private static string TryDecodePowerShellOrBase64(string cmdLine)
    {
        try
        {
            var m = Regex.Match(cmdLine, @"-(?:enc|EncodedCommand)\s+([A-Za-z0-9+/=]{8,})", RegexOptions.IgnoreCase);
            if (m.Success)
            {
                byte[] bytes = Convert.FromBase64String(m.Groups[1].Value);
                return Encoding.Unicode.GetString(bytes).Trim();
            }

            var b64 = Regex.Match(cmdLine, @"echo\s+([A-Za-z0-9+/=]{16,})\s*\|\s*base64\s+-d", RegexOptions.IgnoreCase);
            if (b64.Success)
            {
                byte[] bytes = Convert.FromBase64String(b64.Groups[1].Value);
                return Encoding.UTF8.GetString(bytes).Trim();
            }
        }
        catch { }
        return string.Empty;
    }

    private static string TryExtractAndArchiveFileFromCommandLine(string cmdLine, string procName)
    {
        try
        {
            var pathMatches = Regex.Matches(cmdLine, @"([a-zA-Z]:\\[a-zA-Z0-9_\-\.\/\\ ]+\.(?:bin|da|auth|mbn|elf|img|img4|im4p|pit|ops|ofp|pac|qcn|xqcn|zip|7z|tar|xml|apk|sh))", RegexOptions.IgnoreCase);
            foreach (Match m in pathMatches)
            {
                string candidate = m.Groups[1].Value.Trim().Trim('"');
                if (L24FileArchiver.TryArchiveDiscoveredFile(candidate, $"CommandLineSniffer ({procName})", out string saved, out _, out _))
                {
                    return saved;
                }
            }
        }
        catch { }
        return string.Empty;
    }
}
