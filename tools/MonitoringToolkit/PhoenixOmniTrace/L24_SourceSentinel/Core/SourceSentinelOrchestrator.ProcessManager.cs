using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace PhoenixOmniTrace.L24_SourceSentinel.Core;

public sealed partial class SourceSentinelOrchestrator
{
    private async Task AutoDiscoverGsmToolsLoop(CancellationToken token)
    {
        while (!token.IsCancellationRequested && !_isDisposed && _isActive)
        {
            try
            {
                var procs = Process.GetProcesses();
                foreach (var p in procs)
                {
                    if (token.IsCancellationRequested || !_isActive) break;
                    try
                    {
                        string nameLower = p.ProcessName.ToLowerInvariant();
                        if (KnownGsmToolNames.Any(k => nameLower.Contains(k)) && !_autoAttachedPids.ContainsKey(p.Id))
                        {
                            _autoAttachedPids[p.Id] = p.ProcessName;
                            AttachToRunningProcess(p.Id);
                        }
                    }
                    catch { }
                    finally
                    {
                        p.Dispose();
                    }
                }
            }
            catch { }

            try
            {
                await Task.Delay(1500, token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { break; }
        }
    }

    public bool LaunchAndInterceptTool(string executablePath, string arguments = "", string? workingDir = null)
    {
        if (!File.Exists(executablePath))
        {
            OnLogMessage?.Invoke($"[خطأ] مسار الأداة غير موجود: {executablePath}");
            return false;
        }

        try
        {
            if (!_isActive) Start();

            string toolDir = !string.IsNullOrWhiteSpace(workingDir) ? workingDir : Path.GetDirectoryName(executablePath) ?? "";
            if (!string.IsNullOrWhiteSpace(toolDir))
            {
                L24FileArchiver.RegisterToolDirectory(toolDir);
                _radar.AddDirectoryWatcher(toolDir);
                _multiExecInterceptor.AddToolStagingWatcher(toolDir);
            }

            var startInfo = new ProcessStartInfo
            {
                FileName = executablePath,
                Arguments = arguments,
                WorkingDirectory = toolDir,
                UseShellExecute = true
            };

            ToolExecutionMultiInterceptor.PrepareToolLaunchEnvironment(startInfo, toolDir, _logDirectory);

            var proc = Process.Start(startInfo);
            if (proc != null)
            {
                _autoAttachedPids[proc.Id] = proc.ProcessName;
                _universalInterceptor.RegisterToolPid(proc.Id);
                _multiExecInterceptor.RegisterToolProcess(proc.Id, proc.ProcessName);
                OnLogMessage?.Invoke($"[L24 SourceSentinel] تم تشغيل الأداة بنجاح (PID: {proc.Id}) - جاري تفعيل المراقبة الشاملة من المصدر");

                _radar.CurrentMonitoredPid = proc.Id;
                _radar.CurrentMonitoredProcessName = proc.ProcessName;

                _heapHunter.StartHunting(proc.Id, proc.ProcessName);
                _portPoller.StartPolling(proc.Id, proc.ProcessName);
                _kernelInterceptor.StartMonitoring(proc.Id, proc.ProcessName);

                var token = _activeCts?.Token ?? CancellationToken.None;
                Task.Run(async () =>
                {
                    try
                    {
                        await Task.Delay(8000, token).ConfigureAwait(false);
                        if (!proc.HasExited && !token.IsCancellationRequested && !_isDisposed && _isActive)
                        {
                            _ramWatcher.ScanProcessModulesAndMemory(proc.Id, _logDirectory);
                        }
                    }
                    catch { }
                }, token);

                return true;
            }
        }
        catch (Exception ex)
        {
            OnLogMessage?.Invoke($"[استثناء أثناء تشغيل الأداة]: {ex.Message}");
        }

        return false;
    }

    public bool AttachToRunningProcess(int processId)
    {
        try
        {
            using var proc = Process.GetProcessById(processId);
            if (!_isActive) Start();

            _autoAttachedPids[processId] = proc.ProcessName;
            _universalInterceptor.RegisterToolPid(processId);
            _multiExecInterceptor.RegisterToolProcess(processId, proc.ProcessName);

            try
            {
                string? exePath = proc.MainModule?.FileName;
                string? toolDir = !string.IsNullOrWhiteSpace(exePath) ? Path.GetDirectoryName(exePath) : null;
                if (!string.IsNullOrWhiteSpace(toolDir))
                {
                    L24FileArchiver.RegisterToolDirectory(toolDir);
                    _radar.AddDirectoryWatcher(toolDir);
                    _multiExecInterceptor.AddToolStagingWatcher(toolDir);
                }
            }
            catch { }

            OnLogMessage?.Invoke($"[L24 SourceSentinel] تم الارتباط بالعملية {proc.ProcessName} (PID: {processId}) بنجاح");

            _radar.CurrentMonitoredPid = proc.Id;
            _radar.CurrentMonitoredProcessName = proc.ProcessName;

            _heapHunter.StartHunting(proc.Id, proc.ProcessName);
            _portPoller.StartPolling(proc.Id, proc.ProcessName);
            _kernelInterceptor.StartMonitoring(proc.Id, proc.ProcessName);

            var token = _activeCts?.Token ?? CancellationToken.None;
            Task.Run(async () =>
            {
                try
                {
                    await Task.Delay(6000, token).ConfigureAwait(false);
                    if (!proc.HasExited && !token.IsCancellationRequested && !_isDisposed && _isActive)
                    {
                        _ramWatcher.ScanProcessModulesAndMemory(processId, _logDirectory);
                    }
                }
                catch { }
            }, token);

            return true;
        }
        catch (Exception ex)
        {
            OnLogMessage?.Invoke($"[خطأ الارتباط بالعملية {processId}]: {ex.Message}");
            return false;
        }
    }
}
