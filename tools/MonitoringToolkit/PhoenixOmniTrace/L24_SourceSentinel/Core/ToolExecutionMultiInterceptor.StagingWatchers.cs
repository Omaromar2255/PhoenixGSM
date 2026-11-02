using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using PhoenixOmniTrace.L24_SourceSentinel.Models;

namespace PhoenixOmniTrace.L24_SourceSentinel.Core;

public sealed partial class ToolExecutionMultiInterceptor
{
    private void InitializePreExecutionStagingWatchers()
    {
        var dirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            Path.GetTempPath(),
            @"C:\Temp",
            @"C:\UnlockTool\Temp",
            @"C:\Windows\Temp"
        };

        foreach (var d in dirs)
        {
            TryAddStagingWatcher(d);
        }
    }

    public void AddToolStagingWatcher(string toolDir)
    {
        if (string.IsNullOrWhiteSpace(toolDir) || !Directory.Exists(toolDir)) return;
        TryAddStagingWatcher(toolDir);
    }

    private void TryAddStagingWatcher(string dir)
    {
        if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir)) return;
        try
        {
            var watcher = new FileSystemWatcher(dir)
            {
                IncludeSubdirectories = true,
                InternalBufferSize = 65536,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime
            };

            watcher.Created += OnStagedFileActivity;
            watcher.Changed += OnStagedFileActivity;
            watcher.Renamed += (s, e) => OnStagedFileActivity(s, e);
            watcher.EnableRaisingEvents = true;

            lock (_stagingWatchers)
            {
                _stagingWatchers.Add(watcher);
            }
        }
        catch { }
    }

    private void OnStagedFileActivity(object sender, FileSystemEventArgs e)
    {
        if (!IsEnabled || !_isRunning || string.IsNullOrWhiteSpace(e.FullPath)) return;
        if (e.FullPath.Contains("L24_SourceSentinel", StringComparison.OrdinalIgnoreCase) ||
            e.FullPath.Contains("CapturedFiles", StringComparison.OrdinalIgnoreCase) ||
            e.FullPath.Contains("CapturedArtifacts", StringComparison.OrdinalIgnoreCase))
            return;

        try
        {
            string ext = Path.GetExtension(e.FullPath).ToLowerInvariant();
            string name = Path.GetFileName(e.FullPath).ToLowerInvariant();
            if (name.StartsWith("__pss", StringComparison.OrdinalIgnoreCase))
                return;

            if (ext is ".bat" or ".cmd" or ".ps1" or ".sh" or ".at" or ".seq" ||
                (ext == ".xml" && (name.Contains("rawprogram") || name.Contains("patch") || name.Contains("firehose"))))
            {
                string? content = TryReadTextShared(e.FullPath);
                if (!string.IsNullOrWhiteSpace(content))
                {
                    L24FileArchiver.TryArchiveDiscoveredFile(e.FullPath, "PreExec_ScriptHunter", out string savedScript, out _, out _);
                    string cleanPreview = content.Trim().Replace("\r\n", " ; ").Replace("\n", " ; ");
                    if (cleanPreview.Length > 320) cleanPreview = cleanPreview[..320] + "...";

                    EmitInterceptedCommand(
                        0,
                        SentinelStage.RawCommandExecution,
                        "PreExec_ScriptInterceptor",
                        "Tool Script Generator",
                        e.FullPath,
                        "Staged Script / Batch Execution",
                        $"📜 سكربت أوامر مرحلي ولدته الأداة للتنفيذ [{Path.GetFileName(e.FullPath)}]: {cleanPreview}",
                        cleanPreview,
                        savedScript);
                }
                return;
            }

            if (ext is ".bin" or ".da" or ".mbn" or ".elf" or ".img4" or ".im4p" or ".shsh2" or ".pit" or ".auth" or ".qcn" or ".xqcn" or ".pac" or ".ofp" or ".ops" ||
                name.Contains("preloader") || name.Contains("firehose") || name.Contains("loader") || name.Contains("ramdisk") || name.Contains("ibss") || name.Contains("ibec"))
            {
                if (L24FileArchiver.TryArchiveDiscoveredFile(e.FullPath, "PreExec_LoaderHunter", out string savedLoader, out long savedLen, out _))
                {
                    EmitInterceptedCommand(
                        0,
                        SentinelStage.LocalFilePreparation,
                        "PreExec_LoaderArchiver",
                        "Tool Loader Staging",
                        savedLoader,
                        "Boot Loader / Firmware File Access",
                        $"💾 تم اصطياد وحفظ ملف البوت/اللودر المستخدم فور تجهيزه: [{Path.GetFileName(e.FullPath)}] ({savedLen:N0} بايت) -> {savedLoader}",
                        e.FullPath,
                        savedLoader,
                        (int)Math.Min(savedLen, int.MaxValue));
                }
            }
        }
        catch { }
    }

    private static string? TryReadTextShared(string path)
    {
        for (int i = 0; i < 3; i++)
        {
            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                if (fs.Length <= 0 || fs.Length > 2 * 1024 * 1024) return null;
                using var sr = new StreamReader(fs, Encoding.UTF8);
                return sr.ReadToEnd();
            }
            catch { Thread.Sleep(15); }
        }
        return null;
    }
}
