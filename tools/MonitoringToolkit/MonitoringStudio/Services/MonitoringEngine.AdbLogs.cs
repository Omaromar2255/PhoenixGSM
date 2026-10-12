using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using PhoenixGSM.MonitoringStudio.Models;

namespace PhoenixGSM.MonitoringStudio.Services;

public partial class MonitoringEngine
{
    public static string? FindActiveAdbPath()
    {
        string[] candidates =
        [
            @"C:\UnlockTool\Binaries\adb.exe",
            @"C:\SK.UNLOCKERnew\bin\adb\adb.exe",
            @"C:\Program Files (x86)\CDMA YEMEN TOOL\adb.exe"
        ];
        return candidates.FirstOrDefault(File.Exists);
    }

    #region ADB Transparent Proxy Log Watcher Loop
    private async Task AdbLogWatcherLoop(CancellationToken token)
    {
        string adbLogDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "PhoenixGSM", "Logs", "ADB");

        while (!token.IsCancellationRequested)
        {
            try
            {
                if (Directory.Exists(adbLogDir))
                {
                    var files = Directory.GetFiles(adbLogDir, "adb_log_*.jsonl").OrderByDescending(f => f).ToList();
                    if (files.Count > 0)
                    {
                        var latestFile = files[0];
                        if (_activeAdbLogFile != latestFile)
                        {
                            _activeAdbLogFile = latestFile;
                            _lastAdbLogFileOffset = 0;
                        }

                        var fileInfo = new FileInfo(latestFile);
                        if (fileInfo.Length > _lastAdbLogFileOffset)
                        {
                            using var fs = new FileStream(latestFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            fs.Seek(_lastAdbLogFileOffset, SeekOrigin.Begin);
                            using var reader = new StreamReader(fs, Encoding.UTF8);

                            string? line;
                            while ((line = await reader.ReadLineAsync(token)) != null)
                            {
                                if (string.IsNullOrWhiteSpace(line)) continue;
                                ParseAndEmitAdbLogLine(line);
                            }
                            _lastAdbLogFileOffset = fs.Position;
                        }
                    }
                }

                await Task.Delay(500, token);
            }
            catch (OperationCanceledException) { break; }
            catch { await Task.Delay(1000, token); }
        }
    }

    private void ParseAndEmitAdbLogLine(string jsonLine)
    {
        if (!IsAdbMonitoringEnabled) return;
        try
        {
            using var doc = JsonDocument.Parse(jsonLine);
            var root = doc.RootElement;

            string client = root.TryGetProperty("ClientProcess", out var cp) ? cp.GetString() ?? "adb.exe" : "adb.exe";
            string rawCommand = root.TryGetProperty("RawCommand", out var rc) ? rc.GetString() ?? "" : "";
            string response = root.TryGetProperty("Response", out var resp) ? resp.GetString() ?? "" : "";
            string deviceSerial = root.TryGetProperty("DeviceSerial", out var ds) ? ds.GetString() ?? "" : "";
            int exitCode = root.TryGetProperty("ExitCode", out var ec) ? ec.GetInt32() : 0;

            EmitEvent(new LiveEventItem
            {
                Category = EventSourceCategory.AdbProxy,
                SourceTag = "ADB-PROXY",
                Direction = "IN/OUT",
                EndpointOrTarget = client,
                Protocol = "ADB-CLI",
                Command = ExtractAdbSubcommand(rawCommand),
                Summary = $"[{client}] adb {rawCommand} -> {(exitCode == 0 ? "SUCCESS" : $"EXIT {exitCode}")}",
                PayloadAscii = response,
                PayloadHex = LiveEventItem.FormatHexDump(Encoding.UTF8.GetBytes(response)),
                AdditionalDetails = $"Client Process: {client}\nDevice Serial: {deviceSerial}\nFull Command: adb {rawCommand}\nExit Code: {exitCode}"
            });
        }
        catch { }
    }

    public static string ExtractAdbSubcommand(string fullCmd)
    {
        if (string.IsNullOrWhiteSpace(fullCmd)) return "ADB";

        // Clean out path to adb.exe if present
        int lastQuote = fullCmd.LastIndexOf('"');
        if (lastQuote >= 0 && lastQuote < fullCmd.Length - 1)
        {
            fullCmd = fullCmd.Substring(lastQuote + 1);
        }
        else if (fullCmd.StartsWith("adb", StringComparison.OrdinalIgnoreCase))
        {
            fullCmd = fullCmd.Substring(3);
        }

        var parts = fullCmd.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0) return "ADB";
        if (parts[0] == "-s" && parts.Length > 2) return parts[2];
        return parts[0];
    }
    #endregion
}
