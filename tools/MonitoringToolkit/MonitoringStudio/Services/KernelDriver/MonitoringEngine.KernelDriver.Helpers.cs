using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using PhoenixGSM.MonitoringStudio.Models;
using PhoenixGSM.OmniTrace.Sensors;

namespace PhoenixGSM.MonitoringStudio.Services;

public partial class MonitoringEngine
{
    public static string CleanInboundPhoneResponse(byte[] chunk)
    {
        if (chunk == null || chunk.Length == 0) return string.Empty;
        var sb = new StringBuilder(chunk.Length);
        int printable = 0;
        foreach (byte b in chunk)
        {
            if (b >= 32 && b <= 126)
            {
                sb.Append((char)b);
                printable++;
            }
            else if (b == '\r' || b == '\n' || b == '\t')
            {
                sb.Append((char)b);
                printable++;
            }
        }
        if (printable < Math.Max(2, chunk.Length / 2)) return string.Empty;
        return sb.ToString().Trim('\r', '\n', '\t', ' ', '\0', '.');
    }

    public static string DecodeEmbeddedRilOrAtHex(string hexText)
    {
        if (string.IsNullOrWhiteSpace(hexText)) return string.Empty;
        string clean = hexText.Trim();
        if (clean.Length < 10 || clean.Length > 256 || clean.Length % 2 != 0) return string.Empty;
        if (!clean.All(Uri.IsHexDigit)) return string.Empty;

        try
        {
            byte[] bytes = Convert.FromHexString(clean);
            var segments = new List<string>();
            var current = new StringBuilder();
            foreach (byte b in bytes)
            {
                if (b >= 32 && b <= 126)
                {
                    current.Append((char)b);
                }
                else
                {
                    if (current.Length >= 3)
                    {
                        segments.Add(current.ToString());
                    }
                    current.Clear();
                }
            }
            if (current.Length >= 3)
            {
                segments.Add(current.ToString());
            }

            if (segments.Count > 0)
            {
                return $"ASCII: {string.Join(" / ", segments)}";
            }
        }
        catch { }

        return string.Empty;
    }

    private void FlushGetpropSummary(string epHex, string dir)
    {
        if (!_isAggregatingGetprop) return;
        _isAggregatingGetprop = false;

        string summary = _getpropAggregator.BuildUnifiedSummary();
        if (_getpropAggregator.ExtractedCount > 0)
        {
            EmitEvent(new LiveEventItem
            {
                Timestamp = DateTime.UtcNow,
                Category = EventSourceCategory.AdbProxy,
                SourceTag = "ADB-GETPROP",
                Direction = dir,
                EndpointOrTarget = $"EP {epHex}",
                Protocol = "ADB-STREAM",
                Command = "GETPROP SUMMARY",
                Summary = summary,
                RawPayload = Encoding.UTF8.GetBytes(summary),
                PayloadAscii = summary,
                PayloadHex = LiveEventItem.FormatHexDump(Encoding.UTF8.GetBytes(summary)),
                AdditionalDetails = string.Join("\n", _getpropAggregator.GetAllProperties().Select(kv => $"{kv.Key} = {kv.Value}"))
            });
        }
        _getpropAggregator.Reset();
    }

    private static readonly string KernelDiagFile = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PhoenixGSM", "Logs", "kernel_packets.log");

    private static void KernelDiagLog(string line)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(KernelDiagFile)!);
            File.AppendAllText(KernelDiagFile, $"{DateTime.Now:HH:mm:ss.fff} {line}\n");
        }
        catch { }
    }

    private string ResolveModemPortName(byte[] chunk, string cleanText)
    {
        if (_omniService?.SerialSensor == null) return "MODEM_PORT";
        var sensor = _omniService.SerialSensor;
        var allPorts = sensor.AllDiscoveredPortNames ?? (IReadOnlyCollection<string>)Array.Empty<string>();

        bool isHuawei = cleanText.Contains("^", StringComparison.OrdinalIgnoreCase) ||
                        cleanText.Contains("Honor", StringComparison.OrdinalIgnoreCase) ||
                        cleanText.Contains("Huawei", StringComparison.OrdinalIgnoreCase) ||
                        cleanText.StartsWith("ANY-", StringComparison.OrdinalIgnoreCase) ||
                        cleanText.StartsWith("WKG-", StringComparison.OrdinalIgnoreCase) ||
                        cleanText.StartsWith("H60-", StringComparison.OrdinalIgnoreCase) ||
                        cleanText.StartsWith("LLD-", StringComparison.OrdinalIgnoreCase) ||
                        cleanText.StartsWith("STK-", StringComparison.OrdinalIgnoreCase) ||
                        cleanText.StartsWith("POT-", StringComparison.OrdinalIgnoreCase) ||
                        cleanText.StartsWith("PRA-", StringComparison.OrdinalIgnoreCase) ||
                        cleanText.StartsWith("FIG-", StringComparison.OrdinalIgnoreCase) ||
                        cleanText.StartsWith("JSN-", StringComparison.OrdinalIgnoreCase) ||
                        cleanText.StartsWith("VOG-", StringComparison.OrdinalIgnoreCase) ||
                        cleanText.StartsWith("ELE-", StringComparison.OrdinalIgnoreCase) ||
                        cleanText.StartsWith("YAL-", StringComparison.OrdinalIgnoreCase) ||
                        cleanText.StartsWith("NOH-", StringComparison.OrdinalIgnoreCase) ||
                        cleanText.StartsWith("NEN-", StringComparison.OrdinalIgnoreCase);

        if (isHuawei)
        {
            var hwPort = allPorts.FirstOrDefault(p =>
            {
                var desc = sensor.GetPortDescription(p) ?? "";
                var hwId = sensor.GetPortHardwareId(p) ?? "";
                return desc.Contains("Huawei", StringComparison.OrdinalIgnoreCase) ||
                       desc.Contains("Honor", StringComparison.OrdinalIgnoreCase) ||
                       desc.Contains("Adapter Modem", StringComparison.OrdinalIgnoreCase) ||
                       desc.Contains("PC UI", StringComparison.OrdinalIgnoreCase) ||
                       hwId.Contains("12D1", StringComparison.OrdinalIgnoreCase);
            });
            if (hwPort != null) return hwPort;
            return allPorts.Count == 0 ? "COM12 (Honor/Huawei)" : "MODEM_HUAWEI";
        }

        bool isSamsung = cleanText.Contains("Samsung", StringComparison.OrdinalIgnoreCase) ||
                         cleanText.StartsWith("SM-", StringComparison.OrdinalIgnoreCase) ||
                         cleanText.StartsWith("SEC-", StringComparison.OrdinalIgnoreCase) ||
                         cleanText.Contains("PACM(AP)", StringComparison.OrdinalIgnoreCase);

        if (isSamsung)
        {
            var samPort = allPorts.FirstOrDefault(p =>
            {
                var desc = sensor.GetPortDescription(p) ?? "";
                var hwId = sensor.GetPortHardwareId(p) ?? "";
                return desc.Contains("Samsung", StringComparison.OrdinalIgnoreCase) ||
                       hwId.Contains("04E8", StringComparison.OrdinalIgnoreCase);
            });
            if (samPort != null) return samPort;
            return allPorts.Count == 0 ? "COM5 (Samsung)" : "MODEM_SAMSUNG";
        }

        var defaultModem = allPorts.FirstOrDefault(p =>
        {
            var desc = sensor.GetPortDescription(p) ?? "";
            return desc.Contains("Modem", StringComparison.OrdinalIgnoreCase) ||
                   desc.Contains("PC UI", StringComparison.OrdinalIgnoreCase) ||
                   desc.Contains("Serial", StringComparison.OrdinalIgnoreCase);
        });

        return defaultModem ?? allPorts.FirstOrDefault() ?? "MODEM_PORT";
    }

    private void EmitCapturedPushedFile(CapturedPushedFileRecord rec, string epHex)
    {
        if (rec == null) return;

        string fname = rec.FileName;
        string targetPath = rec.TargetDevicePath;
        long size = rec.FileSizeBytes;
        string vector = rec.CaptureVector;
        string classification = rec.FileClassification;

        string summary = $"[ADB-PUSH] Completed: {targetPath} ({size:N0} bytes) | Classification: {classification} | Vector: {vector} | Saved: CapturedArtifacts/{fname}";

        EmitEvent(new LiveEventItem
        {
            Timestamp = rec.Timestamp,
            Category = EventSourceCategory.UsbDriver,
            SourceTag = "ADB-SYNC",
            Direction = "OUT",
            EndpointOrTarget = $"EP {epHex}",
            Protocol = "ADB-SYNC",
            Command = $"PUSH {targetPath}",
            Summary = summary,
            RawPayload = rec.FileBytes.Take(128).ToArray(),
            PayloadAscii = summary,
            PayloadHex = LiveEventItem.FormatHexDump(rec.FileBytes.Take(64).ToArray()),
            AdditionalDetails = $"Target Path: {targetPath}\nMode: {rec.FilePermissionMode}\nTotal Bytes: {size:N0}\nClassification: {classification}\nVector: {vector}\nSHA256: {rec.Sha256}\nMD5: {rec.Md5}\nSaved: {rec.LocalSavedPath}"
        });

        if (_omniService?.ArtifactSensor?.Vault != null)
        {
            try
            {
                _omniService.ArtifactSensor.Vault.StoreArtifact(
                    content: rec.FileBytes,
                    fileName: fname,
                    targetDevicePath: targetPath,
                    processName: !string.IsNullOrEmpty(rec.ProcessName) ? rec.ProcessName : "adb.exe",
                    pid: rec.ProcessId,
                    sourceVector: vector,
                    localSourcePath: rec.LocalSavedPath,
                    deviceSerial: "",
                    extraAttrs: new Dictionary<string, string>
                    {
                        ["Classification"] = classification,
                        ["Sha256"] = rec.Sha256,
                        ["Md5"] = rec.Md5,
                        ["Mode"] = rec.FilePermissionMode
                    });
            }
            catch { }
        }
    }
}
