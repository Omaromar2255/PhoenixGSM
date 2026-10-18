using System;
using System.IO;
using System.Text;
using PhoenixGSM.MonitoringStudio.Models;
using PhoenixGSM.OmniTrace.Models;
using PhoenixGSM.OmniTrace.Sensors;

namespace PhoenixGSM.MonitoringStudio.Services;

public partial class MonitoringEngine
{
    private void HandleNetworkUrlCaptured(CapturedUrlInfo urlInfo)
    {
        if (!IsUrlMonitoringEnabled) return;

        bool isDns = urlInfo.SourceTag.Equals("DNS-QUERY", StringComparison.OrdinalIgnoreCase);
        bool isClipboard = urlInfo.SourceTag.Equals("CLIPBOARD", StringComparison.OrdinalIgnoreCase);
        bool isConn = urlInfo.SourceTag.Equals("NET-CONN", StringComparison.OrdinalIgnoreCase);
        bool isRawHttp = urlInfo.SourceTag.Equals("RAW-HTTP", StringComparison.OrdinalIgnoreCase);
        bool isTlsSni = urlInfo.SourceTag.Equals("TLS-SNI", StringComparison.OrdinalIgnoreCase);

        string fileName = Path.GetFileName(urlInfo.PathAndQuery.Split('?')[0]);
        string cmd;
        string summary;
        string dir;

        if (isDns)
        {
            cmd = "DNS LOOKUP";
            summary = $"[{urlInfo.ProcessName}] DNS: {urlInfo.Host}";
            dir = "DNS";
        }
        else if (isClipboard)
        {
            cmd = string.IsNullOrWhiteSpace(fileName) ? "COPIED LINK" : $"LINK: {fileName}";
            summary = $"[{urlInfo.ProcessName}] {urlInfo.Url}";
            dir = "CLIP";
        }
        else if (isRawHttp)
        {
            cmd = $"{urlInfo.Method} (HTTP)";
            summary = $"[{urlInfo.ProcessName}] {urlInfo.Method} {urlInfo.Url}";
            dir = "HTTP >>";
        }
        else if (isTlsSni)
        {
            cmd = "HTTPS (TLS)";
            summary = $"[{urlInfo.ProcessName}] HTTPS Handshake -> {urlInfo.Host}";
            dir = "TLS >>";
        }
        else if (isConn)
        {
            cmd = $"{urlInfo.Method} {urlInfo.RemotePort}";
            summary = $"[{urlInfo.ProcessName}] Connect -> {urlInfo.Host}:{urlInfo.RemotePort} ({urlInfo.Scheme})";
            dir = "NET >>";
        }
        else
        {
            cmd = string.IsNullOrWhiteSpace(fileName) ? $"{urlInfo.Method} REQ" : $"DOWNLOAD: {fileName}";
            summary = $"[{urlInfo.ProcessName}] {urlInfo.Method} {urlInfo.Url}";
            dir = "WEB >>";
        }

        string target = !string.IsNullOrEmpty(urlInfo.RemoteEndpoint) ? urlInfo.RemoteEndpoint : urlInfo.Host;

        EmitEvent(new LiveEventItem
        {
            Timestamp = urlInfo.Timestamp,
            Category = EventSourceCategory.NetworkUrl,
            SourceTag = urlInfo.SourceTag,
            Direction = dir,
            EndpointOrTarget = target,
            Protocol = isDns ? "DNS" : urlInfo.Scheme,
            Command = cmd,
            Summary = summary,
            RawPayload = Encoding.UTF8.GetBytes(urlInfo.Url),
            PayloadAscii = $"Captured Network / Connection Event:\nURL: {urlInfo.Url}\nTarget Host: {urlInfo.Host}\nResource Path: {urlInfo.PathAndQuery}\nCaller Process: {urlInfo.ProcessName} (PID {urlInfo.ProcessId})\nMethod / Action: {urlInfo.Method}\nLayer Source: {urlInfo.SourceTag}\nRemote Endpoint: {target}\nTimestamp: {urlInfo.Timestamp:O}",
            PayloadHex = LiveEventItem.FormatHexDump(Encoding.UTF8.GetBytes(urlInfo.Url)),
            AdditionalDetails = $"Captured Network / Connection Event:\nCaller Process: {urlInfo.ProcessName} (PID {urlInfo.ProcessId})\nFull URL / Target: {urlInfo.Url}\nTarget Host: {urlInfo.Host}\nResource: {urlInfo.PathAndQuery}\nInterception Layer: ({urlInfo.SourceTag})\nRemote Endpoint: {target}"
        });
    }

    private void HandleTempFileAtCaptured(TempFileAtEvent fileAt)
    {
        if (!IsTempAtMonitoringEnabled) return;
        string cmdPreview = fileAt.AtCommands.Count > 0 
            ? fileAt.AtCommands[0] 
            : (fileAt.IsBinaryPayload ? $"[STAGED-PAYLOAD: {fileAt.FileName}]" : "AT SCRIPT");
        if (fileAt.AtCommands.Count > 1)
        {
            cmdPreview += $" (+{fileAt.AtCommands.Count - 1} more)";
        }

        string summary = fileAt.IsBinaryPayload
            ? $"[{fileAt.ProcessName}] Staged payload: {fileAt.FileName} ({fileAt.FileSize:N0}B) -> {fileAt.TargetHint}"
            : $"[{fileAt.ProcessName}] Staged {fileAt.AtCommands.Count} AT cmd(s) in {fileAt.FileName} -> {fileAt.TargetHint}";

        var sb = new StringBuilder();
        sb.AppendLine($"Staged File: {fileAt.FilePath}");
        sb.AppendLine($"Size: {fileAt.FileSize:N0} bytes");
        sb.AppendLine($"Creator Process: {fileAt.ProcessName} (PID: {fileAt.ProcessId})");
        sb.AppendLine($"Target Interface: {fileAt.TargetHint}");
        if (fileAt.AtCommands.Count > 0)
        {
            sb.AppendLine($"Extracted Commands / Signatures ({fileAt.AtCommands.Count}):");
            for (int i = 0; i < fileAt.AtCommands.Count; i++)
            {
                sb.AppendLine($"  [{i + 1}] {fileAt.AtCommands[i]}");
            }
        }
        if (!string.IsNullOrWhiteSpace(fileAt.RawContent) && !fileAt.IsBinaryPayload)
        {
            sb.AppendLine();
            sb.AppendLine("=== Full Staged File Content (Un-truncated) ===");
            sb.AppendLine(fileAt.RawContent);
        }
        else if (fileAt.IsBinaryPayload)
        {
            if (!string.IsNullOrWhiteSpace(fileAt.RawContent))
            {
                sb.AppendLine();
                sb.AppendLine("=== Staged Binary Metadata ===");
                sb.AppendLine(fileAt.RawContent);
            }

            if (fileAt.RawBytes != null && fileAt.RawBytes.Length > 0)
            {
                var carvedStrings = TempFileAtSensor.ExtractPrintableStrings(fileAt.RawBytes);
                if (carvedStrings.Count > 0)
                {
                    sb.AppendLine();
                    sb.AppendLine($"=== Extracted Printable Strings & Script Fragments ({carvedStrings.Count:N0} strings found) ===");
                    for (int i = 0; i < carvedStrings.Count; i++)
                    {
                        sb.AppendLine($"  [{i + 1}] {carvedStrings[i]}");
                    }
                }
            }
        }

        EmitEvent(new LiveEventItem
        {
            Timestamp = fileAt.Timestamp,
            Category = EventSourceCategory.TempFileAt,
            SourceTag = fileAt.SourceTag,
            Direction = "FILE >>",
            EndpointOrTarget = fileAt.FileName,
            Protocol = fileAt.IsBinaryPayload ? "STAGED-PAYLOAD" : "STAGED-AT",
            Command = cmdPreview,
            Summary = summary,
            RawPayload = fileAt.RawBytes,
            PayloadAscii = sb.ToString(),
            PayloadHex = fileAt.RawBytes != null ? LiveEventItem.FormatHexDump(fileAt.RawBytes) : string.Empty,
            AdditionalDetails = $"Captured Staged Temp File:\nCreator: {fileAt.ProcessName} (PID {fileAt.ProcessId})\nPath: {fileAt.FilePath}\nCommands Extracted: {fileAt.AtCommands.Count}\nInterception Layer: Filesystem / Temp Interceptor (Layer 3E)\nDestination: {fileAt.TargetHint}\nBinary Payload: {fileAt.IsBinaryPayload}"
        });
    }

    private void HandleInProcessCaptured(InProcessOperationEvent inProc)
    {
        var sb = new StringBuilder();
        sb.AppendLine("In-Process GSM Tool Servicing Operation:");
        sb.AppendLine($"Tool: {inProc.ToolName} (PID {inProc.ProcessId})");
        sb.AppendLine($"Operation: {inProc.OperationName}");
        sb.AppendLine($"Target Device: {inProc.TargetDevice}");
        sb.AppendLine($"Payload Size: {inProc.Payload.Length} bytes");
        if (inProc.Details != null && inProc.Details.Count > 0)
        {
            sb.AppendLine("Details:");
            foreach (var kvp in inProc.Details)
            {
                sb.AppendLine($"  {kvp.Key}: {kvp.Value}");
            }
        }

        EmitEvent(new LiveEventItem
        {
            Timestamp = inProc.Timestamp,
            Category = EventSourceCategory.InProcess,
            SourceTag = inProc.SourceTag,
            Direction = "INTERNAL",
            EndpointOrTarget = inProc.TargetDevice,
            Protocol = "IN-PROCESS",
            Command = inProc.OperationName,
            Summary = $"[{inProc.ToolName}] {inProc.OperationName} -> {inProc.TargetDevice}",
            RawPayload = inProc.Payload,
            PayloadAscii = sb.ToString(),
            PayloadHex = LiveEventItem.FormatHexDump(inProc.Payload),
            AdditionalDetails = sb.ToString()
        });
    }

    private void HandleToolSessionCaptured(GsmToolSessionEvent toolEvt)
    {
        var category = Enum.TryParse<EventSourceCategory>(toolEvt.Category, true, out var cat) ? cat : EventSourceCategory.MediaTek;
        byte[] payloadBytes = Encoding.UTF8.GetBytes(toolEvt.TechnicalDetails);

        EmitEvent(new LiveEventItem
        {
            Timestamp = toolEvt.Timestamp,
            Category = category,
            SourceTag = toolEvt.SourceTag,
            Direction = "HOST->DEV",
            EndpointOrTarget = toolEvt.TargetDevice,
            Protocol = toolEvt.Protocol.ToString().ToUpperInvariant(),
            Command = toolEvt.OperationName,
            Summary = toolEvt.FormattedSummary,
            RawPayload = payloadBytes,
            PayloadAscii = toolEvt.TechnicalDetails,
            PayloadHex = LiveEventItem.FormatHexDump(payloadBytes),
            AdditionalDetails = toolEvt.TechnicalDetails
        });
    }

    private void HandleArtifactCaptured(PushedArtifactInfo artifact)
    {
        if (!IsArtifactVaultEnabled) return;
        var sb = new StringBuilder();
        sb.AppendLine("Pushed Artifact Intercepted & Retained in Vault:");
        sb.AppendLine($"File Name: {artifact.FileName}");
        sb.AppendLine($"Classification: {artifact.FileClassification} ({artifact.MagicDescription})");
        sb.AppendLine($"Target Device Path: {artifact.TargetDevicePath}");
        if (!string.IsNullOrEmpty(artifact.LocalSourcePath))
        {
            sb.AppendLine($"Host Source Path: {artifact.LocalSourcePath}");
        }
        sb.AppendLine($"File Size: {artifact.FileSizeBytes:N0} bytes");
        sb.AppendLine($"SHA-256: {artifact.Sha256}");
        sb.AppendLine($"MD5: {artifact.Md5}");
        sb.AppendLine($"Vault Storage: {artifact.VaultFilePath}");
        sb.AppendLine($"Vault Manifest: {artifact.VaultManifestPath}");
        sb.AppendLine($"Is Exploit/Executable: {artifact.IsExecutableOrExploit}");
        sb.AppendLine($"Deduplicated: {artifact.IsDeduplicated}");
        sb.AppendLine($"Capture Vector: {artifact.SourceVector}");
        sb.AppendLine($"Attributed Tool: {artifact.ProcessName} (PID {artifact.ProcessId})");
        if (artifact.Attributes.Count > 0)
        {
            sb.AppendLine("Metadata Attributes:");
            foreach (var kvp in artifact.Attributes)
            {
                sb.AppendLine($"  {kvp.Key}: {kvp.Value}");
            }
        }

        byte[]? fileBytes = artifact.RawBytes;
        if (fileBytes == null || fileBytes.Length == 0)
        {
            try
            {
                if (File.Exists(artifact.VaultFilePath))
                {
                    fileBytes = File.ReadAllBytes(artifact.VaultFilePath);
                }
                else if (!string.IsNullOrEmpty(artifact.LocalSourcePath) && File.Exists(artifact.LocalSourcePath))
                {
                    fileBytes = File.ReadAllBytes(artifact.LocalSourcePath);
                }
            }
            catch { }
        }

        if (fileBytes != null && fileBytes.Length > 0)
        {
            bool isBinary = TempFileAtSensor.IsBinaryBuffer(fileBytes);
            if (!isBinary)
            {
                string text = TempFileAtSensor.DecodeText(fileBytes);
                sb.AppendLine();
                sb.AppendLine("=== Full Staged File Content (Un-truncated) ===");
                sb.AppendLine(text);
            }
            else
            {
                var carvedStrings = TempFileAtSensor.ExtractPrintableStrings(fileBytes);
                if (carvedStrings.Count > 0)
                {
                    sb.AppendLine();
                    sb.AppendLine($"=== Extracted Printable Strings & Script Fragments ({carvedStrings.Count:N0} strings found) ===");
                    for (int i = 0; i < carvedStrings.Count; i++)
                    {
                        sb.AppendLine($"  [{i + 1}] {carvedStrings[i]}");
                    }
                }
            }
        }

        string sizeStr = artifact.FileSizeBytes < 1024
            ? $"{artifact.FileSizeBytes} B"
            : (artifact.FileSizeBytes < 1048576
                ? $"{artifact.FileSizeBytes / 1024.0:F1} KB"
                : $"{artifact.FileSizeBytes / 1048576.0:F2} MB");

        string cmdPreview = $"VAULT-SAVE {artifact.FileName}";
        string summary = $"[ARTIFACT VAULT] {artifact.FileName} ({sizeStr}) -> {artifact.TargetDevicePath} [{artifact.MagicDescription}]";

        byte[] payloadBytes = fileBytes ?? Encoding.UTF8.GetBytes(sb.ToString());

        EmitEvent(new LiveEventItem
        {
            Timestamp = artifact.Timestamp,
            Category = EventSourceCategory.ArtifactVault,
            SourceTag = "ARTIFACT-VAULT",
            Direction = "PUSH >>",
            EndpointOrTarget = artifact.TargetDevicePath,
            Protocol = "VAULT-ADB",
            Command = cmdPreview,
            Summary = summary,
            RawPayload = payloadBytes,
            PayloadAscii = sb.ToString(),
            PayloadHex = LiveEventItem.FormatHexDump(payloadBytes),
            AdditionalDetails = sb.ToString()
        });
    }
}
