using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace PhoenixGSM.OmniTrace.Decoders;

/// <summary>
/// Parser and decoder for host terminal, PowerShell, and CLI command executions.
/// Handles Base64 obfuscated PowerShell scripts (-EncodedCommand), command arguments,
/// and extracts HTTP/HTTPS download URLs from command lines.
/// </summary>
public static class ShellCommandParser
{
    private static readonly Regex UrlRegex = new(
        @"https?://[a-zA-Z0-9\-\._~:/\?#\[\]@!\$&'\(\)\*\+,;=%]+",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>
    /// Extracts all HTTP and HTTPS URLs present in a command line or text chunk.
    /// Preserves query parameters and #fragments without truncation.
    /// </summary>
    public static List<string> ExtractUrls(string text)
    {
        var result = new List<string>();
        if (string.IsNullOrWhiteSpace(text)) return result;

        var matches = UrlRegex.Matches(text);
        foreach (Match m in matches)
        {
            string url = m.Value.Trim(' ', '\t', '\r', '\n', '"', '\'', '<', '>', ';', ',', '`', '(', ')', '[', ']');
            while (url.EndsWith('.') || url.EndsWith(',')) url = url[..^1];

            if (Uri.TryCreate(url, UriKind.Absolute, out var uri) &&
                (uri.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase) || uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase)))
            {
                result.Add(url);
            }
        }

        return result;
    }

    /// <summary>
    /// Decodes a UTF-16LE Base64 string commonly used in PowerShell -EncodedCommand / -enc invocations.
    /// </summary>
    public static bool TryDecodeBase64Unicode(string base64, out string decoded)
    {
        decoded = string.Empty;
        if (string.IsNullOrWhiteSpace(base64)) return false;

        try
        {
            byte[] bytes = Convert.FromBase64String(base64.Trim('"', '\''));
            decoded = Encoding.Unicode.GetString(bytes).Trim();
            return !string.IsNullOrWhiteSpace(decoded);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Checks whether an executable name corresponds to a shell, terminal, or system management utility.
    /// </summary>
    public static bool IsHostOrShellUtility(string exeName)
    {
        if (string.IsNullOrWhiteSpace(exeName)) return false;
        string lower = Path.GetFileName(exeName).ToLowerInvariant();
        return lower == "cmd.exe" ||
               lower == "powershell.exe" ||
               lower == "pwsh.exe" ||
               lower == "conhost.exe" ||
               lower == "wt.exe" ||
               lower == "windowsterminal.exe" ||
               lower == "bash.exe" ||
               lower == "wscript.exe" ||
               lower == "cscript.exe" ||
               lower == "sc.exe" ||
               lower == "net.exe" ||
               lower == "net1.exe" ||
               lower == "reg.exe" ||
               lower == "pnputil.exe" ||
               lower == "devcon.exe" ||
               lower == "wmic.exe" ||
               lower == "taskkill.exe" ||
               lower == "tasklist.exe" ||
               lower == "certutil.exe" ||
               lower == "bitsadmin.exe" ||
               lower == "curl.exe" ||
               lower == "tar.exe" ||
               lower == "7z.exe" ||
               lower.EndsWith(".bat") ||
               lower.EndsWith(".cmd") ||
               lower.EndsWith(".ps1");
    }

    /// <summary>
    /// Model representing structured host / shell command execution details.
    /// </summary>
    public sealed class ParsedHostExecution
    {
        public string Executable { get; set; } = string.Empty;
        public string Arguments { get; set; } = string.Empty;
        public string Subcommand { get; set; } = string.Empty;
        public string NormalizedCommand { get; set; } = string.Empty;
        public string? DecodedScript { get; set; }
        public bool IsShellWrapper { get; set; }
        public bool IsPowerShell { get; set; }
        public bool IsBatchFile { get; set; }
    }

    /// <summary>
    /// Parses any shell or CLI command line into structured execution metadata.
    /// Handles cmd.exe /c, powershell, pwsh, sc.exe, net.exe, batch files (.bat/.cmd).
    /// </summary>
    public static ParsedHostExecution ParseShellExecution(string exeName, string cmdLine)
    {
        var result = new ParsedHostExecution();
        if (string.IsNullOrWhiteSpace(cmdLine))
        {
            result.Executable = Path.GetFileName(exeName);
            result.Subcommand = "CMD";
            result.NormalizedCommand = result.Executable;
            return result;
        }

        string trimmed = cmdLine.Trim();
        string cleanExe = Path.GetFileName(exeName).ToLowerInvariant();
        if (string.IsNullOrEmpty(cleanExe))
        {
            var firstToken = trimmed.Split(' ', StringSplitOptions.RemoveEmptyEntries)[0];
            cleanExe = Path.GetFileName(firstToken).Trim('"', '\'').ToLowerInvariant();
        }
        result.Executable = cleanExe;

        bool isPs = cleanExe.Contains("powershell") || cleanExe.Contains("pwsh");
        bool isCmd = cleanExe == "cmd.exe" || cleanExe == "cmd";
        bool isBat = cleanExe.EndsWith(".bat") || cleanExe.EndsWith(".cmd");

        result.IsPowerShell = isPs;
        result.IsBatchFile = isBat;

        if (isPs)
        {
            result.IsShellWrapper = true;
            // Base64 EncodedCommand
            int encIdx = trimmed.IndexOf("-enc", StringComparison.OrdinalIgnoreCase);
            if (encIdx < 0) encIdx = trimmed.IndexOf("-encodedcommand", StringComparison.OrdinalIgnoreCase);
            if (encIdx >= 0)
            {
                var parts = trimmed[encIdx..].Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length > 1 && TryDecodeBase64Unicode(parts[1], out var decoded))
                {
                    result.DecodedScript = decoded;
                    var decTokens = decoded.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    string first = decTokens.Length > 0 ? decTokens[0] : "PS";
                    string second = decTokens.Length > 1 ? decTokens[1] : "";
                    result.Subcommand = $"PS [ENC]: {first} {second}".Trim().ToUpperInvariant();
                    result.NormalizedCommand = $"powershell.exe -enc ({decoded})";
                    return result;
                }
            }

            // -Command or -c
            int flagLen = 0;
            int cIdx = trimmed.IndexOf("-command ", StringComparison.OrdinalIgnoreCase);
            if (cIdx >= 0)
            {
                flagLen = 9;
            }
            else
            {
                cIdx = trimmed.IndexOf("-c ", StringComparison.OrdinalIgnoreCase);
                if (cIdx >= 0) flagLen = 3;
            }

            if (cIdx >= 0)
            {
                string afterC = trimmed[(cIdx + flagLen)..].Trim(' ', '"', '\'');
                var parts = afterC.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length > 0)
                {
                    string first = parts[0].Trim('"', '\'');
                    string second = parts.Length > 1 ? parts[1].Trim('"', '\'') : "";
                    result.Subcommand = $"PS: {first} {second}".Trim().ToUpperInvariant();
                    result.NormalizedCommand = $"powershell.exe -Command {afterC}";
                    return result;
                }
            }

            result.Subcommand = "POWERSHELL";
            result.NormalizedCommand = trimmed;
            return result;
        }

        if (isCmd)
        {
            int cmdC = trimmed.IndexOf("/c ", StringComparison.OrdinalIgnoreCase);
            if (cmdC < 0) cmdC = trimmed.IndexOf("/k ", StringComparison.OrdinalIgnoreCase);

            if (cmdC >= 0 && cmdC + 3 < trimmed.Length)
            {
                result.IsShellWrapper = true;
                string afterC = trimmed[(cmdC + 3)..].Trim(' ', '"', '\'');
                var parts = afterC.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length > 0)
                {
                    string first = Path.GetFileNameWithoutExtension(parts[0].Trim('"', '\''));
                    string second = parts.Length > 1 ? parts[1].Trim('"', '\'') : "";
                    result.Subcommand = $"{first} {second}".Trim().ToUpperInvariant();
                    result.NormalizedCommand = afterC;
                    return result;
                }
            }

            result.Subcommand = "CMD";
            result.NormalizedCommand = trimmed;
            return result;
        }

        // Direct utilities or batch files (net.exe, sc.exe, reg.exe, script.bat)
        var tokens = trimmed.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (tokens.Length > 0)
        {
            string first = Path.GetFileName(tokens[0].Trim('"', '\''));
            string arg1 = tokens.Length > 1 ? tokens[1].Trim('"', '\'') : "";
            string arg2 = tokens.Length > 2 ? tokens[2].Trim('"', '\'') : "";
            result.Subcommand = $"{Path.GetFileNameWithoutExtension(first)} {arg1}".Trim().ToUpperInvariant();
            result.NormalizedCommand = trimmed;
            return result;
        }

        result.Subcommand = cleanExe.ToUpperInvariant();
        result.NormalizedCommand = trimmed;
        return result;
    }

    /// <summary>
    /// Extracts a normalized command action name from terminal / shell command lines.
    /// Decodes -EncodedCommand for PowerShell to reveal obfuscated subcommands.
    /// </summary>
    public static string ExtractShellSubcommand(string exeName, string cmdLine, out string? decodedScript)
    {
        var parsed = ParseShellExecution(exeName, cmdLine);
        decodedScript = parsed.DecodedScript;
        return parsed.Subcommand;
    }
}
