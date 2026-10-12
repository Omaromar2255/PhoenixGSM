namespace PhoenixGSM.CommandAnalyzer;

using System.Text;
using System.Text.Json;
using PhoenixGSM.CommandAnalyzer.Models;

/// <summary>
/// Report generator — exports analysis results in various formats
/// </summary>
public class ReportGenerator
{
    /// <summary>
    /// Generate Markdown report
    /// </summary>
    public static string GenerateMarkdown(AnalysisResult result)
    {
        var sb = new StringBuilder();

        sb.AppendLine("# PhoenixGSM Analysis Report");
        sb.AppendLine();
        sb.AppendLine($"**Analysis Date:** {result.AnalysisDate:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"**Source Tool:** {result.SourceTool}");
        sb.AppendLine();

        // General statistics
        sb.AppendLine("## General Statistics");
        sb.AppendLine();
        sb.AppendLine("| Metric | Value |");
        sb.AppendLine("|--------|-------|");
        sb.AppendLine($"| ADB Commands | {result.TotalCommands} |");
        sb.AppendLine($"| Serial Packets | {result.TotalSerialPackets} |");
        sb.AppendLine($"| Process Activities | {result.TotalProcessActivities} |");
        sb.AppendLine();

        // Command categories
        if (result.CategoryBreakdown.Count > 0)
        {
            sb.AppendLine("## Command Breakdown");
            sb.AppendLine();
            sb.AppendLine("| Category | Count |");
            sb.AppendLine("|----------|-------|");
            foreach (var (cat, count) in result.CategoryBreakdown.OrderByDescending(x => x.Value))
                sb.AppendLine($"| {cat} | {count} |");
            sb.AppendLine();
        }

        // Top commands
        if (result.TopCommands.Count > 0)
        {
            sb.AppendLine("## Top Used Commands");
            sb.AppendLine();
            sb.AppendLine("| # | Command | Frequency | Category |");
            sb.AppendLine("|---|---------|-----------|----------|");
            int i = 1;
            foreach (var cmd in result.TopCommands.Take(20))
            {
                var truncated = cmd.Command.Length > 60
                    ? cmd.Command[..60] + "..."
                    : cmd.Command;
                sb.AppendLine($"| {i++} | `{truncated}` | {cmd.Count} | {cmd.Category} |");
            }
            sb.AppendLine();
        }

        // Operation sequences
        if (result.OperationSequences.Count > 0)
        {
            sb.AppendLine("## Detected Operation Sequences");
            sb.AppendLine();
            foreach (var seq in result.OperationSequences)
            {
                sb.AppendLine($"### {seq.Name}");
                sb.AppendLine($"_{seq.Description}_");
                sb.AppendLine();
                sb.AppendLine("```");
                foreach (var step in seq.Steps)
                    sb.AppendLine($"  {step.Order}. [{step.Type}] {step.Command}");
                sb.AppendLine("```");
                sb.AppendLine();
            }
        }

        // AT Commands
        if (result.AtCommands.Count > 0)
        {
            sb.AppendLine("## Discovered AT Commands");
            sb.AppendLine();
            foreach (var at in result.AtCommands)
                sb.AppendLine($"- `{at}`");
            sb.AppendLine();
        }

        // Important files
        if (result.ImportantFiles.Count > 0)
        {
            sb.AppendLine("## Critical Discovered Files");
            sb.AppendLine();
            foreach (var file in result.ImportantFiles)
                sb.AppendLine($"- `{file}`");
            sb.AppendLine();
        }

        // Discovered servers
        if (result.DiscoveredServers.Count > 0)
        {
            sb.AppendLine("## Discovered Servers");
            sb.AppendLine();
            foreach (var server in result.DiscoveredServers)
                sb.AppendLine($"- `{server}`");
            sb.AppendLine();
        }

        // Recommendations
        if (result.Recommendations.Count > 0)
        {
            sb.AppendLine("## Implementation Recommendations");
            sb.AppendLine();
            foreach (var rec in result.Recommendations)
                sb.AppendLine($"- {rec}");
            sb.AppendLine();
        }

        sb.AppendLine("---");
        sb.AppendLine("_Generated automatically by PhoenixGSM Command Analyzer_");

        return sb.ToString();
    }

    /// <summary>
    /// Generate JSON report
    /// </summary>
    public static string GenerateJson(AnalysisResult result)
    {
        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };
        return JsonSerializer.Serialize(result, options);
    }

    /// <summary>
    /// Save report to file
    /// </summary>
    public static async Task SaveReportAsync(string content, string filePath)
    {
        var dir = Path.GetDirectoryName(filePath);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);

        await File.WriteAllTextAsync(filePath, content, Encoding.UTF8);
    }
}
