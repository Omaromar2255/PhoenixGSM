// ╔══════════════════════════════════════════════════════════════╗
// ║  PhoenixGSM — Command Analyzer                              ║
// ║  Aggregates and analyzes data from all monitoring tools      ║
// ╚══════════════════════════════════════════════════════════════╝

using System.Text;
using PhoenixGSM.CommandAnalyzer;
using Spectre.Console;

Console.OutputEncoding = Encoding.UTF8;

var logBaseDir = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
    "PhoenixGSM", "Logs");

var reportDir = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
    "PhoenixGSM", "Reports");

if (args.Length == 0 || args[0] is "--help" or "-h")
{
    ShowHelp();
    return;
}

switch (args[0].ToLower())
{
    case "--analyze" or "-a":
        await AnalyzeAllAsync();
        break;

    case "--summary" or "-s":
        ShowSummary();
        break;

    case "--export" or "-e":
        var format = args.Length > 1 ? args[1] : "markdown";
        await ExportReportAsync(format);
        break;

    default:
        ShowHelp();
        break;
}

/// <summary>Analyze all logs</summary>
async Task AnalyzeAllAsync()
{
    AnsiConsole.Write(new FigletText("PhoenixGSM")
        .LeftJustified()
        .Color(Color.Cyan1));

    AnsiConsole.MarkupLine("[bold cyan]=== Command Analyzer — Full Logs Analysis ===[/]");
    AnsiConsole.WriteLine();

    var parser = new LogParser(logBaseDir);
    var analyzer = new PatternAnalyzer();

    // Check for logs
    var summaries = parser.GetAvailableLogsSummary();
    if (summaries.Count == 0)
    {
        AnsiConsole.MarkupLine("[yellow]Warning: No logs found yet![/]");
        AnsiConsole.MarkupLine("[dim]Run monitoring tools first, then run analysis:[/]");
        AnsiConsole.MarkupLine("[dim]  * AdbMonitor --install[/]");
        AnsiConsole.MarkupLine("[dim]  * ProcessMonitor --target <tool>[/]");
        AnsiConsole.MarkupLine("[dim]  * SerialSniffer --port COM3[/]");
        return;
    }

    // Display available logs
    var table = new Table()
        .Border(TableBorder.Rounded)
        .Title("[cyan]Available Logs[/]")
        .AddColumn("Category")
        .AddColumn("Files")
        .AddColumn("Entries")
        .AddColumn("Size");

    foreach (var (cat, summary) in summaries)
    {
        table.AddRow(
            cat,
            summary.FileCount.ToString(),
            summary.TotalEntries.ToString("N0"),
            $"{summary.TotalSizeKB:F1} KB"
        );
    }
    AnsiConsole.Write(table);
    AnsiConsole.WriteLine();

    // Analysis with progress bar
    PhoenixGSM.CommandAnalyzer.Models.AnalysisResult? result = null;

    await AnsiConsole.Progress()
        .AutoClear(false)
        .Columns(
            new TaskDescriptionColumn(),
            new ProgressBarColumn(),
            new PercentageColumn(),
            new SpinnerColumn())
        .StartAsync(async ctx =>
        {
            // Analyze ADB
            var adbTask = ctx.AddTask("[cyan]Analyzing ADB Logs[/]");
            var adbLogs = await parser.ReadAdbLogsAsync();
            adbTask.Value = 50;
            result = analyzer.AnalyzeAdbLogs(adbLogs);
            adbTask.Value = 100;

            // Analyze Serial
            var serialTask = ctx.AddTask("[yellow]Analyzing Serial Logs[/]");
            var serialLogs = await parser.ReadSerialLogsAsync();
            serialTask.Value = 50;
            analyzer.AnalyzeSerialLogs(serialLogs, result!);
            serialTask.Value = 100;

            // Analyze Process
            var processTask = ctx.AddTask("[green]Analyzing Process Logs[/]");
            var processLogs = await parser.ReadProcessLogsAsync();
            processTask.Value = 50;
            analyzer.AnalyzeProcessLogs(processLogs, result!);
            processTask.Value = 100;

            // Analyze USB
            var usbTask = ctx.AddTask("[magenta]Analyzing USB ADB Logs[/]");
            var usbLogs = await parser.ReadUsbLogsAsync();
            usbTask.Value = 50;
            analyzer.AnalyzeUsbLogs(usbLogs, result!);
            usbTask.Value = 100;

            // Correlate Timeline
            var timelineTask = ctx.AddTask("[blue]Correlating Multi-Tool Timeline[/]");
            analyzer.CorrelateTimeline(adbLogs, usbLogs, serialLogs, processLogs, result!);
            timelineTask.Value = 100;
        });

    if (result is null) return;

    AnsiConsole.WriteLine();

    // Display results
    DisplayResults(result!);

    // Auto save reports
    Directory.CreateDirectory(reportDir);
    var mdPath = Path.Combine(reportDir, $"analysis_{DateTime.Now:yyyy-MM-dd_HHmmss}.md");
    var jsonPath = Path.Combine(reportDir, $"analysis_{DateTime.Now:yyyy-MM-dd_HHmmss}.json");

    await ReportGenerator.SaveReportAsync(ReportGenerator.GenerateMarkdown(result!), mdPath);
    await ReportGenerator.SaveReportAsync(ReportGenerator.GenerateJson(result!), jsonPath);

    AnsiConsole.MarkupLine("\n[green]Success: Reports saved to:[/]");
    AnsiConsole.MarkupLine($"  Report (MD)  : [link]{mdPath}[/]");
    AnsiConsole.MarkupLine($"  Report (JSON): [link]{jsonPath}[/]");
}

/// <summary>Show logs summary</summary>
void ShowSummary()
{
    var parser = new LogParser(logBaseDir);
    var summaries = parser.GetAvailableLogsSummary();

    AnsiConsole.MarkupLine("[bold cyan]=== Available Logs Summary ===[/]\n");

    if (summaries.Count == 0)
    {
        AnsiConsole.MarkupLine("[yellow]No logs recorded yet.[/]");
        return;
    }

    foreach (var (cat, summary) in summaries)
    {
        var panel = new Panel(
            $"Files   : {summary.FileCount}\n" +
            $"Entries : {summary.TotalEntries:N0}\n" +
            $"Size    : {summary.TotalSizeKB:F1} KB\n" +
            $"From    : {summary.EarliestEntry:yyyy-MM-dd}\n" +
            $"To      : {summary.LatestEntry:yyyy-MM-dd}")
            .Header($"[cyan]{cat}[/]")
            .Border(BoxBorder.Rounded);

        AnsiConsole.Write(panel);
    }
}

/// <summary>Export report</summary>
async Task ExportReportAsync(string format)
{
    AnsiConsole.MarkupLine("[cyan]Exporting report...[/]");

    var parser = new LogParser(logBaseDir);
    var analyzer = new PatternAnalyzer();

    var adbLogs = await parser.ReadAdbLogsAsync();
    var result = analyzer.AnalyzeAdbLogs(adbLogs);

    var serialLogs = await parser.ReadSerialLogsAsync();
    analyzer.AnalyzeSerialLogs(serialLogs, result);

    var processLogs = await parser.ReadProcessLogsAsync();
    analyzer.AnalyzeProcessLogs(processLogs, result);

    Directory.CreateDirectory(reportDir);

    string content;
    string ext;
    if (format.ToLower() is "json" or "j")
    {
        content = ReportGenerator.GenerateJson(result);
        ext = "json";
    }
    else
    {
        content = ReportGenerator.GenerateMarkdown(result);
        ext = "md";
    }

    var path = Path.Combine(reportDir, $"report_{DateTime.Now:yyyy-MM-dd_HHmmss}.{ext}");
    await ReportGenerator.SaveReportAsync(content, path);

    AnsiConsole.MarkupLine($"[green]Report saved successfully: {path}[/]");
}

/// <summary>Display analysis results</summary>
void DisplayResults(PhoenixGSM.CommandAnalyzer.Models.AnalysisResult result)
{
    // General stats
    var statsTable = new Table()
        .Border(TableBorder.Rounded)
        .Title("[bold cyan]General Statistics[/]")
        .AddColumn("Metric")
        .AddColumn("Value");

    statsTable.AddRow("ADB Commands", result.TotalCommands.ToString("N0"));
    statsTable.AddRow("USB ADB Frames", result.TotalUsbFrames.ToString("N0"));
    statsTable.AddRow("Serial Packets", result.TotalSerialPackets.ToString("N0"));
    statsTable.AddRow("Process Activities", result.TotalProcessActivities.ToString("N0"));
    statsTable.AddRow("AT Commands", result.AtCommands.Count.ToString());
    statsTable.AddRow("Detected Sequences", result.OperationSequences.Count.ToString());
    AnsiConsole.Write(statsTable);

    // USB breakdown
    if (result.UsbCommandBreakdown.Count > 0)
    {
        AnsiConsole.WriteLine();
        var usbTable = new Table()
            .Border(TableBorder.Rounded)
            .Title("[bold magenta]USB ADB Frames Breakdown[/]")
            .AddColumn("Command")
            .AddColumn("Frames Count");

        foreach (var (cmd, count) in result.UsbCommandBreakdown.OrderByDescending(x => x.Value))
        {
            usbTable.AddRow(cmd, count.ToString());
        }
        AnsiConsole.Write(usbTable);
    }

    // Chronological Timeline
    if (result.ChronologicalEvents.Count > 0)
    {
        AnsiConsole.WriteLine();
        var timeTable = new Table()
            .Border(TableBorder.Rounded)
            .Title("[bold cyan]Chronological Multi-Tool Timeline (Correlated Sequence)[/]")
            .AddColumn("Time")
            .AddColumn("Source")
            .AddColumn("Event Summary")
            .AddColumn("Details");

        foreach (var ev in result.ChronologicalEvents.Take(25))
        {
            var color = ev.Source switch
            {
                "ADB" => "cyan",
                "USB" => "magenta",
                "SERIAL" => "yellow",
                "PROCESS" => "green",
                _ => "white"
            };

            var details = ev.Details.Length > 50 ? ev.Details[..47] + "..." : ev.Details;
            timeTable.AddRow(
                ev.Timestamp.ToString("HH:mm:ss.fff"),
                $"[{color}]{ev.Source}[/]",
                Markup.Escape(ev.Summary),
                Markup.Escape(details)
            );
        }
        AnsiConsole.Write(timeTable);
    }

    // Top commands
    if (result.TopCommands.Count > 0)
    {
        AnsiConsole.WriteLine();
        var cmdTable = new Table()
            .Border(TableBorder.Rounded)
            .Title("[bold yellow]Top 15 Most Used Commands[/]")
            .AddColumn("#")
            .AddColumn("Command")
            .AddColumn("Frequency");

        int i = 1;
        foreach (var cmd in result.TopCommands.Take(15))
        {
            var display = cmd.Command.Length > 55 ? cmd.Command[..55] + "..." : cmd.Command;
            cmdTable.AddRow(i.ToString(), Markup.Escape(display), cmd.Count.ToString());
            i++;
        }
        AnsiConsole.Write(cmdTable);
    }

    // Sequences
    if (result.OperationSequences.Count > 0)
    {
        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[bold magenta]Detected Operation Sequences:[/]");
        foreach (var seq in result.OperationSequences)
        {
            var stepCount = seq.Steps.Count;
            var tree = new Tree($"[bold]{Markup.Escape(seq.Name)}[/] ({stepCount} steps)");
            foreach (var step in seq.Steps)
            {
                var color = step.Type switch
                {
                    "SHELL" => "cyan",
                    "REBOOT" => "red",
                    "FILE_PUSH" or "FILE_PULL" => "yellow",
                    _ => "white"
                };
                tree.AddNode($"[dim]{step.Order}.[/] [{color}]{Markup.Escape(step.Command)}[/]");
            }
            AnsiConsole.Write(tree);
            AnsiConsole.WriteLine();
        }
    }

    // Recommendations
    if (result.Recommendations.Count > 0)
    {
        AnsiConsole.WriteLine();
        var recPanel = new Panel(
            string.Join("\n", result.Recommendations))
            .Header("[bold green]Implementation Recommendations[/]")
            .Border(BoxBorder.Double)
            .BorderColor(Color.Green);
        AnsiConsole.Write(recPanel);
    }
}

static void ShowHelp()
{
    AnsiConsole.Write(new FigletText("PhoenixGSM")
        .LeftJustified()
        .Color(Color.Cyan1));

    AnsiConsole.MarkupLine(@"[bold cyan]Command Analyzer — Aggregate and analyze monitoring logs[/]

  [bold]Usage:[/]
    CommandAnalyzer [yellow]--analyze[/]              Full analysis of all logs
    CommandAnalyzer [yellow]--summary[/]              Summary of recorded logs
    CommandAnalyzer [yellow]--export markdown[/]      Export Markdown report
    CommandAnalyzer [yellow]--export json[/]          Export JSON report
    CommandAnalyzer [yellow]--help[/]                 Show help menu

  [bold]Workflow:[/]
    [dim]1.[/] Run monitoring tools (AdbMonitor, ProcessMonitor, SerialSniffer)
    [dim]2.[/] Use your normal mobile tools as usual
    [dim]3.[/] Run CommandAnalyzer --analyze to inspect the captured data
    [dim]4.[/] Review discovered sequences and recommendations
    [dim]5.[/] Integrate commands into PhoenixGSM Pro
");
}
