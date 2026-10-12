namespace PhoenixGSM.CommandAnalyzer;

using System.Text.Json;
using PhoenixGSM.CommandAnalyzer.Models;

/// <summary>
/// محلل الأنماط — يكتشف تسلسلات العمليات من السجلات
/// Pattern analyzer — discovers operation sequences from logs
/// 
/// هذا هو الجزء الأهم: يحول البيانات الخام إلى معرفة قابلة للاستخدام
/// This is the most important part: converts raw data into actionable knowledge
/// </summary>
public class PatternAnalyzer
{
    /// <summary>
    /// تحليل سجلات ADB واستخراج الأنماط
    /// Analyze ADB logs and extract patterns
    /// </summary>
    public AnalysisResult AnalyzeAdbLogs(List<JsonElement> logs)
    {
        var result = new AnalysisResult { TotalCommands = logs.Count };

        // 1. تصنيف الأوامر / Categorize commands
        foreach (var log in logs)
        {
            var category = GetJsonString(log, "category");
            var command = GetJsonString(log, "command");
            var process = GetJsonString(log, "calling_process");

            if (!string.IsNullOrEmpty(category))
                result.CategoryBreakdown[category] = result.CategoryBreakdown.GetValueOrDefault(category) + 1;

            if (!string.IsNullOrEmpty(process))
                result.SourceTool = process;
        }

        // 2. أكثر الأوامر استخداماً / Most used commands
        result.TopCommands = logs
            .Select(l => GetJsonString(l, "command"))
            .Where(c => !string.IsNullOrEmpty(c))
            .GroupBy(c => NormalizeCommand(c))
            .Select(g => new CommandFrequency
            {
                Command = g.Key,
                Count = g.Count(),
                Category = GuessCategory(g.Key)
            })
            .OrderByDescending(c => c.Count)
            .Take(30)
            .ToList();

        // 3. اكتشاف تسلسلات العمليات / Discover operation sequences
        result.OperationSequences = DiscoverSequences(logs);

        // 4. توصيات / Recommendations
        result.Recommendations = GenerateRecommendations(result);

        return result;
    }

    /// <summary>
    /// تحليل سجلات Serial واستخراج أوامر AT
    /// Analyze Serial logs and extract AT commands
    /// </summary>
    public void AnalyzeSerialLogs(List<JsonElement> logs, AnalysisResult result)
    {
        result.TotalSerialPackets = logs.Count;

        foreach (var log in logs)
        {
            var protocol = GetJsonString(log, "protocol");
            var ascii = GetJsonString(log, "ascii_data");
            var isAt = log.TryGetProperty("is_at_command", out var atProp) && atProp.GetBoolean();

            if (!string.IsNullOrEmpty(protocol))
                result.DetectedProtocols[protocol] = result.DetectedProtocols.GetValueOrDefault(protocol) + 1;

            if (isAt && !string.IsNullOrEmpty(ascii))
            {
                var atCmd = ascii.Trim().Split('\r', '\n')[0];
                if (!result.AtCommands.Contains(atCmd))
                    result.AtCommands.Add(atCmd);
            }
        }
    }

    /// <summary>
    /// تحليل سجلات العمليات
    /// Analyze process logs
    /// </summary>
    public void AnalyzeProcessLogs(List<JsonElement> logs, AnalysisResult result)
    {
        result.TotalProcessActivities = logs.Count;

        foreach (var log in logs)
        {
            var type = GetJsonString(log, "activity_type");
            var path = GetJsonString(log, "path");
            var details = GetJsonString(log, "details");

            // الملفات المهمة / Important files
            if (type is "FILE_CREATE" or "FILE_WRITE" or "FILE_READ" && !string.IsNullOrEmpty(path))
            {
                if (IsInterestingPath(path) && !result.ImportantFiles.Contains(path))
                    result.ImportantFiles.Add(path);
            }

            // السيرفرات / Servers
            if (type == "NETWORK_CONNECT" && !string.IsNullOrEmpty(path))
            {
                if (!result.DiscoveredServers.Contains(path))
                    result.DiscoveredServers.Add(path);
            }
        }
    }

    /// <summary>
    /// تحليل سجلات USB ADB وربطها بالبروتوكول
    /// Analyze USB ADB logs and calculate metrics
    /// </summary>
    public void AnalyzeUsbLogs(List<JsonElement> logs, AnalysisResult result)
    {
        result.TotalUsbFrames = logs.Count;

        foreach (var log in logs)
        {
            var cmd = GetJsonString(log, "adb_command");
            if (!string.IsNullOrEmpty(cmd))
            {
                result.UsbCommandBreakdown[cmd] = result.UsbCommandBreakdown.GetValueOrDefault(cmd) + 1;
            }
        }
    }

    /// <summary>
    /// ربط جميع السجلات زمنياً من كافة المصادر (ADB, USB, Serial, Process)
    /// Correlate all logs into a single timeline
    /// </summary>
    public void CorrelateTimeline(
        List<JsonElement> adbLogs,
        List<JsonElement> usbLogs,
        List<JsonElement> serialLogs,
        List<JsonElement> processLogs,
        AnalysisResult result)
    {
        var events = new List<CorrelatedEvent>();

        foreach (var a in adbLogs)
        {
            if (DateTime.TryParse(GetJsonString(a, "timestamp"), out var t))
            {
                events.Add(new CorrelatedEvent
                {
                    Timestamp = t,
                    Source = "ADB",
                    Summary = $"ADB {GetJsonString(a, "category")}",
                    Details = GetJsonString(a, "command")
                });
            }
        }

        foreach (var u in usbLogs)
        {
            if (DateTime.TryParse(GetJsonString(u, "timestamp"), out var t))
            {
                var dir = GetJsonString(u, "direction");
                var cmd = GetJsonString(u, "adb_command");
                var ep = GetJsonString(u, "endpoint");
                var preview = GetJsonString(u, "payload_preview");
                events.Add(new CorrelatedEvent
                {
                    Timestamp = t,
                    Source = "USB",
                    Summary = $"USB {dir} ({ep}) -> {cmd}",
                    Details = string.IsNullOrWhiteSpace(preview) ? cmd : $"{cmd}: {preview}"
                });
            }
        }

        foreach (var s in serialLogs)
        {
            if (DateTime.TryParse(GetJsonString(s, "timestamp"), out var t))
            {
                var proto = GetJsonString(s, "protocol");
                var ascii = GetJsonString(s, "ascii_data");
                events.Add(new CorrelatedEvent
                {
                    Timestamp = t,
                    Source = "SERIAL",
                    Summary = $"Serial ({proto})",
                    Details = ascii.Trim().Replace("\r\n", " ")
                });
            }
        }

        foreach (var p in processLogs)
        {
            if (DateTime.TryParse(GetJsonString(p, "timestamp"), out var t))
            {
                var act = GetJsonString(p, "activity_type");
                var path = GetJsonString(p, "path");
                events.Add(new CorrelatedEvent
                {
                    Timestamp = t,
                    Source = "PROCESS",
                    Summary = $"Process {act}",
                    Details = path
                });
            }
        }

        result.ChronologicalEvents = events.OrderBy(e => e.Timestamp).ToList();
    }

    /// <summary>
    /// اكتشاف تسلسلات العمليات المتكررة
    /// Discover recurring operation sequences
    /// 
    /// مثال: إذا كانت نفس الأوامر تتكرر دائماً بنفس الترتيب
    /// فهذا يعني أنها تمثل عملية واحدة (مثل FRP Bypass)
    /// </summary>
    private List<OperationSequence> DiscoverSequences(List<JsonElement> logs)
    {
        var sequences = new List<OperationSequence>();

        // تقسيم الأوامر إلى مجموعات بناءً على الفواصل الزمنية
        // Split commands into groups based on time gaps
        var groups = new List<List<JsonElement>>();
        var currentGroup = new List<JsonElement>();

        DateTime? lastTime = null;
        foreach (var log in logs)
        {
            var timeStr = GetJsonString(log, "timestamp");
            if (DateTime.TryParse(timeStr, out var time))
            {
                // فاصل أكثر من 30 ثانية = مجموعة جديدة / Gap > 30s = new group
                if (lastTime.HasValue && (time - lastTime.Value).TotalSeconds > 30)
                {
                    if (currentGroup.Count >= 3)
                        groups.Add(new List<JsonElement>(currentGroup));
                    currentGroup.Clear();
                }
                lastTime = time;
            }
            currentGroup.Add(log);
        }
        if (currentGroup.Count >= 3)
            groups.Add(currentGroup);

        // Convert groups to sequences
        int seqNum = 1;
        foreach (var group in groups)
        {
            var seq = new OperationSequence
            {
                Name = $"Sequence #{seqNum} — {GuessOperationName(group)}",
                Description = $"Sequence of {group.Count} steps automatically detected",
                Steps = group.Select((g, i) => new SequenceStep
                {
                    Order = i + 1,
                    Type = GetJsonString(g, "category"),
                    Command = GetJsonString(g, "command"),
                    Description = DescribeCommand(GetJsonString(g, "command"))
                }).ToList()
            };

            sequences.Add(seq);
            seqNum++;
        }

        return sequences;
    }

    /// <summary>Guess operation name from commands</summary>
    private static string GuessOperationName(List<JsonElement> group)
    {
        var allCommands = string.Join(" ", group.Select(g => GetJsonString(g, "command").ToLower()));

        if (allCommands.Contains("frp") || allCommands.Contains("google") ||
            (allCommands.Contains("settings") && allCommands.Contains("secure")))
            return "FRP Bypass";

        if (allCommands.Contains("unlock") || allCommands.Contains("clck") || allCommands.Contains("nck"))
            return "Network Unlock";

        if (allCommands.Contains("flash") || allCommands.Contains("odin") || allCommands.Contains("download"))
            return "Firmware Flash";

        if (allCommands.Contains("imei") || allCommands.Contains("egmr") || allCommands.Contains("nv_data"))
            return "IMEI / NV Repair";

        if (allCommands.Contains("relock") || allCommands.Contains("bootloader"))
            return "Bootloader Relock";

        if (allCommands.Contains("arabic") || allCommands.Contains("locale") || allCommands.Contains("csc"))
            return "Language / CSC Change";

        if (allCommands.Contains("getprop") || allCommands.Contains("dumpsys"))
            return "Device Info Query";

        return "General Operation";
    }

    /// <summary>Describe command</summary>
    private static string DescribeCommand(string command)
    {
        var lower = command.ToLower();
        return lower switch
        {
            _ when lower.Contains("reboot recovery") => "Reboot to recovery mode",
            _ when lower.Contains("reboot download") => "Reboot to download mode",
            _ when lower.Contains("reboot bootloader") => "Reboot to bootloader / fastboot",
            _ when lower.Contains("reboot") => "Reboot device",
            _ when lower.Contains("getprop") => "Read system properties",
            _ when lower.Contains("settings put") => "Modify system setting",
            _ when lower.Contains("settings get") => "Read system setting",
            _ when lower.Contains("pm disable") => "Disable package/app",
            _ when lower.Contains("pm enable") => "Enable package/app",
            _ when lower.Contains("pm uninstall") => "Uninstall package/app",
            _ when lower.Contains("am start") => "Start activity / intent",
            _ when lower.Contains("push") => "Push file to device",
            _ when lower.Contains("pull") => "Pull file from device",
            _ when lower.Contains("install") => "Install package APK",
            _ when lower.Contains("shell dd") => "Direct block device write",
            _ when lower.Contains("content delete") => "Delete content provider data",
            _ when lower.Contains("wipe") => "Wipe device partitions/data",
            _ => command.Length > 60 ? command[..60] + "..." : command
        };
    }

    /// <summary>Normalize command for grouping</summary>
    private static string NormalizeCommand(string command)
    {
        // Remove variable values
        var normalized = System.Text.RegularExpressions.Regex.Replace(
            command, @"\b[0-9a-fA-F]{8,}\b", "<HEX>");
        normalized = System.Text.RegularExpressions.Regex.Replace(
            normalized, @"\/[a-zA-Z0-9_\/]+\.(bin|tar|img|zip)", "/<FILE>");
        return normalized.Trim();
    }

    /// <summary>Guess command category</summary>
    private static string GuessCategory(string command)
    {
        var lower = command.ToLower();
        if (lower.Contains("shell")) return "SHELL";
        if (lower.Contains("push") || lower.Contains("pull")) return "FILE";
        if (lower.Contains("reboot")) return "REBOOT";
        if (lower.Contains("install")) return "INSTALL";
        return "GENERAL";
    }

    /// <summary>Is path interesting</summary>
    private static bool IsInterestingPath(string path)
    {
        string[] keywords = ["adb", "samsung", "frp", "unlock", "imei", "firmware",
            "flash", "cert", "efs", "nv_data", ".bin", ".tar", ".pit"];
        var lower = path.ToLower();
        return keywords.Any(k => lower.Contains(k));
    }

    /// <summary>Generate implementation recommendations</summary>
    private static List<string> GenerateRecommendations(AnalysisResult result)
    {
        var recs = new List<string>();

        if (result.TopCommands.Any(c => c.Command.Contains("shell")))
            recs.Add("High frequency of shell commands: Build a robust ADB shell wrapper.");

        if (result.OperationSequences.Any(s => s.Name.Contains("FRP")))
            recs.Add("FRP Bypass sequence identified: Can be fully automated.");

        if (result.OperationSequences.Any(s => s.Name.Contains("Unlock")))
            recs.Add("Network unlock sequence detected: Collect more samples across models.");

        if (result.AtCommands.Count > 0)
            recs.Add($"Detected {result.AtCommands.Count} AT commands: Implement AT Command Engine.");

        if (result.DiscoveredServers.Count > 0)
            recs.Add($"Discovered {result.DiscoveredServers.Count} server endpoints: Analyze external APIs.");

        if (result.ImportantFiles.Count > 0)
            recs.Add($"Discovered {result.ImportantFiles.Count} critical files: Inspect binary structures.");

        recs.Add("Continue capturing operations across different tools to enrich knowledge base.");

        return recs;
    }

    /// <summary>قراءة خاصية نصية من JSON / Read string property from JSON</summary>
    private static string GetJsonString(JsonElement element, string property)
    {
        return element.TryGetProperty(property, out var value) ? value.GetString() ?? "" : "";
    }
}
