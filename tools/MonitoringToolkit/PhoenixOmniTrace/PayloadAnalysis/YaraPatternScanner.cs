using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace PhoenixGSM.OmniTrace.PayloadAnalysis;

// تعريف القاعدة / Rule definition
public class YaraRuleDefinition
{
    public string Name { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public List<string> StringPatterns { get; set; } = new();
    public List<byte[]> ByteSequences { get; set; } = new();
    public List<string> RegexPatterns { get; set; } = new();
}

// نتيجة الفحص / Scan match result
public class YaraScanMatch
{
    public string RuleName { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public string MatchedPattern { get; set; } = string.Empty;
    public long Offset { get; set; }
}

public class YaraPatternScanner : IDisposable
{
    private readonly List<YaraRuleDefinition> _rules;

    public YaraPatternScanner(IEnumerable<YaraRuleDefinition> rules)
    {
        _rules = new List<YaraRuleDefinition>(rules);
    }

    /// <summary>
    /// يفحص مصفوفة بايتات / Scans a byte array
    /// </summary>
    public List<YaraScanMatch> ScanBuffer(ReadOnlySpan<byte> buffer, string fileName = "")
    {
        var matches = new List<YaraScanMatch>();
        try
        {
            // تحويل البايتات إلى نص للبحث عن النصوص / Convert to string for text search
            string textBuffer = Encoding.ASCII.GetString(buffer);

            foreach (var rule in _rules)
            {
                bool matched = false;

                // 1. Strings
                foreach (var pattern in rule.StringPatterns)
                {
                    int index = textBuffer.IndexOf(pattern, StringComparison.OrdinalIgnoreCase);
                    if (index >= 0)
                    {
                        matches.Add(CreateMatch(rule, pattern, index));
                        matched = true;
                    }
                }

                // 2. Regex
                foreach (var regexPattern in rule.RegexPatterns)
                {
                    try
                    {
                        var regex = new Regex(regexPattern, RegexOptions.IgnoreCase | RegexOptions.Compiled);
                        var match = regex.Match(textBuffer);
                        if (match.Success)
                        {
                            matches.Add(CreateMatch(rule, match.Value, match.Index));
                            matched = true;
                        }
                    }
                    catch
                    {
                        // Ignore invalid regex
                    }
                }

                // 3. Bytes
                if (!matched)
                {
                    foreach (var byteSeq in rule.ByteSequences)
                    {
                        int index = IndexOfSequence(buffer, byteSeq);
                        if (index >= 0)
                        {
                            matches.Add(CreateMatch(rule, BitConverter.ToString(byteSeq), index));
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            // Fail-open
            Console.WriteLine($"[YaraPatternScanner] ScanBuffer Error: {ex.Message}");
        }
        return matches;
    }

    /// <summary>
    /// يفحص ملف / Scans a file
    /// </summary>
    public List<YaraScanMatch> ScanFile(string filePath)
    {
        var matches = new List<YaraScanMatch>();
        try
        {
            if (File.Exists(filePath))
            {
                byte[] fileBytes = File.ReadAllBytes(filePath);
                matches.AddRange(ScanBuffer(fileBytes, Path.GetFileName(filePath)));
            }
        }
        catch (Exception ex)
        {
            // Fail-open
            Console.WriteLine($"[YaraPatternScanner] ScanFile Error: {ex.Message}");
        }
        return matches;
    }

    private YaraScanMatch CreateMatch(YaraRuleDefinition rule, string matchedPattern, long offset)
    {
        return new YaraScanMatch
        {
            RuleName = rule.Name,
            Category = rule.Category,
            Severity = rule.Severity,
            MatchedPattern = matchedPattern,
            Offset = offset
        };
    }

    private int IndexOfSequence(ReadOnlySpan<byte> buffer, byte[] pattern)
    {
        if (pattern.Length == 0) return -1;
        for (int i = 0; i <= buffer.Length - pattern.Length; i++)
        {
            bool found = true;
            for (int j = 0; j < pattern.Length; j++)
            {
                if (buffer[i + j] != pattern[j])
                {
                    found = false;
                    break;
                }
            }
            if (found) return i;
        }
        return -1;
    }

    public void Dispose()
    {
        // تنظيف / Cleanup
        _rules.Clear();
    }
}
