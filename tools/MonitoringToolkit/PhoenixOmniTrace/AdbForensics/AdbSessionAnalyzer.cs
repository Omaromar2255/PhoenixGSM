using System;
using System.Collections.Generic;
using System.Linq;

namespace PhoenixGSM.OmniTrace.AdbForensics;

[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public class SessionAnalysisResult
{
    public int TotalCommands { get; set; }
    public Dictionary<AdbRiskLevel, int> RiskDistribution { get; set; } = new();
    public List<string> DetectedPatterns { get; set; } = new();
    public int OverallRiskScore { get; set; } // 0-100
}

[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public class AdbSessionAnalyzer
{
    private readonly AdbCommandClassifier _classifier = new();

    public SessionAnalysisResult AnalyzeSession(List<dynamic> commandEvents)
    {
        var result = new SessionAnalysisResult();
        
        try
        {
            if (commandEvents == null || !commandEvents.Any())
                return result;

            result.TotalCommands = commandEvents.Count;

            var risks = new List<AdbCommandRisk>();
            foreach (var evt in commandEvents)
            {
                string cmd = evt.Command?.ToString() ?? "";
                var risk = _classifier.ClassifyCommand(cmd);
                risks.Add(risk);

                if (result.RiskDistribution.ContainsKey(risk.RiskLevel))
                    result.RiskDistribution[risk.RiskLevel]++;
                else
                    result.RiskDistribution[risk.RiskLevel] = 1;
            }

            // تحليل الأنماط - Pattern Analysis
            DetectReconnaissance(risks, result);
            DetectStagedAttack(risks, result);
            DetectDataTheft(risks, result);
            DetectCleanup(risks, result);

            // حساب التقييم الإجمالي - Calculate Overall Risk Score
            result.OverallRiskScore = CalculateScore(result);
        }
        catch (Exception ex)
        {
            // Fail-open
            Console.WriteLine($"[AdbSessionAnalyzer] Error: {ex.Message}");
        }

        return result;
    }

    private void DetectReconnaissance(List<AdbCommandRisk> risks, SessionAnalysisResult result)
    {
        // Multiple getprop/dumpsys followed by push
        bool hasQuery = false;
        foreach (var r in risks)
        {
            if (r.Command.Contains("getprop") || r.Command.Contains("dumpsys"))
                hasQuery = true;
            else if (hasQuery && r.Command.Contains("push"))
            {
                result.DetectedPatterns.Add("Reconnaissance Chain (Query -> Push)");
                break;
            }
        }
    }

    private void DetectStagedAttack(List<AdbCommandRisk> risks, SessionAnalysisResult result)
    {
        // push -> execute -> push
        int pushCount = 0;
        bool executed = false;
        foreach (var r in risks)
        {
            if (r.Command.Contains("push"))
                pushCount++;
            else if (pushCount > 0 && r.Category == AdbCommandCategory.ShellExecution)
                executed = true;

            if (pushCount >= 2 && executed)
            {
                result.DetectedPatterns.Add("Staged Attack (Push -> Execute -> Push)");
                break;
            }
        }
    }

    private void DetectDataTheft(List<AdbCommandRisk> risks, SessionAnalysisResult result)
    {
        // shell -> content query -> pull
        bool hasShell = false;
        bool hasQuery = false;
        foreach (var r in risks)
        {
            if (r.Command.Contains("shell") && !r.Command.Contains("content"))
                hasShell = true;
            if (hasShell && r.Command.Contains("content query"))
                hasQuery = true;
            if (hasQuery && r.Command.Contains("pull"))
            {
                result.DetectedPatterns.Add("Data Theft Chain (Shell -> Query -> Pull)");
                break;
            }
        }
    }

    private void DetectCleanup(List<AdbCommandRisk> risks, SessionAnalysisResult result)
    {
        // commands followed by logcat -c
        if (risks.Count > 1)
        {
            var last = risks.Last();
            if (last.Command.Contains("logcat -c") || last.Command.Contains("rm "))
            {
                result.DetectedPatterns.Add("Cleanup Chain (Execution -> Log Clear/Remove)");
            }
        }
    }

    private int CalculateScore(SessionAnalysisResult result)
    {
        int score = 0;
        int critical = result.RiskDistribution.GetValueOrDefault(AdbRiskLevel.Critical, 0);
        int high = result.RiskDistribution.GetValueOrDefault(AdbRiskLevel.High, 0);
        int medium = result.RiskDistribution.GetValueOrDefault(AdbRiskLevel.Medium, 0);

        score += critical * 25;
        score += high * 10;
        score += medium * 2;
        score += result.DetectedPatterns.Count * 15;

        return Math.Min(100, score);
    }
}
