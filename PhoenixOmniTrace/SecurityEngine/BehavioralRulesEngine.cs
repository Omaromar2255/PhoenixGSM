using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace PhoenixGSM.OmniTrace.SecurityEngine;

[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public class BehavioralRulesEngine
{
    private readonly List<IDetectionRule> _rules = new();
    private readonly ConcurrentBag<ThreatAlert> _alertHistory = new();

    public event EventHandler<ThreatAlert>? OnThreatDetected;

    public BehavioralRulesEngine()
    {
        // تسجيل القواعد الافتراضية - Register default rules
        RegisterRule(new Rules.SilentApkInstallRule());
        RegisterRule(new Rules.DataExfiltrationRule());
        RegisterRule(new Rules.BackdoorInstallRule());
        RegisterRule(new Rules.UnauthorizedRootRule());
        RegisterRule(new Rules.ImeiTamperingRule());
        RegisterRule(new Rules.CovertChannelRule());
        RegisterRule(new Rules.AntiForensicRule());
    }

    public void RegisterRule(IDetectionRule rule)
    {
        if (rule != null)
        {
            _rules.Add(rule);
        }
    }

    public int GetRuleCount() => _rules.Count;

    public IReadOnlyCollection<ThreatAlert> GetAlertHistory() => _alertHistory.ToArray();

    public List<ThreatAlert> EvaluateCommand(dynamic commandEvent)
    {
        var alerts = new List<ThreatAlert>();
        try
        {
            foreach (var rule in _rules)
            {
                var alert = rule.Evaluate(commandEvent);
                if (alert != null)
                {
                    _alertHistory.Add(alert);
                    alerts.Add(alert);
                    
                    // إطلاق الحدث - Fire event
                    OnThreatDetected?.Invoke(this, alert);
                }
            }
        }
        catch (Exception ex)
        {
            // Fail-open
            Console.WriteLine($"[BehavioralRulesEngine] Evaluation Error: {ex.Message}");
        }
        return alerts;
    }

    public List<ThreatAlert> EvaluateAll(IEnumerable<dynamic> commandEvents)
    {
        var allAlerts = new List<ThreatAlert>();
        try
        {
            foreach (var cmdEvent in commandEvents)
            {
                allAlerts.AddRange(EvaluateCommand(cmdEvent));
            }
        }
        catch (Exception ex)
        {
            // Fail-open
            Console.WriteLine($"[BehavioralRulesEngine] Bulk Evaluation Error: {ex.Message}");
        }
        return allAlerts;
    }
}
