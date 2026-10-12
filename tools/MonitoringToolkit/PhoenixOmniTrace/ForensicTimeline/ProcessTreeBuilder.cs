using System;
using System.Collections.Generic;
using System.Linq;

namespace PhoenixGSM.OmniTrace.ForensicTimeline;

public class ProcessInfo
{
    public int ProcessId { get; set; }
    public int ParentProcessId { get; set; }
    public string ImageName { get; set; } = string.Empty;
    public string CommandLine { get; set; } = string.Empty;
    public DateTime StartTime { get; set; }
    public DateTime? ExitTime { get; set; }
}

public class ProcessNode
{
    public ProcessInfo Info { get; set; } = new();
    public List<ProcessNode> Children { get; set; } = new();
    public bool IsAnomalous { get; set; }
}

/// <summary>
/// Builds hierarchical process lineage tree
/// بناء شجرة سلالة العمليات الهرمية
/// </summary>
public class ProcessTreeBuilder : IDisposable
{
    private readonly HashSet<string> _suspiciousChains = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd.exe -> powershell.exe -EncodedCommand",
        "cmd.exe -> certutil.exe"
    };

    public ProcessNode BuildTree(IEnumerable<ProcessInfo> processEvents)
    {
        var root = new ProcessNode { Info = new ProcessInfo { ImageName = "ROOT" } };
        
        try
        {
            var dict = new Dictionary<int, ProcessNode>();
            
            foreach (var p in processEvents.OrderBy(p => p.StartTime))
            {
                var node = new ProcessNode { Info = p };
                dict[p.ProcessId] = node;
                
                if (dict.TryGetValue(p.ParentProcessId, out var parentNode))
                {
                    parentNode.Children.Add(node);
                    
                    // Check anomaly
                    // فحص الشذوذ
                    string chain = $"{parentNode.Info.ImageName} -> {node.Info.ImageName}";
                    if (node.Info.CommandLine.Contains("-EncodedCommand", StringComparison.OrdinalIgnoreCase))
                        chain += " -EncodedCommand";
                        
                    if (_suspiciousChains.Contains(chain))
                    {
                        node.IsAnomalous = true;
                    }
                }
                else
                {
                    root.Children.Add(node);
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ProcessTree] Error building tree: {ex.Message}");
        }
        
        return root;
    }

    public void Dispose()
    {
        // Cleanup resources
        // تنظيف الموارد
    }
}
