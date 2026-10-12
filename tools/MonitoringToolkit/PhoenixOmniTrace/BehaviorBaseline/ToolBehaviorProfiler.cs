using System;

namespace PhoenixGSM.OmniTrace.BehaviorBaseline;

public class ToolBehaviorProfile
{
    public double AverageCommandRate { get; set; }
    public double AveragePayloadSize { get; set; }
    public double WriteRatio { get; set; }
}

public class ToolBehaviorProfiler
{
    private long _totalObservations = 0;
    private double _sumCommandRate = 0;
    private long _sumPayloadSize = 0;
    private long _totalWrites = 0;
    private readonly object _lockObj = new object();

    public ToolBehaviorProfile CurrentProfile { get; private set; } = new ToolBehaviorProfile();

    /// <summary>
    /// يسجل مراقبة لتحديث خط الأساس / Records an observation to update baseline
    /// </summary>
    public void RecordObservation(double commandRate, int payloadSize, bool isWrite)
    {
        try
        {
            lock (_lockObj)
            {
                _totalObservations++;
                _sumCommandRate += commandRate;
                _sumPayloadSize += payloadSize;

                if (isWrite)
                {
                    _totalWrites++;
                }

                // تحديث الإحصائيات / Update statistics
                CurrentProfile.AverageCommandRate = _sumCommandRate / _totalObservations;
                CurrentProfile.AveragePayloadSize = (double)_sumPayloadSize / _totalObservations;
                CurrentProfile.WriteRatio = (double)_totalWrites / _totalObservations;
            }
        }
        catch (Exception ex)
        {
            // Fail-open: لا تعطل عملية التنميط / Do not crash profiling
            Console.WriteLine($"[Profiler Error] {ex.Message}");
        }
    }

    public ToolBehaviorProfile GetProfile()
    {
        lock (_lockObj)
        {
            return new ToolBehaviorProfile
            {
                AverageCommandRate = CurrentProfile.AverageCommandRate,
                AveragePayloadSize = CurrentProfile.AveragePayloadSize,
                WriteRatio = CurrentProfile.WriteRatio
            };
        }
    }
}
