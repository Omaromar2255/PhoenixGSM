using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text;

namespace PhoenixOmniTrace.L24_SourceSentinel.Models;

public sealed class SourceTelemetryEvent : INotifyPropertyChanged
{
    private string _targetResource = string.Empty;
    private string _commandCategory = string.Empty;
    private string _decodedCommandText = string.Empty;
    private string _rawPayloadHex = string.Empty;
    private int _payloadSize;
    private string _pureCommandText = string.Empty;
    private string _savedFilePath = string.Empty;

    public Guid EventId { get; init; } = Guid.NewGuid();
    public DateTime Timestamp { get; init; } = DateTime.UtcNow;
    public int ProcessId { get; init; }
    public int ThreadId { get; init; }
    public SentinelStage Stage { get; init; }
    public long MemoryAddress { get; init; }

    public string HookedApiName { get; init; } = string.Empty;
    public string CallerModuleOrigin { get; init; } = string.Empty;

    public string TargetResource
    {
        get => _targetResource;
        set { if (_targetResource != value) { _targetResource = value; OnPropertyChanged(); } }
    }

    public string CommandCategory
    {
        get => _commandCategory;
        set
        {
            if (_commandCategory != value)
            {
                _commandCategory = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(CommandGroup));
                OnPropertyChanged(nameof(CommandGroupBadge));
            }
        }
    }

    public string DecodedCommandText
    {
        get => _decodedCommandText;
        set
        {
            if (_decodedCommandText != value)
            {
                _decodedCommandText = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(PureCommandText));
                OnPropertyChanged(nameof(CommandGroup));
                OnPropertyChanged(nameof(CommandGroupBadge));
            }
        }
    }

    public string RawPayloadHex
    {
        get => _rawPayloadHex;
        set
        {
            if (_rawPayloadHex != value)
            {
                _rawPayloadHex = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(PureCommandText));
            }
        }
    }

    public int PayloadSize
    {
        get => _payloadSize;
        set { if (_payloadSize != value) { _payloadSize = value; OnPropertyChanged(); } }
    }

    public string SavedFilePath
    {
        get => _savedFilePath;
        set { if (_savedFilePath != value) { _savedFilePath = value; OnPropertyChanged(); } }
    }

    public string PureCommandText
    {
        get
        {
            if (!string.IsNullOrWhiteSpace(_pureCommandText))
                return _pureCommandText;

            if (!string.IsNullOrWhiteSpace(_rawPayloadHex) && _rawPayloadHex.Length % 2 == 0)
            {
                try
                {
                    string utf8 = Encoding.UTF8.GetString(Convert.FromHexString(_rawPayloadHex)).Trim();
                    if (!string.IsNullOrWhiteSpace(utf8) && IsMostlyPrintable(utf8))
                        return utf8;
                }
                catch { }
            }

            int colonIdx = _decodedCommandText.IndexOf(':');
            if (colonIdx >= 0 && colonIdx + 1 < _decodedCommandText.Length &&
                !_decodedCommandText.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
                !_decodedCommandText.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                return _decodedCommandText[(colonIdx + 1)..].Trim();
            }

            return _decodedCommandText.Trim();
        }
        set
        {
            if (_pureCommandText != value)
            {
                _pureCommandText = value;
                OnPropertyChanged();
            }
        }
    }

    public L24CommandScope Scope => L24CommandClassifier.DetermineScope(HookedApiName, Stage, CommandCategory, DecodedCommandText, PureCommandText);
    public L24CommandGroup CommandGroup => L24CommandClassifier.DetermineGroup(CommandCategory, DecodedCommandText, PureCommandText);
    public string CommandGroupBadge => L24CommandClassifier.GetGroupArabicTitle(CommandGroup);

    public bool IsPhoneResponse =>
        CommandCategory.Contains("Response", StringComparison.OrdinalIgnoreCase) ||
        DecodedCommandText.Contains("رد الهاتف", StringComparison.OrdinalIgnoreCase) ||
        DecodedCommandText.Contains("رد المودم", StringComparison.OrdinalIgnoreCase);

    public string ScopeBadge => Scope switch
    {
        L24CommandScope.ExecutedOnDevice => "⚡ منفذ فعلياً للجهاز",
        L24CommandScope.DiscoveredInRam => "🧠 مكتشف في الذاكرة",
        _ => "📡 رادار / ملفات محفوظة"
    };

    public string StageBadge => Stage switch
    {
        SentinelStage.RamUnpackOrModuleLoad => "🧠 RAM / Module",
        SentinelStage.PortAndDeviceRadar => "📡 Radar / Scan",
        SentinelStage.LocalFilePreparation => "💾 Saved File / Prep",
        SentinelStage.PortConfiguration => "⚙️ Port Config",
        SentinelStage.RawCommandExecution => Scope == L24CommandScope.DiscoveredInRam ? "🧠 RAM Discovered" : "⚡ Executed Command",
        SentinelStage.NetworkPreEncryption => "🌐 Network / Login / URL",
        _ => Stage.ToString()
    };

    public string FormattedTimestamp => Timestamp.ToLocalTime().ToString("HH:mm:ss.fff");
    public string TimeFormatted => FormattedTimestamp;
    public string ProcessThreadInfo => $"{ProcessId}:{ThreadId}";

    private static bool IsMostlyPrintable(string s)
    {
        int printable = 0;
        foreach (char c in s)
        {
            if ((c >= 32 && c <= 126) || c == '\r' || c == '\n' || c == '\t')
                printable++;
        }
        return s.Length > 0 && (double)printable / s.Length >= 0.85;
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? propName = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propName));
}
