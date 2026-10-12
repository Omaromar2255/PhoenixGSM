file_path = r'c:\Users\pc5\softwer\PhoenixGSM\tools\MonitoringToolkit\MonitoringStudio\ViewModels\MainViewModel.cs'
with open(file_path, 'r', encoding='utf-8') as f:
    content = f.read()

prop_block = """    public bool IsCmdMonitoringEnabled
    {
        get => _engine.IsCmdMonitoringEnabled;
        set
        {
            if (_engine.IsCmdMonitoringEnabled != value)
            {
                _engine.IsCmdMonitoringEnabled = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(CmdMonitoringStatusText));
                OnPropertyChanged(nameof(CmdMonitoringStatusColor));
            }
        }
    }
    public string CmdMonitoringStatusText => IsCmdMonitoringEnabled ? "ON" : "OFF";
    public string CmdMonitoringStatusColor => IsCmdMonitoringEnabled ? "#FFFFFF" : "#607286";

    public bool IsShellMonitoringEnabled
    {
        get => _engine.IsShellMonitoringEnabled;
        set
        {
            if (_engine.IsShellMonitoringEnabled != value)
            {
                _engine.IsShellMonitoringEnabled = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(ShellMonitoringStatusText));
                OnPropertyChanged(nameof(ShellMonitoringStatusColor));
            }
        }
    }
    public string ShellMonitoringStatusText => IsShellMonitoringEnabled ? "ON" : "OFF";
    public string ShellMonitoringStatusColor => IsShellMonitoringEnabled ? "#A5D6A7" : "#607286";
"""

if 'IsCmdMonitoringEnabled' not in content:
    content = content.replace('    public bool IsArtifactVaultEnabled', prop_block + '\n    public bool IsArtifactVaultEnabled')
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)
    print('Added missing toggle properties.')
else:
    print('Properties already exist.')
