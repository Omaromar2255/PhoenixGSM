namespace PhoenixGSM.MonitoringStudio.ViewModels;

public partial class MainViewModel
{
    private int _totalEventsCount = 0;
    public int TotalEventsCount
    {
        get => _totalEventsCount;
        set { _totalEventsCount = value; OnPropertyChanged(); }
    }

    private int _phoneCommandsCount = 0;
    public int PhoneCommandsCount
    {
        get => _phoneCommandsCount;
        set { _phoneCommandsCount = value; OnPropertyChanged(); }
    }

    private int _usbCount = 0;
    public int UsbCount
    {
        get => _usbCount;
        set { _usbCount = value; OnPropertyChanged(); }
    }

    private int _adbCount = 0;
    public int AdbCount
    {
        get => _adbCount;
        set { _adbCount = value; OnPropertyChanged(); }
    }

    private int _serialCount = 0;
    public int SerialCount
    {
        get => _serialCount;
        set { _serialCount = value; OnPropertyChanged(); }
    }

    private int _processCount = 0;
    public int ProcessCount
    {
        get => _processCount;
        set { _processCount = value; OnPropertyChanged(); }
    }

    private int _networkCount = 0;
    public int NetworkCount
    {
        get => _networkCount;
        set { _networkCount = value; OnPropertyChanged(); }
    }

    private int _tempAtCount = 0;
    public int TempAtCount
    {
        get => _tempAtCount;
        set { _tempAtCount = value; OnPropertyChanged(); }
    }

    private int _mtpCount = 0;
    public int MtpCount
    {
        get => _mtpCount;
        set { _mtpCount = value; OnPropertyChanged(); }
    }

    private int _mtkCount = 0;
    public int MtkCount
    {
        get => _mtkCount;
        set { _mtkCount = value; OnPropertyChanged(); }
    }

    private int _spdCount = 0;
    public int SpdCount
    {
        get => _spdCount;
        set { _spdCount = value; OnPropertyChanged(); }
    }

    private int _edlCount = 0;
    public int EdlCount
    {
        get => _edlCount;
        set { _edlCount = value; OnPropertyChanged(); }
    }

    private int _inProcessCount = 0;
    public int InProcessCount
    {
        get => _inProcessCount;
        set { _inProcessCount = value; OnPropertyChanged(); }
    }

    private int _appleCount = 0;
    public int AppleCount
    {
        get => _appleCount;
        set { _appleCount = value; OnPropertyChanged(); }
    }

    private int _artifactVaultCount = 0;
    public int ArtifactVaultCount
    {
        get => _artifactVaultCount;
        set { _artifactVaultCount = value; OnPropertyChanged(); }
    }

    private int _cmdCount = 0;
    public int CmdCount
    {
        get => _cmdCount;
        set { _cmdCount = value; OnPropertyChanged(); }
    }

    private int _shellCount = 0;
    public int ShellCount
    {
        get => _shellCount;
        set { _shellCount = value; OnPropertyChanged(); }
    }
}
