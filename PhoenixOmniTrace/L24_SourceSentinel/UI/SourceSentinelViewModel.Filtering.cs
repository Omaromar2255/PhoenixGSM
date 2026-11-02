using System;
using System.ComponentModel;
using System.Linq;
using PhoenixOmniTrace.L24_SourceSentinel.Models;

namespace PhoenixOmniTrace.L24_SourceSentinel.UI;

public sealed partial class SourceSentinelViewModel
{
    // فلترة تبويب الأوامر المكتشفة في الذاكرة (11 خياراً شاملاً)
    private string _discoveredCategoryFilter = "All";
    public string DiscoveredCategoryFilter
    {
        get => _discoveredCategoryFilter;
        set
        {
            if (_discoveredCategoryFilter != value)
            {
                _discoveredCategoryFilter = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(IsDiscAllSelected));
                OnPropertyChanged(nameof(IsDiscModemSelected));
                OnPropertyChanged(nameof(IsDiscMtkSelected));
                OnPropertyChanged(nameof(IsDiscQualcommSelected));
                OnPropertyChanged(nameof(IsDiscAppleSelected));
                OnPropertyChanged(nameof(IsDiscAdbSelected));
                OnPropertyChanged(nameof(IsDiscServerCloudSelected));
                OnPropertyChanged(nameof(IsDiscTransferSelected));
                OnPropertyChanged(nameof(IsDiscArchiveSelected));
                OnPropertyChanged(nameof(IsDiscCryptoSelected));
                OnPropertyChanged(nameof(IsDiscOtherSelected));
                FilteredDiscoveredRamEvents.Refresh();
            }
        }
    }

    public bool IsDiscAllSelected => DiscoveredCategoryFilter == "All";
    public bool IsDiscModemSelected => DiscoveredCategoryFilter == "ModemAt";
    public bool IsDiscMtkSelected => DiscoveredCategoryFilter == "MediaTek";
    public bool IsDiscQualcommSelected => DiscoveredCategoryFilter == "Qualcomm";
    public bool IsDiscAppleSelected => DiscoveredCategoryFilter == "AppleIos";
    public bool IsDiscAdbSelected => DiscoveredCategoryFilter == "AdbFastboot";
    public bool IsDiscServerCloudSelected => DiscoveredCategoryFilter == "ServerCloudLogin";
    public bool IsDiscTransferSelected => DiscoveredCategoryFilter == "FileTransfer";
    public bool IsDiscArchiveSelected => DiscoveredCategoryFilter == "ArchiveUnpack";
    public bool IsDiscCryptoSelected => DiscoveredCategoryFilter == "CryptoAuth";
    public bool IsDiscOtherSelected => DiscoveredCategoryFilter == "OtherCommands";

    public int DiscModemCount => DiscoveredRamEvents.Count(e => e.CommandGroup == L24CommandGroup.ModemAt);
    public int DiscMtkCount => DiscoveredRamEvents.Count(e => e.CommandGroup == L24CommandGroup.MediaTek);
    public int DiscQualcommCount => DiscoveredRamEvents.Count(e => e.CommandGroup == L24CommandGroup.Qualcomm);
    public int DiscAppleCount => DiscoveredRamEvents.Count(e => e.CommandGroup == L24CommandGroup.AppleIos);
    public int DiscAdbCount => DiscoveredRamEvents.Count(e => e.CommandGroup == L24CommandGroup.AdbFastboot);
    public int DiscServerCloudCount => DiscoveredRamEvents.Count(e => e.CommandGroup == L24CommandGroup.ServerCloudLogin);
    public int DiscTransferCount => DiscoveredRamEvents.Count(e => e.CommandGroup == L24CommandGroup.FileTransfer);
    public int DiscArchiveCount => DiscoveredRamEvents.Count(e => e.CommandGroup == L24CommandGroup.ArchiveUnpack);
    public int DiscCryptoCount => DiscoveredRamEvents.Count(e => e.CommandGroup == L24CommandGroup.CryptoAuth);
    public int DiscOtherCount => DiscoveredRamEvents.Count(e => e.CommandGroup == L24CommandGroup.OtherCommands);

    public string DiscAllButtonText => $"🌐 الكل ({DiscoveredRamCommandsCount})";
    public string DiscModemButtonText => $"📻 المودم ({DiscModemCount}){(IsModemCategoryEnabled ? "" : " [معطل]")}";
    public string DiscMtkButtonText => $"🔶 ميدياتك ({DiscMtkCount}){(IsMtkCategoryEnabled ? "" : " [معطل]")}";
    public string DiscQualcommButtonText => $"🔷 كوالكوم و EDL ({DiscQualcommCount}){(IsQualcommCategoryEnabled ? "" : " [معطل]")}";
    public string DiscAppleButtonText => $"🍎 أبل Apple ({DiscAppleCount}){(IsAppleCategoryEnabled ? "" : " [معطل]")}";
    public string DiscAdbButtonText => $"🤖 ADB/Fastboot ({DiscAdbCount}){(IsAdbCategoryEnabled ? "" : " [معطل]")}";
    public string DiscServerCloudButtonText => $"🌐 الروابط والخوادم ({DiscServerCloudCount}){(IsServerCloudCategoryEnabled && !ExcludeUrlsFromDiscovered ? "" : " [معطل]")}";
    public string DiscTransferButtonText => $"📤 نقل وملفات بوت ({DiscTransferCount}){(IsTransferCategoryEnabled ? "" : " [معطل]")}";
    public string DiscArchiveButtonText => $"📦 فك ضغط ({DiscArchiveCount}){(IsArchiveCategoryEnabled ? "" : " [معطل]")}";
    public string DiscCryptoButtonText => $"🔐 تشفير ومفاتيح ({DiscCryptoCount}){(IsCryptoCategoryEnabled ? "" : " [معطل]")}";
    public string DiscOtherButtonText => $"🧩 أوامر أخرى ({DiscOtherCount}){(IsOtherCategoryEnabled ? "" : " [معطل]")}";

    public bool IsModemCategoryEnabled
    {
        get => _orchestrator.IsCategoryDetectionEnabled(L24CommandGroup.ModemAt);
        set => SetCategoryState(L24CommandGroup.ModemAt, value, nameof(IsModemCategoryEnabled), nameof(DiscModemButtonText));
    }

    public bool IsMtkCategoryEnabled
    {
        get => _orchestrator.IsCategoryDetectionEnabled(L24CommandGroup.MediaTek);
        set => SetCategoryState(L24CommandGroup.MediaTek, value, nameof(IsMtkCategoryEnabled), nameof(DiscMtkButtonText));
    }

    public bool IsQualcommCategoryEnabled
    {
        get => _orchestrator.IsCategoryDetectionEnabled(L24CommandGroup.Qualcomm);
        set => SetCategoryState(L24CommandGroup.Qualcomm, value, nameof(IsQualcommCategoryEnabled), nameof(DiscQualcommButtonText));
    }

    public bool IsAppleCategoryEnabled
    {
        get => _orchestrator.IsCategoryDetectionEnabled(L24CommandGroup.AppleIos);
        set => SetCategoryState(L24CommandGroup.AppleIos, value, nameof(IsAppleCategoryEnabled), nameof(DiscAppleButtonText));
    }

    public bool IsAdbCategoryEnabled
    {
        get => _orchestrator.IsCategoryDetectionEnabled(L24CommandGroup.AdbFastboot);
        set => SetCategoryState(L24CommandGroup.AdbFastboot, value, nameof(IsAdbCategoryEnabled), nameof(DiscAdbButtonText));
    }

    public bool IsServerCloudCategoryEnabled
    {
        get => _orchestrator.IsCategoryDetectionEnabled(L24CommandGroup.ServerCloudLogin);
        set => SetCategoryState(L24CommandGroup.ServerCloudLogin, value, nameof(IsServerCloudCategoryEnabled), nameof(DiscServerCloudButtonText));
    }

    public bool IsTransferCategoryEnabled
    {
        get => _orchestrator.IsCategoryDetectionEnabled(L24CommandGroup.FileTransfer);
        set => SetCategoryState(L24CommandGroup.FileTransfer, value, nameof(IsTransferCategoryEnabled), nameof(DiscTransferButtonText));
    }

    public bool IsArchiveCategoryEnabled
    {
        get => _orchestrator.IsCategoryDetectionEnabled(L24CommandGroup.ArchiveUnpack);
        set => SetCategoryState(L24CommandGroup.ArchiveUnpack, value, nameof(IsArchiveCategoryEnabled), nameof(DiscArchiveButtonText));
    }

    public bool IsCryptoCategoryEnabled
    {
        get => _orchestrator.IsCategoryDetectionEnabled(L24CommandGroup.CryptoAuth);
        set => SetCategoryState(L24CommandGroup.CryptoAuth, value, nameof(IsCryptoCategoryEnabled), nameof(DiscCryptoButtonText));
    }

    public bool IsOtherCategoryEnabled
    {
        get => _orchestrator.IsCategoryDetectionEnabled(L24CommandGroup.OtherCommands);
        set => SetCategoryState(L24CommandGroup.OtherCommands, value, nameof(IsOtherCategoryEnabled), nameof(DiscOtherButtonText));
    }

    private void SetCategoryState(L24CommandGroup group, bool enabled, string propName, string buttonPropName)
    {
        if (_orchestrator.IsCategoryDetectionEnabled(group) != enabled)
        {
            _orchestrator.SetCategoryDetectionEnabled(group, enabled);
            OnPropertyChanged(propName);
            OnPropertyChanged(buttonPropName);
            FilteredDiscoveredRamEvents.Refresh();
        }
    }

    public bool ExcludeUrlsFromDiscovered
    {
        get => _orchestrator.ExcludeUrlsFromDiscovered;
        set
        {
            if (_orchestrator.ExcludeUrlsFromDiscovered != value)
            {
                _orchestrator.ExcludeUrlsFromDiscovered = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(DiscServerCloudButtonText));
                FilteredDiscoveredRamEvents.Refresh();
            }
        }
    }

    public bool ExcludeUrlsFromRawLog
    {
        get => _orchestrator.ExcludeUrlsFromRawLog;
        set
        {
            if (_orchestrator.ExcludeUrlsFromRawLog != value)
            {
                _orchestrator.ExcludeUrlsFromRawLog = value;
                OnPropertyChanged();
                FilteredUnfilteredRawEvents.Refresh();
            }
        }
    }

    public void NotifyAllCategoryProperties()
    {
        OnPropertyChanged(nameof(IsModemCategoryEnabled));
        OnPropertyChanged(nameof(IsMtkCategoryEnabled));
        OnPropertyChanged(nameof(IsQualcommCategoryEnabled));
        OnPropertyChanged(nameof(IsAppleCategoryEnabled));
        OnPropertyChanged(nameof(IsAdbCategoryEnabled));
        OnPropertyChanged(nameof(IsServerCloudCategoryEnabled));
        OnPropertyChanged(nameof(IsTransferCategoryEnabled));
        OnPropertyChanged(nameof(IsArchiveCategoryEnabled));
        OnPropertyChanged(nameof(IsCryptoCategoryEnabled));
        OnPropertyChanged(nameof(IsOtherCategoryEnabled));
        OnPropertyChanged(nameof(ExcludeUrlsFromDiscovered));
        OnPropertyChanged(nameof(ExcludeUrlsFromRawLog));
        UpdateDiscoveredCategoryCounters();
    }

    private void UpdateDiscoveredCategoryCounters()
    {
        OnPropertyChanged(nameof(DiscModemCount));
        OnPropertyChanged(nameof(DiscMtkCount));
        OnPropertyChanged(nameof(DiscQualcommCount));
        OnPropertyChanged(nameof(DiscAppleCount));
        OnPropertyChanged(nameof(DiscAdbCount));
        OnPropertyChanged(nameof(DiscServerCloudCount));
        OnPropertyChanged(nameof(DiscTransferCount));
        OnPropertyChanged(nameof(DiscArchiveCount));
        OnPropertyChanged(nameof(DiscCryptoCount));
        OnPropertyChanged(nameof(DiscOtherCount));

        OnPropertyChanged(nameof(DiscAllButtonText));
        OnPropertyChanged(nameof(DiscModemButtonText));
        OnPropertyChanged(nameof(DiscMtkButtonText));
        OnPropertyChanged(nameof(DiscQualcommButtonText));
        OnPropertyChanged(nameof(DiscAppleButtonText));
        OnPropertyChanged(nameof(DiscAdbButtonText));
        OnPropertyChanged(nameof(DiscServerCloudButtonText));
        OnPropertyChanged(nameof(DiscTransferButtonText));
        OnPropertyChanged(nameof(DiscArchiveButtonText));
        OnPropertyChanged(nameof(DiscCryptoButtonText));
        OnPropertyChanged(nameof(DiscOtherButtonText));
    }

    private void RefreshAllViews()
    {
        FilteredExecutedEvents.Refresh();
        FilteredPurePhoneEvents.Refresh();
        FilteredDiscoveredRamEvents.Refresh();
        FilteredRadarEvents.Refresh();
        FilteredUnfilteredRawEvents.Refresh();
        FilteredEvents.Refresh();
        UpdateExecutedCategoryCounters();
        UpdatePureCategoryCounters();
    }

    // فلترة تبويب الأوامر الفعلية المنفذة للجهاز (Tab 1: Executed Phone Commands)
    private string _executedCategoryFilter = "All";
    public string ExecutedCategoryFilter
    {
        get => _executedCategoryFilter;
        set
        {
            if (_executedCategoryFilter != value)
            {
                _executedCategoryFilter = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(IsExecAllSelected));
                OnPropertyChanged(nameof(IsExecModemSelected));
                OnPropertyChanged(nameof(IsExecMtkSelected));
                OnPropertyChanged(nameof(IsExecQualcommSelected));
                OnPropertyChanged(nameof(IsExecAppleSelected));
                OnPropertyChanged(nameof(IsExecAdbSelected));
                OnPropertyChanged(nameof(IsExecOtherSelected));
                FilteredExecutedEvents.Refresh();
            }
        }
    }

    public bool IsExecAllSelected => ExecutedCategoryFilter == "All";
    public bool IsExecModemSelected => ExecutedCategoryFilter == "ModemAt";
    public bool IsExecMtkSelected => ExecutedCategoryFilter == "MediaTek";
    public bool IsExecQualcommSelected => ExecutedCategoryFilter == "Qualcomm";
    public bool IsExecAppleSelected => ExecutedCategoryFilter == "AppleIos";
    public bool IsExecAdbSelected => ExecutedCategoryFilter == "AdbFastboot";
    public bool IsExecOtherSelected => ExecutedCategoryFilter == "OtherCommands";

    public int ExecModemCount => ExecutedDeviceEvents.Count(e => e.CommandGroup == L24CommandGroup.ModemAt);
    public int ExecMtkCount => ExecutedDeviceEvents.Count(e => e.CommandGroup == L24CommandGroup.MediaTek);
    public int ExecQualcommCount => ExecutedDeviceEvents.Count(e => e.CommandGroup == L24CommandGroup.Qualcomm);
    public int ExecAppleCount => ExecutedDeviceEvents.Count(e => e.CommandGroup == L24CommandGroup.AppleIos);
    public int ExecAdbCount => ExecutedDeviceEvents.Count(e => e.CommandGroup == L24CommandGroup.AdbFastboot);
    public int ExecOtherCount => ExecutedDeviceEvents.Count(e => e.CommandGroup != L24CommandGroup.ModemAt &&
                                                                 e.CommandGroup != L24CommandGroup.MediaTek &&
                                                                 e.CommandGroup != L24CommandGroup.Qualcomm &&
                                                                 e.CommandGroup != L24CommandGroup.AppleIos &&
                                                                 e.CommandGroup != L24CommandGroup.AdbFastboot);

    public string ExecAllButtonText => $"🌐 الكل ({ExecutedCommandsCount})";
    public string ExecModemButtonText => $"📻 المودم ({ExecModemCount})";
    public string ExecMtkButtonText => $"🔶 ميدياتك ({ExecMtkCount})";
    public string ExecQualcommButtonText => $"🔷 كوالكوم ({ExecQualcommCount})";
    public string ExecAppleButtonText => $"🍎 أبل ({ExecAppleCount})";
    public string ExecAdbButtonText => $"🤖 ADB ({ExecAdbCount})";
    public string ExecOtherButtonText => $"🧩 أخرى ({ExecOtherCount})";

    public void UpdateExecutedCategoryCounters()
    {
        OnPropertyChanged(nameof(ExecModemCount));
        OnPropertyChanged(nameof(ExecMtkCount));
        OnPropertyChanged(nameof(ExecQualcommCount));
        OnPropertyChanged(nameof(ExecAppleCount));
        OnPropertyChanged(nameof(ExecAdbCount));
        OnPropertyChanged(nameof(ExecOtherCount));

        OnPropertyChanged(nameof(ExecAllButtonText));
        OnPropertyChanged(nameof(ExecModemButtonText));
        OnPropertyChanged(nameof(ExecMtkButtonText));
        OnPropertyChanged(nameof(ExecQualcommButtonText));
        OnPropertyChanged(nameof(ExecAppleButtonText));
        OnPropertyChanged(nameof(ExecAdbButtonText));
        OnPropertyChanged(nameof(ExecOtherButtonText));
    }

    // فلترة تبويب أوامر الهاتف الصافية للتجربة (Tab 2: Pure Phone Testable Commands)
    private string _pureCategoryFilter = "All";
    public string PureCategoryFilter
    {
        get => _pureCategoryFilter;
        set
        {
            if (_pureCategoryFilter != value)
            {
                _pureCategoryFilter = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(IsPureAllSelected));
                OnPropertyChanged(nameof(IsPureModemSelected));
                OnPropertyChanged(nameof(IsPureMtkSelected));
                OnPropertyChanged(nameof(IsPureQualcommSelected));
                OnPropertyChanged(nameof(IsPureAppleSelected));
                OnPropertyChanged(nameof(IsPureAdbSelected));
                OnPropertyChanged(nameof(IsPureOtherSelected));
                FilteredPurePhoneEvents.Refresh();
            }
        }
    }

    public bool IsPureAllSelected => PureCategoryFilter == "All";
    public bool IsPureModemSelected => PureCategoryFilter == "ModemAt";
    public bool IsPureMtkSelected => PureCategoryFilter == "MediaTek";
    public bool IsPureQualcommSelected => PureCategoryFilter == "Qualcomm";
    public bool IsPureAppleSelected => PureCategoryFilter == "AppleIos";
    public bool IsPureAdbSelected => PureCategoryFilter == "AdbFastboot";
    public bool IsPureOtherSelected => PureCategoryFilter == "OtherCommands";

    public int PureModemCount => PurePhoneTestableEvents.Count(e => e.CommandGroup == L24CommandGroup.ModemAt);
    public int PureMtkCount => PurePhoneTestableEvents.Count(e => e.CommandGroup == L24CommandGroup.MediaTek);
    public int PureQualcommCount => PurePhoneTestableEvents.Count(e => e.CommandGroup == L24CommandGroup.Qualcomm);
    public int PureAppleCount => PurePhoneTestableEvents.Count(e => e.CommandGroup == L24CommandGroup.AppleIos);
    public int PureAdbCount => PurePhoneTestableEvents.Count(e => e.CommandGroup == L24CommandGroup.AdbFastboot);
    public int PureOtherCount => PurePhoneTestableEvents.Count(e => e.CommandGroup != L24CommandGroup.ModemAt &&
                                                                   e.CommandGroup != L24CommandGroup.MediaTek &&
                                                                   e.CommandGroup != L24CommandGroup.Qualcomm &&
                                                                   e.CommandGroup != L24CommandGroup.AppleIos &&
                                                                   e.CommandGroup != L24CommandGroup.AdbFastboot);

    public string PureAllButtonText => $"🌐 الكل ({PurePhoneCommandsCount})";
    public string PureModemButtonText => $"📻 المودم ({PureModemCount})";
    public string PureMtkButtonText => $"🔶 ميدياتك ({PureMtkCount})";
    public string PureQualcommButtonText => $"🔷 كوالكوم ({PureQualcommCount})";
    public string PureAppleButtonText => $"🍎 أبل ({PureAppleCount})";
    public string PureAdbButtonText => $"🤖 ADB ({PureAdbCount})";
    public string PureOtherButtonText => $"🧩 أخرى ({PureOtherCount})";

    public void UpdatePureCategoryCounters()
    {
        OnPropertyChanged(nameof(PureModemCount));
        OnPropertyChanged(nameof(PureMtkCount));
        OnPropertyChanged(nameof(PureQualcommCount));
        OnPropertyChanged(nameof(PureAppleCount));
        OnPropertyChanged(nameof(PureAdbCount));
        OnPropertyChanged(nameof(PureOtherCount));

        OnPropertyChanged(nameof(PureAllButtonText));
        OnPropertyChanged(nameof(PureModemButtonText));
        OnPropertyChanged(nameof(PureMtkButtonText));
        OnPropertyChanged(nameof(PureQualcommButtonText));
        OnPropertyChanged(nameof(PureAppleButtonText));
        OnPropertyChanged(nameof(PureAdbButtonText));
        OnPropertyChanged(nameof(PureOtherButtonText));
    }

    private bool FilterExecutedDeviceItem(object obj)
    {
        if (obj is not SourceTelemetryEvent item) return false;

        if (item.CommandGroup == L24CommandGroup.ServerCloudLogin || L24CommandClassifier.IsUrlOrNetworkOrAuth(item))
            return false;

        if (item.CommandGroup == L24CommandGroup.AdbFastboot && !_orchestrator.IsCategoryDetectionEnabled(L24CommandGroup.AdbFastboot))
            return false;

        if (!FilterCommonItem(item)) return false;

        if (_executedCategoryFilter != "All")
        {
            if (_executedCategoryFilter == "OtherCommands")
            {
                if (item.CommandGroup == L24CommandGroup.ModemAt ||
                    item.CommandGroup == L24CommandGroup.MediaTek ||
                    item.CommandGroup == L24CommandGroup.Qualcomm ||
                    item.CommandGroup == L24CommandGroup.AppleIos ||
                    item.CommandGroup == L24CommandGroup.AdbFastboot)
                    return false;
            }
            else if (Enum.TryParse<L24CommandGroup>(_executedCategoryFilter, out var grp))
            {
                if (item.CommandGroup != grp) return false;
            }
        }

        return true;
    }

    private bool FilterPurePhoneItem(object obj)
    {
        if (obj is not SourceTelemetryEvent item) return false;
        if (!FilterCommonItem(item)) return false;

        if (_pureCategoryFilter != "All")
        {
            if (_pureCategoryFilter == "OtherCommands")
            {
                if (item.CommandGroup == L24CommandGroup.ModemAt ||
                    item.CommandGroup == L24CommandGroup.MediaTek ||
                    item.CommandGroup == L24CommandGroup.Qualcomm ||
                    item.CommandGroup == L24CommandGroup.AppleIos ||
                    item.CommandGroup == L24CommandGroup.AdbFastboot)
                    return false;
            }
            else if (Enum.TryParse<L24CommandGroup>(_pureCategoryFilter, out var grp))
            {
                if (item.CommandGroup != grp) return false;
            }
        }

        return true;
    }

    private bool FilterCommonItem(object obj)
    {
        if (obj is not SourceTelemetryEvent item) return false;
        if (!ShowPhoneResponses && item.IsPhoneResponse) return false;

        if (!string.IsNullOrWhiteSpace(_activeOriginFilter))
        {
            bool originMatches = item.CallerModuleOrigin.Contains(_activeOriginFilter, StringComparison.OrdinalIgnoreCase)
                              || item.TargetResource.Contains(_activeOriginFilter, StringComparison.OrdinalIgnoreCase);
            if (!originMatches) return false;
        }

        if (!string.IsNullOrWhiteSpace(_searchText))
        {
            string q = _searchText.Trim();
            return item.DecodedCommandText.Contains(q, StringComparison.OrdinalIgnoreCase)
                || item.PureCommandText.Contains(q, StringComparison.OrdinalIgnoreCase)
                || item.TargetResource.Contains(q, StringComparison.OrdinalIgnoreCase)
                || item.CallerModuleOrigin.Contains(q, StringComparison.OrdinalIgnoreCase)
                || item.CommandCategory.Contains(q, StringComparison.OrdinalIgnoreCase);
        }

        return true;
    }

    private bool FilterDiscoveredRamItem(object obj)
    {
        if (obj is not SourceTelemetryEvent item) return false;
        if (!FilterCommonItem(item)) return false;

        if (!_orchestrator.IsCategoryDetectionEnabled(item.CommandGroup))
            return false;

        if (ExcludeUrlsFromDiscovered && (item.CommandGroup == L24CommandGroup.ServerCloudLogin || L24CommandClassifier.IsUrlOrNetworkOrAuth(item)))
            return false;

        if (_discoveredCategoryFilter != "All" && Enum.TryParse<L24CommandGroup>(_discoveredCategoryFilter, out var grp))
        {
            if (item.CommandGroup != grp) return false;
        }
        return true;
    }

    private bool FilterUnfilteredRawItem(object obj)
    {
        if (obj is not SourceTelemetryEvent item) return false;

        if (ExcludeUrlsFromRawLog && (item.CommandGroup == L24CommandGroup.ServerCloudLogin || L24CommandClassifier.IsUrlOrNetworkOrAuth(item)))
            return false;

        if (string.IsNullOrWhiteSpace(_searchText)) return true;

        string q = _searchText.Trim();
        return item.DecodedCommandText.Contains(q, StringComparison.OrdinalIgnoreCase)
            || item.PureCommandText.Contains(q, StringComparison.OrdinalIgnoreCase)
            || item.TargetResource.Contains(q, StringComparison.OrdinalIgnoreCase)
            || item.CallerModuleOrigin.Contains(q, StringComparison.OrdinalIgnoreCase)
            || item.CommandCategory.Contains(q, StringComparison.OrdinalIgnoreCase)
            || item.HookedApiName.Contains(q, StringComparison.OrdinalIgnoreCase);
    }
}
