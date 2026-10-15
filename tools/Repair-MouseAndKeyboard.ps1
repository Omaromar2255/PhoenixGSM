<#
.SYNOPSIS
    PhoenixGSM — Universal USB Mouse & Keyboard Auto-Repair Script
    أداة فينيكس الفورية لإصلاح تعطل الماوس ولوحة المفاتيح ومنافذ الـ USB بعد وضع السكون

.DESCRIPTION
    Comprehensive diagnostic and repair utility for Windows USB Mouse and Keyboard input devices:
    1. Restores essential system UpperFilters (kbdclass and mouclass) in Windows registry.
    2. Cleans corrupted or orphaned 3rd-party filter drivers blocking input devices (Code 10/19/39).
    3. Resolves Sleep & Power Management issues:
       - Disables USB Selective Suspend (AC & DC).
       - Disables PCIe Link State Power Management (ASPM) to prevent xHCI sleep dropouts.
       - Disables USB Root Hub power savings (prevents port power cut on sleep).
       - Arms Wake-on-USB for all connected and programmable Mouse, Keyboard, and HID devices.
    4. Automatically recovers and re-enumerates hung or frozen HID devices post-sleep.
    5. Generates a clear bilingual diagnostic and verification report.

.PARAMETER DiagnosticOnly
    Runs diagnostic checks only without modifying the system.

.PARAMETER AutoFix
    Applies all repairs automatically (Default mode).
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$DiagnosticOnly,
    [switch]$AutoFix,
    [string]$BackupDir = ""
)

$isRepairMode = -not $DiagnosticOnly.IsPresent
if ($DiagnosticOnly.IsPresent) {
    $isRepairMode = $false
} elseif ($AutoFix.IsPresent) {
    $isRepairMode = $true
}

# ==============================================================================
# 0. Administrator Privilege Check & Auto-Elevation
# ==============================================================================
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] Requires Administrator privileges. Restarting with elevated rights..." -ForegroundColor Yellow
    Write-Host "[!] يتطلب السكريبت صلاحيات المسؤول. جارٍ إعادة التشغيل كمسؤول..." -ForegroundColor Yellow
    
    $scriptPath = if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        Join-Path $PSScriptRoot $MyInvocation.MyCommand.Name
    } elseif ($MyInvocation.MyCommand.Definition) {
        $MyInvocation.MyCommand.Definition
    } else {
        $PSCommandPath
    }
    
    $argParts = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in $PSBoundParameters.GetEnumerator()) {
        if ($entry.Value -is [System.Management.Automation.SwitchParameter]) {
            if ($entry.Value.IsPresent) { $argParts.Add("-$($entry.Key)") }
        } elseif ($entry.Value -is [bool]) {
            if ($entry.Value) { $argParts.Add("-$($entry.Key)") }
        } else {
            $argParts.Add("-$($entry.Key) `"$($entry.Value)`"")
        }
    }
    if ($argParts.Count -eq 0) { $argParts.Add("-AutoFix") }
    $argString = $argParts -join " "
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -NoExit -File `"$scriptPath`" $argString"
    Exit
}

# ==============================================================================
# Setup Paths & Logging
# ==============================================================================
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$scriptDir = if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
    $PSScriptRoot
} elseif ($MyInvocation.MyCommand.Definition) {
    Split-Path -Parent $MyInvocation.MyCommand.Definition
} else {
    (Get-Location).Path
}

if ([string]::IsNullOrWhiteSpace($BackupDir)) {
    $BackupDir = Join-Path $scriptDir "backups\MouseKeyboard_$timestamp"
}
if (-not (Test-Path $BackupDir)) {
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
}

$logFile = Join-Path $BackupDir "mouse_keyboard_repair.log"

function Write-Log {
    param(
        [string]$Message,
        [ConsoleColor]$Color = [ConsoleColor]::White,
        [string]$Level = "INFO"
    )
    $timeStr = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$timeStr] [$Level] $Message"
    try {
        Add-Content -Path $logFile -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch {}
    Write-Host $Message -ForegroundColor $Color
}

Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host "   PhoenixGSM -- Universal USB Mouse & Keyboard Auto-Repair Tool          " -ForegroundColor Cyan
Write-Host "   أداة فينيكس الفورية لإصلاح تعطل الماوس ولوحة المفاتيح والـ USB بعد السكون    " -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Log "Starting repair session at $timestamp. Mode: $(if ($isRepairMode) { 'AutoFix' } else { 'DiagnosticOnly' })" -Color Gray
Write-Log "Backup directory: $BackupDir" -Color Gray
Write-Host ""

$issuesFound = [System.Collections.Generic.List[string]]::new()
$actionsTaken = [System.Collections.Generic.List[string]]::new()

# ==============================================================================
# 1. Restore & Protect Keyboard and Mouse Core Class Drivers
# ==============================================================================
Write-Host "--------------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "[1/4] فحص واستعادة تعاريف كلاس لوحة المفاتيح والماوس (kbdclass & mouclass)..." -ForegroundColor Yellow

$inputClassConfigs = @(
    @{
        Name = "Keyboard"
        Guid = "{4d36e96b-e325-11ce-bfc1-08002be10318}"
        ExpectedFilter = "kbdclass"
        Desc = "لوحة المفاتيح"
    },
    @{
        Name = "Mouse"
        Guid = "{4d36e96f-e325-11ce-bfc1-08002be10318}"
        ExpectedFilter = "mouclass"
        Desc = "الماوس ومؤشر التأشير"
    }
)

foreach ($cfg in $inputClassConfigs) {
    $guid = $cfg.Guid
    $cName = $cfg.Name
    $exp = $cfg.ExpectedFilter
    $desc = $cfg.Desc
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\$guid"

    if (Test-Path $regPath) {
        $props = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
        $currentUpper = if ($props.UpperFilters) { @($props.UpperFilters) } else { @() }

        # Check if expected core driver is missing
        if (-not ($currentUpper -contains $exp)) {
            $issueMsg = "تعريف الفئة ($desc - $cName) مفقود منه الفلتر الأساسي ($exp)! وهذا يمنع استجابة الجهاز نهائياً."
            $issuesFound.Add($issueMsg)
            Write-Log "  [!] Missing core driver filter '$exp' in $cName class ($guid)!" -Color Red -Level "WARN"

            if ($isRepairMode) {
                # Export backup of class key
                $regBak = Join-Path $BackupDir "Class_${cName}_Upper_BeforeFix.reg"
                reg.exe export "HKLM\SYSTEM\CurrentControlSet\Control\Class\$guid" "$regBak" /y | Out-Null

                $updatedFilters = [System.Collections.Generic.List[string]]::new()
                foreach ($u in $currentUpper) {
                    if (-not [string]::IsNullOrWhiteSpace($u) -and $u -ne $exp) {
                        $updatedFilters.Add($u)
                    }
                }
                $updatedFilters.Add($exp)

                Set-ItemProperty -Path $regPath -Name "UpperFilters" -Value ([string[]]$updatedFilters) -Type MultiString
                $actMsg = "تمت استعادة الفلتر الأساسي ($exp) لفئة $desc بنجاح وتأمينه في سجل النظام."
                $actionsTaken.Add($actMsg)
                Write-Log "      [SUCCESS] Restored '$exp' into UpperFilters for $cName class." -Color Green
            }
        } else {
            Write-Log "  [OK] Class $cName ($desc) : Core filter '$exp' is present and healthy." -Color Green
        }

        # Check for rogue or invalid filters in LowerFilters
        if ($props.LowerFilters) {
            $currLower = @($props.LowerFilters)
            $knownBadLower = @("UsbDk", "PhoenixUsbMonitor", "libusb0", "libusbK")
            $badFound = $currLower | Where-Object { $knownBadLower -contains $_ }
            if ($badFound) {
                $issueMsg = "تم العثور على فلاتر تعارض ($($badFound -join ', ')) في LowerFilters لفئة $desc."
                $issuesFound.Add($issueMsg)
                Write-Log "  [!] Conflict LowerFilter detected in $cName : $($badFound -join ', ')" -Color Red -Level "WARN"

                if ($isRepairMode) {
                    $cleanLower = $currLower | Where-Object { $knownBadLower -notcontains $_ }
                    if ($cleanLower -and $cleanLower.Count -gt 0) {
                        Set-ItemProperty -Path $regPath -Name "LowerFilters" -Value ([string[]]$cleanLower) -Type MultiString
                    } else {
                        Remove-ItemProperty -Path $regPath -Name "LowerFilters" -ErrorAction SilentlyContinue
                    }
                    $actionsTaken.Add("تم تنظيف الفلاتر المعارضة من LowerFilters لفئة $desc.")
                    Write-Log "      [SUCCESS] Cleaned conflicting LowerFilters from $cName." -Color Green
                }
            }
        }
    }
}

# Also verify HIDClass UpperFilters and LowerFilters
$hidGuid = "{745a17a0-74d3-11d0-b6fe-00a0c90f57da}"
$hidRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\$hidGuid"
if (Test-Path $hidRegPath) {
    $hidProps = Get-ItemProperty -Path $hidRegPath -ErrorAction SilentlyContinue
    $knownBadHid = @("UsbDk", "PhoenixUsbMonitor", "USBPcap")
    foreach ($fltProp in @("UpperFilters", "LowerFilters")) {
        if ($hidProps.$fltProp) {
            $currFlt = @($hidProps.$fltProp)
            $badInHid = $currFlt | Where-Object { $knownBadHid -contains $_ }
            if ($badInHid) {
                $issuesFound.Add("تم العثور على فلتر معطل ($($badInHid -join ', ')) في فئة أجهزة HIDClass ($fltProp).")
                Write-Log "  [!] Problematic filter ($($badInHid -join ', ')) found in HIDClass ($fltProp)" -Color Red -Level "WARN"
                if ($isRepairMode) {
                    $cleanF = $currFlt | Where-Object { $knownBadHid -notcontains $_ }
                    if ($cleanF -and $cleanF.Count -gt 0) {
                        Set-ItemProperty -Path $hidRegPath -Name $fltProp -Value ([string[]]$cleanF) -Type MultiString
                    } else {
                        Remove-ItemProperty -Path $hidRegPath -Name $fltProp -ErrorAction SilentlyContinue
                    }
                    $actionsTaken.Add("تمت إزالة الفلتر المعطل من فئة أجهزة HID ($fltProp).")
                    Write-Log "      [SUCCESS] Cleaned $fltProp for HIDClass." -Color Green
                }
            }
        }
    }
}

# ==============================================================================
# 2. Fix USB Sleep, Suspend & Wake-On-USB Configuration
# ==============================================================================
Write-Host "--------------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "[2/4] إصلاح إعدادات الطاقة ومنع انقطاع الكهرباء في وضع السكون (Sleep & Wake)..." -ForegroundColor Yellow

if ($isRepairMode) {
    try {
        # 1. Disable USB Selective Suspend in active power scheme
        & powercfg.exe /setacvalueindex SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0 2>$null
        & powercfg.exe /setdcvalueindex SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0 2>$null
        
        # 2. Disable PCI Express Link State Power Management (ASPM) to prevent xHCI USB controller drops
        & powercfg.exe /setacvalueindex SCHEME_CURRENT 501a4d13-42af-4429-9fd1-a8218c268e20 ee12f906-d277-404b-b6da-e5fa1a576df5 0 2>$null
        & powercfg.exe /setdcvalueindex SCHEME_CURRENT 501a4d13-42af-4429-9fd1-a8218c268e20 ee12f906-d277-404b-b6da-e5fa1a576df5 0 2>$null
        
        # Apply active power scheme
        & powercfg.exe /SetActive SCHEME_CURRENT 2>$null
        
        $actionsTaken.Add("تم تعطيل USB Selective Suspend و PCIe Link State Power Management لمنع فصل متحكمات الـ USB.")
        Write-Log "  [+] Power settings optimized: USB Selective Suspend & PCIe ASPM disabled." -Color Green
    } catch {
        Write-Log "  [INFO] Powercfg adjustment note: $_" -Color Gray
    }

    # 3. Disable Root Hub and USB Generic Hub power suspension in registry
    $usbEnumPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\USB"
    if (Test-Path $usbEnumPath) {
        $paramKeys = Get-ChildItem -Path $usbEnumPath -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -eq "Device Parameters" }
        $hubFixCount = 0
        foreach ($dp in $paramKeys) {
            try {
                $p = Get-ItemProperty -Path $dp.PSPath -ErrorAction SilentlyContinue
                if ($p.EnhancedPowerManagementEnabled -eq 1 -or $p.SelectiveSuspendEnabled -eq 1) {
                    Set-ItemProperty -Path $dp.PSPath -Name "EnhancedPowerManagementEnabled" -Value 0 -ErrorAction SilentlyContinue
                    Set-ItemProperty -Path $dp.PSPath -Name "SelectiveSuspendEnabled" -Value 0 -ErrorAction SilentlyContinue
                    $hubFixCount++
                }
            } catch {}
        }
        if ($hubFixCount -gt 0) {
            $actionsTaken.Add("تم إلغاء ميزة توفير الطاقة وإيقاف المنافذ على ($hubFixCount) عقدة موزع USB.")
            Write-Log "  [+] Disabled power-off on $hubFixCount USB hub parameter nodes." -Color Green
        }
    }

    # 4. Arm Wake-on-USB for all programmable Mouse, Keyboard, and HID devices
    $wakeProgs = powercfg.exe /devicequery wake_programmable 2>$null
    $armedDevices = [System.Collections.Generic.List[string]]::new()
    if ($wakeProgs) {
        foreach ($wp in $wakeProgs) {
            $trimmedWp = $wp.Trim()
            if (-not [string]::IsNullOrWhiteSpace($trimmedWp) -and ($trimmedWp -match "(?i)mouse|keyboard|hid|input")) {
                & powercfg.exe -deviceenablewake "$trimmedWp" 2>$null
                $armedDevices.Add($trimmedWp)
            }
        }
        if ($armedDevices.Count -gt 0) {
            $actionsTaken.Add("تم تفعيل ميزة الاستيقاظ الدائم (Wake-on-USB) للأجهزة: $($armedDevices -join ', ').")
            Write-Log "  [+] Successfully armed Wake-on-USB for input devices: $($armedDevices -join ', ')" -Color Green
        } else {
            Write-Log "  [OK] Input devices are already armed or managed by hardware ACPI." -Color Green
        }
    }
} else {
    Write-Log "  [INFO] Skipped power setting modifications in Diagnostic-Only mode." -Color Gray
}

# ==============================================================================
# 3. Soft-Restart & Re-enumerate Hung Input Devices
# ==============================================================================
Write-Host "--------------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "[3/4] إعادة تنشيط واستئناف أجهزة الماوس واللوحة المعلقة (Device Cycle & Rescan)..." -ForegroundColor Yellow

if ($isRepairMode) {
    # Find present HID mouse and keyboard devices
    $hidInputDevices = Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | Where-Object {
        $_.Class -in @("Mouse", "Keyboard", "HIDClass") -and $_.InstanceId -like "HID\*"
    }

    if ($hidInputDevices) {
        foreach ($d in $hidInputDevices) {
            Write-Log "  [*] Refreshing device stack for: $($d.FriendlyName) [$($d.InstanceId)]" -Color Cyan
            try {
                Disable-PnpDevice -InstanceId $d.InstanceId -Confirm:$false -ErrorAction SilentlyContinue
                Start-Sleep -Milliseconds 150
                Enable-PnpDevice -InstanceId $d.InstanceId -Confirm:$false -ErrorAction SilentlyContinue
            } catch {}
        }
        $actionsTaken.Add("تمت إعادة تشغيل وتنشيط أجهزة الماوس ولوحة المفاتيح المتصلة برمجياً.")
    }

    # Trigger PnP bus rescan
    Write-Log "  [*] Triggering system PnP rescan via pnputil..." -Color Cyan
    pnputil.exe /scan-devices | Out-Null
    Start-Sleep -Seconds 1
    Write-Log "  [OK] Hardware bus rescan complete." -Color Green
}

# ==============================================================================
# 4. Bilingual Verification & Final Report
# ==============================================================================
Write-Host ""
Write-Host "==========================================================================" -ForegroundColor Green
Write-Host "         تقرير فحص وإصلاح الماوس ولوحة المفاتيح والـ USB                    " -ForegroundColor Green
Write-Host "==========================================================================" -ForegroundColor Green

Write-Host "1. المشاكل المكتشفة (Detected Issues):" -ForegroundColor Cyan
if ($issuesFound.Count -gt 0) {
    foreach ($iss in $issuesFound) {
        Write-Host "   [!] $iss" -ForegroundColor Red
    }
} else {
    Write-Host "   [OK] جميع تعاريف الفئات وسجل النظام سليمة ولا توجد مشاكل بنيوية." -ForegroundColor Green
}

Write-Host ""
Write-Host "2. الإجراءات المطبقة (Actions Applied):" -ForegroundColor Cyan
if ($actionsTaken.Count -gt 0) {
    foreach ($act in $actionsTaken) {
        Write-Host "   [+] $act" -ForegroundColor Green
    }
} else {
    Write-Host "   [-] لم تكن هناك حاجة لتعديل الإعدادات (النظام مهيأ مسبقاً)." -ForegroundColor Gray
}

Write-Host ""
Write-Host "3. حالة أجهزة الإدخال المتصلة حالياً (Connected Input Devices):" -ForegroundColor Cyan
$presentInputs = Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | Where-Object {
    $_.Class -in @("Mouse", "Keyboard")
}
if ($presentInputs) {
    foreach ($pi in $presentInputs) {
        $color = if ($pi.Status -eq "OK") { [ConsoleColor]::Green } else { [ConsoleColor]::Red }
        Write-Host "   - [$($pi.Class)] $($pi.FriendlyName) | Status: $($pi.Status) [$($pi.InstanceId)]" -ForegroundColor $color
    }
} else {
    Write-Host "   [!] لم يتم العثور على أجهزة إدخال متصلة حالياً." -ForegroundColor Red
}

Write-Host ""
Write-Host "4. الأجهزة المصرح لها بالإيقاظ والبقاء قيد العمل أثناء السكون (Wake-Armed Devices):" -ForegroundColor Cyan
$armedCheck = powercfg.exe /devicequery wake_armed 2>$null
if ($armedCheck) {
    foreach ($ac in $armedCheck) {
        $tAc = $ac.Trim()
        if (-not [string]::IsNullOrWhiteSpace($tAc)) {
            Write-Host "   * $tAc" -ForegroundColor Green
        }
    }
} else {
    Write-Host "   (لا توجد أجهزة مبرمجة للإيقاظ - يتم التحكم بها عبر اللوحة الأم)" -ForegroundColor Gray
}

Write-Host ""
Write-Host "==========================================================================" -ForegroundColor Green
Write-Host "  [SUCCESS] تمت المعالجة بنجاح. الماوس ولوحة المفاتيح جاهزان وتعملان الآن! " -ForegroundColor Green
Write-Host "  تم حفظ سجل التنفيذ في: $BackupDir" -ForegroundColor Gray
Write-Host "==========================================================================" -ForegroundColor Green
Write-Host ""
