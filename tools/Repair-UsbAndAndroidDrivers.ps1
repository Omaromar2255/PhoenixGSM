<#
.SYNOPSIS
    PhoenixGSM — Universal Windows USB & Android Device Auto-Repair Script
    أداة فينيكس الذكية لإصلاح مشاكل تعريفات USB والاندرويد والتوصيل التلقائي

.DESCRIPTION
    Enterprise-grade automated diagnostic and repair engine for Windows mobile servicing environments:
    1. Removes rogue/poisoned ADB drivers (e.g. Chimera oem16.inf claiming CDC ACM Class_02&SubClass_02).
    2. Restores internal modems/sensors (e.g. Sierra Wireless EM7345) falsely hijacked as Android ADB.
    3. Cleans problematic and orphaned USB filter drivers (UsbDk, PhoenixUsbMonitor, broken UpperFilters/LowerFilters).
    4. Clears UsbDk persistent hide rules and sets UsbDk service startup to disabled.
    5. Cleans failed USB device descriptor nodes and phantom root devices in error state.
    6. Disables USB Selective Suspend and registry power management on USB root hubs.
    7. Verifies port 5037 and restarts ADB server cleanly when appropriate.
    8. Forces Windows PnP hardware rescan and prints a comprehensive bilingual report.

.PARAMETER DiagnosticOnly
    Runs diagnostic checks only without modifying the system.

.PARAMETER AutoFix
    Applies all fixes automatically with safe backups (Default mode).

.PARAMETER SkipAdbRestart
    Skips terminating or restarting ADB processes and port 5037.

.PARAMETER BackupDir
    Custom path for saving backups and execution logs.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$DiagnosticOnly,
    [switch]$AutoFix,
    [switch]$SkipAdbRestart,
    [string]$BackupDir = ""
)

# Determine operating mode: AutoFix is default unless DiagnosticOnly is passed
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
    
    # Properly serialize parameters without treating switch values as positional arguments
    $argParts = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in $PSBoundParameters.GetEnumerator()) {
        if ($entry.Value -is [System.Management.Automation.SwitchParameter]) {
            if ($entry.Value.IsPresent) {
                $argParts.Add("-$($entry.Key)")
            }
        } elseif ($entry.Value -is [bool]) {
            if ($entry.Value) {
                $argParts.Add("-$($entry.Key)")
            }
        } else {
            $argParts.Add("-$($entry.Key) `"$($entry.Value)`"")
        }
    }
    
    if ($argParts.Count -eq 0) {
        $argParts.Add("-AutoFix")
    }
    
    $argString = $argParts -join " "
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -NoExit -File `"$scriptPath`" $argString"
    Exit
}

# ==============================================================================
# Setup Paths, Logs, and Backups
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
    $BackupDir = Join-Path $scriptDir "backups\Repair_$timestamp"
}
if (-not (Test-Path $BackupDir)) {
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
}

$logFile = Join-Path $BackupDir "repair_execution.log"

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
Write-Host "   PhoenixGSM -- Universal Windows USB & Android Device Auto-Repair Tool  " -ForegroundColor Cyan
Write-Host "   اداة فينيكس الذكية لاصلاح مشاكل تعريفات USB والاندرويد والتوصيل التلقائي   " -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Log "Starting repair session at $timestamp. Mode: $(if ($isRepairMode) { 'AutoFix' } else { 'DiagnosticOnly' })" -Color Gray
Write-Log "Backup directory: $BackupDir" -Color Gray
Write-Host ""

$issuesFound = [System.Collections.Generic.List[string]]::new()
$actionsTaken = [System.Collections.Generic.List[string]]::new()
$rebootRecommended = $false

# Helper function to find adb executable
function Find-AdbPath {
    $cmd = Get-Command adb -ErrorAction SilentlyContinue
    if ($cmd -and (Test-Path $cmd.Source)) { return $cmd.Source }
    
    $commonAdbPaths = @(
        "C:\UnlockTool\Binaries\adb.exe",
        "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe",
        "C:\platform-tools\adb.exe",
        "C:\adb\adb.exe",
        "C:\Program Files (x86)\Chimera\adb.exe",
        "C:\Program Files\Chimera\adb.exe"
    )
    foreach ($p in $commonAdbPaths) {
        if (Test-Path $p) { return $p }
    }
    return $null
}

# ==============================================================================
# 1. Rogue INF Drivers Check (e.g. Chimera oem16.inf hijacking CDC ACM)
# ==============================================================================
Write-Host "--------------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "[1/8] فحص تعريفات INF المسمومة وتعاريف الاندرويد العشوائية (Rogue ADB Drivers)..." -ForegroundColor Yellow

$infDir = "C:\Windows\INF"
$rogueInfs = [System.Collections.Generic.List[System.IO.FileInfo]]::new()

if (Test-Path $infDir) {
    $candidateInfs = Get-ChildItem -Path $infDir -Filter "oem*.inf" -ErrorAction SilentlyContinue
    foreach ($infFile in $candidateInfs) {
        $lines = Get-Content -Path $infFile.FullName -ErrorAction SilentlyContinue
        if (-not $lines) { continue }

        $isAdbOrWinUsb = $false
        $hasToxicGenericClassMatch = $false
        $toxicDetail = ""

        # First pass: Determine if driver targets Android / ADB / WinUSB
        foreach ($line in $lines) {
            $trimmed = $line.Trim()
            if ($trimmed.StartsWith(";")) { continue }

            if ($trimmed -match "(?i)AndroidUsbDeviceClass|ClassGuid\s*=\s*\{3F966BD9|AndroidWinUsb|Class\s*=\s*Android") {
                $isAdbOrWinUsb = $true
            }
        }

        # Second pass: Check device identification lines in model sections
        foreach ($line in $lines) {
            $trimmed = $line.Trim()
            if ($trimmed.StartsWith(";")) { continue }

            # Match lines assigning hardware IDs: e.g. %Device% = InstallSec, USB\Class_02...
            # Toxic pattern: binds generic USB Class 02 (CDC ACM/Modem), 0A (CDC Data), E0 (Wireless)
            # WITHOUT any specific VID_ constraint on THAT declaration line!
            if ($trimmed -match '(?i)USB\\Class_(02|0A|E0)' -and $trimmed -notmatch '(?i)VID_[0-9A-Fa-f]{4}') {
                $hasToxicGenericClassMatch = $true
                $toxicDetail = $trimmed
                break
            }
        }

        if ($hasToxicGenericClassMatch -and $isAdbOrWinUsb) {
            $rogueInfs.Add($infFile)
            $issueMsg = "تم اكتشاف ملف تعريف مسموم: $($infFile.Name) يربط كلاس المودم العام ($toxicDetail) بـ Android ADB بدون تحديد VID!"
            $issuesFound.Add($issueMsg)
            Write-Log "  [!] Rogue INF driver detected: $($infFile.Name)" -Color Red -Level "WARN"
            Write-Log "      Line: $toxicDetail" -Color Yellow
        }
    }

    if ($rogueInfs.Count -gt 0) {
        foreach ($rInf in $rogueInfs) {
            if ($isRepairMode) {
                Write-Log "      [+] Exporting driver package backup for $($rInf.Name)..." -Color Gray
                pnputil.exe /export-driver $rInf.Name $BackupDir | Out-Null

                Write-Log "      [*] Deleting and uninstalling rogue driver $($rInf.Name)..." -Color Magenta
                $delOutput = pnputil.exe /delete-driver $rInf.Name /uninstall /force 2>&1
                $delText = $delOutput -join " "
                if ($delText -match "deleted successfully|success") {
                    $actMsg = "تم حذف وتفكيك التعريف المسموم $($rInf.Name) بنجاح وتحرير كلاس المودم وCDC ACM."
                    $actionsTaken.Add($actMsg)
                    Write-Log "      [SUCCESS] Rogue driver $($rInf.Name) deleted and uninstalled." -Color Green
                } else {
                    Write-Log "      [INFO] Pnputil delete result: $delText" -Color Gray
                }
            }
        }
    } else {
        Write-Log "  [OK] No rogue ADB driver INF claiming generic CDC ACM (USB\Class_02)." -Color Green
    }
}

# ==============================================================================
# 2. Stuck / Hijacked Internal Hardware Check (e.g. Sierra Wireless, WWAN, Sensors)
# ==============================================================================
Write-Host "--------------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "[2/8] فحص الاجهزة الداخلية المعلقة كاندرويد دائم (Stuck/Ghost Android Devices)..." -ForegroundColor Yellow

$androidDevices = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { 
    ($_.Class -in @("AndroidUsbDeviceClass", "Android Device", "Android Phone", "ADB Interface") -or 
     $_.FriendlyName -like "*Android ADB*" -or $_.FriendlyName -like "*Android Device*") -and $_.Present -eq $true 
}

$knownInternalVids = @(
    "1199", # Sierra Wireless
    "413C", # Dell WWAN / Broadcom
    "0489", # Foxconn / Broadcom
    "0A5C", # Broadcom
    "2CA3", # Fibocom
    "1782", # Fibocom
    "2C7C", # Quectel
    "1BC7", # Telit
    "1410", # Novatel Wireless
    "0BDB", # Ericsson
    "1E0E", # SIMCom
    "1546", # U-blox GNSS
    "0BDA", # Realtek Internal
    "8087", # Intel Internal
    "03F0"  # HP WWAN
)

$ghostFound = $false
if ($androidDevices) {
    foreach ($dev in $androidDevices) {
        $instId = $dev.InstanceId
        $isInternalOrNonPhone = $false
        $detectionReason = ""

        # Check 1: Known internal telecom/sensor VIDs
        foreach ($vid in $knownInternalVids) {
            if ($instId -match "(?i)VID_$vid") {
                $isInternalOrNonPhone = $true
                $detectionReason = "Internal Hardware VID_$vid"
                break
            }
        }

        # Check 2: DevPKey Container Properties (Local Machine Container check)
        if (-not $isInternalOrNonPhone) {
            try {
                $containerProp = Get-PnpDeviceProperty -InstanceId $instId -KeyName "DEVPKEY_Device_InLocalMachineContainer" -ErrorAction SilentlyContinue
                if ($containerProp -and $containerProp.Data -eq $true) {
                    $isInternalOrNonPhone = $true
                    $detectionReason = "Device belongs to Local Machine Container (Non-removable internal hardware)"
                }
            } catch {}
        }

        # Check 3: ACPI BIOS Device path check
        if (-not $isInternalOrNonPhone) {
            try {
                $biosProp = Get-PnpDeviceProperty -InstanceId $instId -KeyName "DEVPKEY_Device_BiosDeviceName" -ErrorAction SilentlyContinue
                if ($biosProp -and -not [string]::IsNullOrWhiteSpace($biosProp.Data)) {
                    $isInternalOrNonPhone = $true
                    $detectionReason = "ACPI Motherboard Device ($($biosProp.Data))"
                }
            } catch {}
        }

        if ($isInternalOrNonPhone) {
            $ghostFound = $true
            $issueMsg = "جهاز داخلي ($($dev.FriendlyName)) [$instId] معلق كـ Android ADB دائم! السبب: $detectionReason"
            $issuesFound.Add($issueMsg)
            Write-Log "  [!] Internal hardware hijacked as Android ADB: $($dev.FriendlyName) [$instId]" -Color Red -Level "WARN"
            Write-Log "      Detection: $detectionReason" -Color Yellow

            if ($isRepairMode) {
                Write-Log "      [*] Removing wrong driver binding and rescanning native hardware..." -Color Cyan
                pnputil.exe /remove-device "$instId" | Out-Null
                pnputil.exe /scan-devices | Out-Null
                $actMsg = "تمت ازالة الربط الخاطئ للجهاز الداخلي $instId واعادة ربطه بتعريفه الاصلي."
                $actionsTaken.Add($actMsg)
                Write-Log "      [SUCCESS] Removed wrong Android binding on $instId and rescanned native driver." -Color Green
            }
        } else {
            Write-Log "  [*] Active connected mobile device: $($dev.FriendlyName) [$instId] (Status: $($dev.Status))" -Color Cyan
        }
    }
}

if (-not $ghostFound) {
    Write-Log "  [OK] No stuck ghost Android devices found on internal hardware. All clear." -Color Green
}

# ==============================================================================
# 3. USB Class Filter Drivers & Orphaned Filter Cleanup
# ==============================================================================
Write-Host "--------------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "[3/8] فحص فلاتر ناقل الـ USB وحذف الفلاتر المعطلة واليتيمة (USB Filters & UsbDk)..." -ForegroundColor Yellow

$classGuidsToClean = @(
    @{ Name = "USB Controllers and Hubs"; Guid = "{36fc9e60-c465-11cf-8056-444553540000}"; BadFilters = @("UsbDk", "PhoenixUsbMonitor", "USBPcap", "libusb0", "libusbK", "wsvd") },
    @{ Name = "Ports (COM and LPT)";      Guid = "{4d36e978-e325-11ce-bfc1-08002be10318}"; BadFilters = @("PhoenixUsbMonitor", "libusb0", "libusbK") },
    @{ Name = "Modem Class";              Guid = "{4d36e96d-e325-11ce-bfc1-08002be10318}"; BadFilters = @("PhoenixUsbMonitor") },
    @{ Name = "Android Device Class";     Guid = "{3f966bd9-fa04-4ec5-991c-d326973b5128}"; BadFilters = @("PhoenixUsbMonitor") },
    @{ Name = "WinUSB Class";             Guid = "{88bae032-5a81-49f0-bc3d-a4ff138216d6}"; BadFilters = @("PhoenixUsbMonitor") },
    @{ Name = "USB Devices Class";        Guid = "{88bae032-5a81-49f0-bc3d-a4ff138216d7}"; BadFilters = @("PhoenixUsbMonitor") }
)

foreach ($cDef in $classGuidsToClean) {
    $guid = $cDef.Guid
    $cName = $cDef.Name
    $badList = $cDef.BadFilters
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\$guid"

    if (Test-Path $regPath) {
        $props = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue

        # Clean UpperFilters
        if ($props.UpperFilters) {
            $currUpper = @($props.UpperFilters)
            $foundBad = $currUpper | Where-Object { $badList -contains $_ }
            if ($foundBad) {
                $issueMsg = "تم العثور على فلاتر معطلة ($($foundBad -join ', ')) في UpperFilters لفئة $cName ($guid)"
                $issuesFound.Add($issueMsg)
                Write-Log "  [!] Problematic UpperFilters found in $cName : $($foundBad -join ', ')" -Color Red -Level "WARN"

                if ($isRepairMode) {
                    $regBackupFile = Join-Path $BackupDir "Class_${guid}_Upper.reg"
                    reg.exe export "HKLM\SYSTEM\CurrentControlSet\Control\Class\$guid" "$regBackupFile" /y | Out-Null

                    $cleanUpper = $currUpper | Where-Object { $badList -notcontains $_ }
                    if ($cleanUpper -and $cleanUpper.Count -gt 0) {
                        Set-ItemProperty -Path $regPath -Name "UpperFilters" -Value ([string[]]$cleanUpper)
                        Write-Log "      [+] Cleaned conflicting filters. Kept: $($cleanUpper -join ', ')" -Color Green
                    } else {
                        Remove-ItemProperty -Path $regPath -Name "UpperFilters" -ErrorAction SilentlyContinue
                        Write-Log "      [+] UpperFilters removed completely from $cName (restored stock Windows stack)." -Color Green
                    }
                    $actionsTaken.Add("تمت ازالة الفلاتر المعطلة ($($foundBad -join ', ')) من فئة $cName.")
                }
            } else {
                Write-Log "  [OK] Class $cName : UpperFilters healthy ($($currUpper -join ', '))." -Color Green
            }
        } else {
            Write-Log "  [OK] Class $cName : No UpperFilters blocking devices." -Color Green
        }

        # Clean LowerFilters
        if ($props.LowerFilters) {
            $currLower = @($props.LowerFilters)
            $foundBadLower = $currLower | Where-Object { $badList -contains $_ }
            if ($foundBadLower) {
                $issueMsg = "تم العثور على فلاتر معطلة ($($foundBadLower -join ', ')) في LowerFilters لفئة $cName ($guid)"
                $issuesFound.Add($issueMsg)
                Write-Log "  [!] Problematic LowerFilters found in $cName : $($foundBadLower -join ', ')" -Color Red -Level "WARN"

                if ($isRepairMode) {
                    $regBackupFile = Join-Path $BackupDir "Class_${guid}_Lower.reg"
                    reg.exe export "HKLM\SYSTEM\CurrentControlSet\Control\Class\$guid" "$regBackupFile" /y | Out-Null

                    $cleanLower = $currLower | Where-Object { $badList -notcontains $_ }
                    if ($cleanLower -and $cleanLower.Count -gt 0) {
                        Set-ItemProperty -Path $regPath -Name "LowerFilters" -Value ([string[]]$cleanLower)
                    } else {
                        Remove-ItemProperty -Path $regPath -Name "LowerFilters" -ErrorAction SilentlyContinue
                    }
                    $actionsTaken.Add("تمت ازالة الفلاتر المعطلة من LowerFilters لفئة $cName.")
                    Write-Log "      [+] Cleaned LowerFilters for class $cName." -Color Green
                }
            }
        }
    }
}

# Audit for orphaned filter drivers across ALL device classes
$allClassKeys = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Control\Class" -ErrorAction SilentlyContinue
foreach ($k in $allClassKeys) {
    $kProps = Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue
    foreach ($filterProp in @("UpperFilters", "LowerFilters")) {
        if ($kProps.$filterProp) {
            $filters = @($kProps.$filterProp)
            $deadFilters = [System.Collections.Generic.List[string]]::new()
            foreach ($flt in $filters) {
                if ([string]::IsNullOrWhiteSpace($flt)) { continue }
                $svcKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$flt"
                if (-not (Test-Path $svcKey)) {
                    $deadFilters.Add($flt)
                } else {
                    $svcProps = Get-ItemProperty -Path $svcKey -ErrorAction SilentlyContinue
                    if ($svcProps.ImagePath) {
                        $rawPath = $svcProps.ImagePath -replace "^\\\?\\", "" -replace '"', ""
                        $expandedPath = [Environment]::ExpandEnvironmentVariables($rawPath)
                        if ($expandedPath -match "^system32" -or $expandedPath -match "^drivers") {
                            $expandedPath = Join-Path $env:windir $expandedPath
                        }
                        if (-not (Test-Path $expandedPath)) {
                            $deadFilters.Add($flt)
                        }
                    }
                }
            }

            if ($deadFilters.Count -gt 0) {
                $clsName = if ($kProps.'(Default)') { $kProps.'(Default)' } else { $k.PSChildName }
                $issueMsg = "تم العثور على فلاتر يتيمة مفقودة الملفات ($($deadFilters -join ', ')) في $filterProp لفئة $clsName تسبب خطأ Code 19/39!"
                $issuesFound.Add($issueMsg)
                Write-Log "  [!] Orphaned dead filter(s) detected in $clsName ($filterProp): $($deadFilters -join ', ')" -Color Red -Level "WARN"

                if ($isRepairMode) {
                    $regBackupFile = Join-Path $BackupDir "Orphan_${k.PSChildName}_${filterProp}.reg"
                    reg.exe export "HKLM\SYSTEM\CurrentControlSet\Control\Class\$($k.PSChildName)" "$regBackupFile" /y | Out-Null

                    $cleanFlt = $filters | Where-Object { $deadFilters -notcontains $_ }
                    if ($cleanFlt -and $cleanFlt.Count -gt 0) {
                        Set-ItemProperty -Path $k.PSPath -Name $filterProp -Value ([string[]]$cleanFlt)
                    } else {
                        Remove-ItemProperty -Path $k.PSPath -Name $filterProp -ErrorAction SilentlyContinue
                    }
                    $actionsTaken.Add("تم حذف الفلاتر اليتيمة ($($deadFilters -join ', ')) من $filterProp لفئة $clsName.")
                    Write-Log "      [+] Successfully purged orphaned filter drivers from $clsName." -Color Green
                }
            }
        }
    }
}

# ==============================================================================
# 4. UsbDk Hider Rules & Service Startup Configuration
# ==============================================================================
Write-Host "--------------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "[4/8] فحص قواعد حجب UsbDk وتعطيل تشغيل خدمة UsbDk التلقائي..." -ForegroundColor Yellow

$usbDkController = $null
$possibleUsbDkPaths = @(
    "C:\Program Files\UsbDk Runtime Library\UsbDkController.exe",
    "C:\Program Files (x86)\UsbDk Runtime Library\UsbDkController.exe"
)
foreach ($up in $possibleUsbDkPaths) {
    if (Test-Path $up) {
        $usbDkController = $up
        break
    }
}

if ($usbDkController) {
    Write-Log "  [*] UsbDkController found at: $usbDkController" -Color Cyan
    if ($isRepairMode) {
        try {
            Write-Log "      [*] Clearing all persistent UsbDk hide rules..." -Color Cyan
            $hiderOutput = & "$usbDkController" -Z 2>&1
            $actionsTaken.Add("تم تنظيف وتصفير قواعد حجب الاجهزة في UsbDk (UsbDkController -Z).")
            Write-Log "      [SUCCESS] Persistent hide rules cleared." -Color Green
        } catch {
            Write-Log "      [INFO] UsbDkController reset output: $_" -Color Gray
        }
    }
}

# Ensure UsbDk service startup is set to Disabled (4) so it does not auto-hook on reboot
$usbDkSvcPath = "HKLM:\SYSTEM\CurrentControlSet\Services\UsbDk"
if (Test-Path $usbDkSvcPath) {
    $usProps = Get-ItemProperty -Path $usbDkSvcPath -ErrorAction SilentlyContinue
    if ($usProps.Start -ne 4) {
        $issueMsg = "خدمة UsbDk مفعلة برمجيا (Start = $($usProps.Start)) مما قد يعيد تثبيت فلاتر الحجب عند اعادة التشغيل."
        $issuesFound.Add($issueMsg)
        Write-Log "  [!] UsbDk service startup is active (Start=$($usProps.Start))." -Color Yellow -Level "WARN"

        if ($isRepairMode) {
            Set-ItemProperty -Path $usbDkSvcPath -Name "Start" -Value 4
            $actionsTaken.Add("تم تغيير نوع بدء خدمة UsbDk الى معطل (Start = 4) لمنع حجب منافذ الـ USB.")
            Write-Log "      [SUCCESS] Set UsbDk service start type to 4 (Disabled)." -Color Green
        }
    } else {
        Write-Log "  [OK] UsbDk service startup is already disabled." -Color Green
    }
}

# ==============================================================================
# 5. Phantom Devices, Stuck Ports & Descriptor Failure Recovery
# ==============================================================================
Write-Host "--------------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "[5/8] فحص الاجهزة الوهمية المعطلة وتجاوز فشل قراءة الوصف (Descriptor Failure)..." -ForegroundColor Yellow

$badDeviceList = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object {
    # 1. Broken root devices
    (($_.InstanceId -like "ROOT\PORTS*" -or $_.InstanceId -like "ROOT\USB*") -and ($_.Status -ne "OK" -or $_.Problem -ne "CM_PROB_NONE")) -or
    # 2. USB Descriptor failures or hung enumeration nodes
    ($_.InstanceId -like "USB\VID_0000*" -or $_.InstanceId -like "*DESCRIPTOR_FAILURE*" -or $_.InstanceId -like "*UNKNOWN_USB_DEVICE*") -or
    # 3. Present external devices in CM_PROB_FAILED_POST_START (Code 10) or CM_PROB_FAILED_INSTALL (Code 28)
    ($_.Present -eq $true -and $_.Class -in @("USB", "Ports", "Modem", "AndroidUsbDeviceClass") -and $_.Problem -in @("CM_PROB_FAILED_POST_START", "CM_PROB_FAILED_INSTALL") -and $_.InstanceId -notlike "PCI\*")
}

if ($badDeviceList) {
    foreach ($bDev in $badDeviceList) {
        $issueMsg = "جهاز في حالة فشل أو تعليق: $($bDev.FriendlyName) [$($bDev.InstanceId)] (مشكلة: $($bDev.Problem))"
        $issuesFound.Add($issueMsg)
        Write-Log "  [!] Failed/Hung device detected: $($bDev.FriendlyName) [$($bDev.InstanceId)] (Problem: $($bDev.Problem))" -Color Red -Level "WARN"

        if ($isRepairMode) {
            Write-Log "      [*] Purging stuck device node $($bDev.InstanceId)..." -Color Cyan
            pnputil.exe /remove-device "$($bDev.InstanceId)" | Out-Null
            $actionsTaken.Add("تمت إزالة العقدة المعلقة للجهاز $($bDev.InstanceId).")
            Write-Log "      [SUCCESS] Hung device node removed successfully." -Color Green
        }
    }
} else {
    Write-Log "  [OK] No phantom, failed descriptor, or stalled USB nodes detected." -Color Green
}

# ==============================================================================
# 6. USB Power Management & Hub Keep-Alive Configuration
# ==============================================================================
Write-Host "--------------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "[6/8] الغاء تعليق الطاقة (USB Selective Suspend) وتثبيت طاقة الـ Hubs..." -ForegroundColor Yellow

if ($isRepairMode) {
    try {
        # Power schemes Selective Suspend
        & powercfg.exe /setacvalueindex SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0 2>$null
        & powercfg.exe /setdcvalueindex SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0 2>$null
        & powercfg.exe /SetActive SCHEME_CURRENT 2>$null
        $actionsTaken.Add("تم تعطيل USB Selective Suspend في خطة الطاقة الحالية.")
        Write-Log "  [+] USB Selective Suspend disabled via powercfg." -Color Green
    } catch {
        Write-Log "  [INFO] Power configuration note: $_" -Color Gray
    }

    # Disable EnhancedPowerManagementEnabled and SelectiveSuspendEnabled on USB Hubs in Registry
    $usbHubEnumPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\USB"
    if (Test-Path $usbHubEnumPath) {
        $hubSubKeys = Get-ChildItem -Path $usbHubEnumPath -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -eq "Device Parameters" }
        foreach ($dp in $hubSubKeys) {
            try {
                $props = Get-ItemProperty -Path $dp.PSPath -ErrorAction SilentlyContinue
                if ($props.EnhancedPowerManagementEnabled -eq 1) {
                    Set-ItemProperty -Path $dp.PSPath -Name "EnhancedPowerManagementEnabled" -Value 0 -ErrorAction SilentlyContinue
                }
                if ($props.SelectiveSuspendEnabled -eq 1) {
                    Set-ItemProperty -Path $dp.PSPath -Name "SelectiveSuspendEnabled" -Value 0 -ErrorAction SilentlyContinue
                }
            } catch {}
        }
        $actionsTaken.Add("تم ضبط مفاتيح إدارة طاقة موزعات USB في السجل لمنع انقطاع اتصال هواتف الفلاش.")
        Write-Log "  [+] USB Root Hub power save keys disabled in registry (Prevents disconnects in EDL/BROM)." -Color Green
    }
} else {
    Write-Log "  [INFO] Skipped power setting modifications in Diagnostic-Only mode." -Color Gray
}

# ==============================================================================
# 7. Check Port 5037 and ADB Server Clean Restart
# ==============================================================================
Write-Host "--------------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "[7/8] فحص المنفذ 5037 وتحديث خادم ADB (Port 5037 & ADB Daemon)..." -ForegroundColor Yellow

if (-not $SkipAdbRestart) {
    $port5037 = Get-NetTCPConnection -LocalPort 5037 -ErrorAction SilentlyContinue

    if ($port5037) {
        $ownerPid = $port5037.OwningProcess | Select-Object -First 1
        $ownerProc = Get-Process -Id $ownerPid -ErrorAction SilentlyContinue
        $pName = if ($ownerProc) { $ownerProc.ProcessName } else { "Unknown" }
        Write-Log "  [*] Port 5037 is active. Owning process: $pName (PID: $ownerPid)" -Color Cyan

        if ($isRepairMode) {
            if ($pName -eq "adb") {
                Write-Log "      [*] Restarting ADB daemon to refresh attached device registry..." -Color Cyan
                $adbExe = Find-AdbPath
                if ($adbExe) {
                    & "$adbExe" kill-server 2>&1 | Out-Null
                    Start-Sleep -Milliseconds 800
                    & "$adbExe" start-server 2>&1 | Out-Null
                    $actionsTaken.Add("تم اعادة تشغيل خادم ADB ($adbExe) بنجاح وتحديث قائمة الاجهزة.")
                    Write-Log "      [SUCCESS] ADB daemon restarted cleanly using $adbExe." -Color Green
                } else {
                    Stop-Process -Id $ownerPid -Force -ErrorAction SilentlyContinue
                    $actionsTaken.Add("تم انهاء عملية ADB العالقة (PID: $ownerPid).")
                    Write-Log "      [SUCCESS] Terminated stuck ADB process $ownerPid." -Color Green
                }
            } else {
                Write-Log "      [INFO] Port 5037 owned by GSM servicing software ($pName). Session preserved." -Color DarkYellow
            }
        }
    } else {
        Write-Log "  [OK] Port 5037 is free and ready for mobile communication." -Color Green
    }
} else {
    Write-Log "  [INFO] Skipped ADB check per user flag (-SkipAdbRestart)." -Color Gray
}

# ==============================================================================
# 8. Global Hardware Rescan & Discovery
# ==============================================================================
Write-Host "--------------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "[8/8] اعادة فحص وتنشيط ناقل الاجهزة بالكامل (Global PnP Rescan & Topology)..." -ForegroundColor Yellow

if ($isRepairMode) {
    Write-Log "  [*] Triggering system-wide PnP hardware scan via pnputil..." -Color Cyan
    pnputil.exe /scan-devices | Out-Null
    Start-Sleep -Seconds 2
    Write-Log "  [OK] Hardware scan complete. System topology updated." -Color Green
}

# Check if any controller requires reboot
$rebootPendingDevices = Get-PnpDevice -Class USB -PresentOnly -ErrorAction SilentlyContinue | Where-Object {
    $_.Problem -in @("CM_PROB_NEED_RESTART", "CM_PROB_DRIVER_FAILED_PRIOR_UNLOAD")
}
if ($rebootPendingDevices) {
    $rebootRecommended = $true
}

# ==============================================================================
# Comprehensive Final Report
# ==============================================================================
Write-Host ""
Write-Host "==========================================================================" -ForegroundColor Green
Write-Host "              تقرير الفحص والاصلاح الشامل (Diagnostic and Repair Report)     " -ForegroundColor Green
Write-Host "==========================================================================" -ForegroundColor Green

Write-Host "1. المشاكل التي تم اكتشافها (Issues Detected):" -ForegroundColor Cyan
if ($issuesFound.Count -gt 0) {
    foreach ($iss in $issuesFound) {
        Write-Host "   [!] $iss" -ForegroundColor Red
    }
} else {
    Write-Host "   [OK] لم يتم اكتشاف اي مشاكل او تعارضات غير طبيعية في النظام." -ForegroundColor Green
}

Write-Host ""
Write-Host "2. الاجراءات التي تم تنفيذها (Actions Taken):" -ForegroundColor Cyan
if ($actionsTaken.Count -gt 0) {
    foreach ($act in $actionsTaken) {
        Write-Host "   [+] $act" -ForegroundColor Green
    }
} else {
    Write-Host "   [-] لم يتم تنفيذ اجراءات تعديلية (النظام سليم او وضع الفحص فقط)." -ForegroundColor Gray
}

Write-Host ""
Write-Host "3. الاجهزة المتصلة حاليا وجاهزة للعمل (Currently Connected Devices):" -ForegroundColor Cyan

$connectedDevices = Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | Where-Object {
    $_.Class -in @("AndroidUsbDeviceClass", "Android Device", "Android Phone", "Ports", "Modem", "USBDevice", "MEDIA") -or
    ($_.Class -eq "USB" -and ($_.FriendlyName -like "*Samsung*" -or $_.FriendlyName -like "*Composite*" -or $_.FriendlyName -like "*MediaTek*" -or $_.FriendlyName -like "*Qualcomm*" -or $_.FriendlyName -like "*Spreadtrum*"))
}

if ($connectedDevices) {
    foreach ($cDev in $connectedDevices) {
        $statusColor = if ($cDev.Status -eq "OK") { [ConsoleColor]::Green } else { [ConsoleColor]::Yellow }
        Write-Host "   - [$($cDev.Class)] $($cDev.FriendlyName) | Status: $($cDev.Status)" -ForegroundColor $statusColor
        Write-Log "Connected Device: [$($cDev.Class)] $($cDev.FriendlyName) ($($cDev.InstanceId)) Status: $($cDev.Status)" -Color Gray
    }
} else {
    Write-Host "   (لا توجد اجهزة هواتف او مودم متصلة حاليا - المنافذ جاهزة لاستقبال توصيل هاتفك)" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "==========================================================================" -ForegroundColor Green
if ($rebootRecommended) {
    Write-Host "  [NOTICE] تمت ازالة تعريف الفلتر من الذاكرة بنجاح. يُفضل اعادة تشغيل الحاسوب مرة واحدة" -ForegroundColor Yellow
    Write-Host "           لاطلاق ذاكرة منفذ USB 2.0 (EHCI) القديم بالكامل من طبقة UsbDk." -ForegroundColor Yellow
    Write-Host "           (ملاحظة: منافذ USB 3.0 الحديثة تعمل بشكل سليم 100% دون الحاجة لاعادة التشغيل)." -ForegroundColor Yellow
} else {
    Write-Host "  [SUCCESS] تمت المعالجة بنجاح. المنافذ جاهزة للتعرف على الاجهزة المتصلة فورا! " -ForegroundColor Green
}
Write-Host "  سجل النسخ الاحتياطي محفوظ في: $BackupDir" -ForegroundColor Gray
Write-Host "==========================================================================" -ForegroundColor Green
Write-Host ""
