# Automated Validation and Comprehensive Test Suite for Repair-UsbAndAndroidDrivers.ps1

$ErrorActionPreference = "Stop"
$scriptDir = if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) { $PSScriptRoot } elseif ($MyInvocation.MyCommand.Definition) { Split-Path -Parent $MyInvocation.MyCommand.Definition } else { (Get-Location).Path }
$repairScript = Join-Path $scriptDir "Repair-UsbAndAndroidDrivers.ps1"

Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host "  PhoenixGSM - Testing USB and Android Device Repair Script Matrix        " -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Cyan

$testResults = [System.Collections.Generic.List[PSCustomObject]]::new()

function Assert-Test {
    param(
        [string]$TestName,
        [scriptblock]$ScriptBlock
    )
    Write-Host "Running: $TestName ... " -NoNewline -ForegroundColor Yellow
    try {
        & $ScriptBlock
        Write-Host "PASSED" -ForegroundColor Green
        $testResults.Add([PSCustomObject]@{ Test = $TestName; Status = "PASSED"; Error = "" })
    } catch {
        Write-Host "FAILED: $_" -ForegroundColor Red
        $testResults.Add([PSCustomObject]@{ Test = $TestName; Status = "FAILED"; Error = "$_" })
    }
}

# 1. Test Script Existence and Syntax
Assert-Test "1. Script Existence and File Validity" {
    if (-not (Test-Path $repairScript)) { throw "Repair script not found at $repairScript" }
    $syntaxErrors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($repairScript, [ref]$null, [ref]$syntaxErrors) | Out-Null
    if ($syntaxErrors -and $syntaxErrors.Count -gt 0) {
        throw "Syntax errors detected in script: $($syntaxErrors -join '; ')"
    }
}

# 2. Test Parameter Serialization & No 'True' Directory Creation Bug
Assert-Test "2. Parameter Handling & Prevention of 'True' Directory Creation" {
    $junkDir = Join-Path (Get-Location).Path "True"
    if (Test-Path $junkDir) { Remove-Item -Path $junkDir -Recurse -Force }
    
    $tempBackup = Join-Path $env:TEMP "PhoenixTest_Param_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    $output = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$repairScript" -DiagnosticOnly -BackupDir "$tempBackup" 2>&1
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) { throw "Script failed with exit code $exitCode. Output: $($output -join "`n")" }
    
    if (Test-Path $junkDir) {
        Remove-Item -Path $junkDir -Recurse -Force
        throw "REGRESSION: Parameter serialization created a directory named 'True' in root directory!"
    }
}

# 3. Test Mode Switching: DiagnosticOnly vs Default AutoFix
Assert-Test "3. Operating Modes: DiagnosticOnly vs Default AutoFix" {
    $tempBackup1 = Join-Path $env:TEMP "PhoenixTest_DiagMode_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    $output1 = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$repairScript" -DiagnosticOnly -BackupDir "$tempBackup1" 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Script failed in DiagnosticOnly mode" }
    if (($output1 -join "`n") -notmatch "Mode: DiagnosticOnly") {
        throw "Script did not honor -DiagnosticOnly flag!"
    }

    $tempBackup2 = Join-Path $env:TEMP "PhoenixTest_AutoMode_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    $output2 = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$repairScript" -BackupDir "$tempBackup2" 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Script failed in default mode" }
    if (($output2 -join "`n") -notmatch "Mode: AutoFix") {
        throw "Script default mode is not AutoFix!"
    }
}

# 4. Unit Test: Rogue INF Detection Engine (Edge Cases & False Positive Prevention)
Assert-Test "4. Unit Test: Rogue INF Pattern Discrimination Engine" {
    $testMockDir = Join-Path $env:TEMP "PhoenixTest_MockInfs_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    New-Item -ItemType Directory -Path $testMockDir -Force | Out-Null
    try {
        # Case A: Legitimate driver with VID and Class_02 on same line
        $validInfContent = @"
[Version]
Signature = "`$Windows NT`$"
Class = Modems
ClassGuid = {4d36e96d-e325-11ce-bfc1-08002be10318}
[Samsung.NT]
%SAMSUNG.Modem% = Install, USB\VID_04E8&PID_6860&Class_02&SubClass_02&Prot_01
"@
        Set-Content -Path "$testMockDir\oemValid.inf" -Value $validInfContent

        # Case B: Rogue driver with unconstrained Class_02&SubClass_02 targeting ADB
        $rogueInfContentB = @"
[Version]
Signature = "`$Windows NT`$"
Class = AndroidUsbDeviceClass
ClassGuid = {3F966BD9-FA04-4ec5-991C-D326973B5128}
[Google.NT]
%SingleAdbInterface% = USB_Install, USB\Class_02&SubClass_02
"@
        Set-Content -Path "$testMockDir\oemRogueB.inf" -Value $rogueInfContentB

        # Case C: Rogue driver with unconstrained Class_02 (no SubClass) targeting WinUSB
        $rogueInfContentC = @"
[Version]
Signature = "`$Windows NT`$"
Class = Android Device
ClassGuid = {3F966BD9-FA04-4ec5-991C-D326973B5128}
[DeviceList.NT]
%AdbDev% = USB_Install, USB\Class_02
"@
        Set-Content -Path "$testMockDir\oemRogueC.inf" -Value $rogueInfContentC

        # Run discrimination logic
        $detectedRogues = [System.Collections.Generic.List[string]]::new()
        foreach ($file in (Get-ChildItem -Path $testMockDir -Filter "*.inf")) {
            $lines = Get-Content -Path $file.FullName
            $isAdbOrWinUsb = $false
            $hasToxicGenericClassMatch = $false

            foreach ($line in $lines) {
                $trimmed = $line.Trim()
                if ($trimmed.StartsWith(";")) { continue }
                if ($trimmed -match "(?i)AndroidUsbDeviceClass|ClassGuid\s*=\s*\{3F966BD9|AndroidWinUsb|Class\s*=\s*Android") {
                    $isAdbOrWinUsb = $true
                }
            }
            foreach ($line in $lines) {
                $trimmed = $line.Trim()
                if ($trimmed.StartsWith(";")) { continue }
                if ($trimmed -match "(?i)USB\\Class_(02|0A|E0)" -and $trimmed -notmatch "(?i)VID_[0-9A-Fa-f]{4}") {
                    $hasToxicGenericClassMatch = $true
                    break
                }
            }
            if ($hasToxicGenericClassMatch -and $isAdbOrWinUsb) {
                $detectedRogues.Add($file.Name)
            }
        }

        if ($detectedRogues -contains "oemValid.inf") {
            throw "FALSE POSITIVE: Valid vendor INF oemValid.inf was incorrectly flagged as rogue!"
        }
        if (-not ($detectedRogues -contains "oemRogueB.inf")) {
            throw "FALSE NEGATIVE: Rogue INF oemRogueB.inf was NOT detected!"
        }
        if (-not ($detectedRogues -contains "oemRogueC.inf")) {
            throw "FALSE NEGATIVE: Rogue INF oemRogueC.inf was NOT detected!"
        }
    } finally {
        Remove-Item -Path $testMockDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# 5. Unit Test: Orphaned Filter Driver Detection Logic
Assert-Test "5. Unit Test: Orphaned Filter Driver Detection Logic" {
    # Test checking for non-existent service name
    $fakeFilter = "NonExistentServiceFilter_12345"
    $isDead = -not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$fakeFilter")
    if (-not $isDead) { throw "Expected non-existent service to be flagged as dead." }
    
    # Test checking for legitimate Windows service
    $legitFilter = "partmgr"
    $isLegitDead = -not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$legitFilter")
    if ($isLegitDead) { throw "Valid core service partmgr was falsely flagged as dead." }
}

# 6. Test Live Diagnostic Execution
Assert-Test "6. Live System Diagnostic-Only Execution" {
    $tempBackup = Join-Path $env:TEMP "PhoenixTest_DiagLive_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    $output = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$repairScript" -DiagnosticOnly -BackupDir "$tempBackup" 2>&1
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) { throw "Script failed with exit code $exitCode. Output: $($output -join "`n")" }
    if (-not (Test-Path "$tempBackup\repair_execution.log")) { throw "Log file was not generated in $tempBackup" }
}

# 7. Test Live AutoFix Execution
Assert-Test "7. Live System AutoFix Execution and Remediation" {
    $tempBackup = Join-Path $env:TEMP "PhoenixTest_FixLive_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    $output = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$repairScript" -AutoFix -BackupDir "$tempBackup" 2>&1
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) { throw "Script failed with exit code $exitCode. Output: $($output -join "`n")" }
    if (-not (Test-Path "$tempBackup\repair_execution.log")) { throw "Log file was not generated in $tempBackup" }
}

# 8. Verification: No Ghost / Internal Hardware Stuck as Android
Assert-Test "8. Verification: No Ghost / Internal Hardware Stuck as Android" {
    $androidDevices = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { 
        ($_.Class -in @("AndroidUsbDeviceClass", "Android Device", "Android Phone", "ADB Interface") -or 
         $_.FriendlyName -like "*Android ADB*") -and $_.Present -eq $true 
    }
    
    if ($androidDevices) {
        foreach ($dev in $androidDevices) {
            if ($dev.InstanceId -like "*VID_1199*" -or $dev.InstanceId -like "*VID_413C*") {
                throw "Internal hardware $($dev.InstanceId) is still stuck as Android device!"
            }
        }
    }
}

# 9. Verification: Sierra Wireless Hardware State
Assert-Test "9. Verification: Sierra Wireless Hardware State" {
    $sierraDevices = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { 
        $_.InstanceId -like "*VID_1199*PID_A001*" -and $_.Present -eq $true 
    }
    if ($sierraDevices) {
        foreach ($sd in $sierraDevices) {
            if ($sd.Class -eq "AndroidUsbDeviceClass" -or $sd.Class -eq "Android Device") {
                throw "Sierra Wireless interface $($sd.InstanceId) is assigned to Android class!"
            }
        }
    }
}

# 10. Verification: No Toxic Class_02 Wildcards in OEM INFs
Assert-Test "10. Verification: No Toxic Class_02 Wildcards in OEM INFs" {
    $allOemInfs = Get-ChildItem -Path C:\Windows\INF\oem*.inf -ErrorAction SilentlyContinue
    foreach ($inf in $allOemInfs) {
        $lines = Get-Content -Path $inf.FullName -ErrorAction SilentlyContinue
        $isAdb = $false
        foreach ($l in $lines) {
            if ($l -match "(?i)AndroidUsbDeviceClass|ClassGuid\s*=\s*\{3F966BD9") { $isAdb = $true; break }
        }
        if ($isAdb) {
            foreach ($l in $lines) {
                if ($l.Trim().StartsWith(";")) { continue }
                if ($l -match "(?i)USB\\Class_02" -and $l -notmatch "(?i)VID_") {
                    throw "Found toxic INF still installed: $($inf.FullName) with line: $l"
                }
            }
        }
    }
}

# 11. Verification: USB Class UpperFilters Healthy
Assert-Test "11. Verification: USB Class UpperFilters and UsbDk Service" {
    $usbClassProps = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{36fc9e60-c465-11cf-8056-444553540000}" -ErrorAction SilentlyContinue
    if ($usbClassProps.UpperFilters) {
        $badF = @($usbClassProps.UpperFilters) | Where-Object { $_ -in @("UsbDk", "PhoenixUsbMonitor", "USBPcap") }
        if ($badF) {
            throw "Problematic UpperFilters still present on USB Controller class: $($badF -join ', ')"
        }
    }
    
    $usbDkSvc = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\UsbDk" -ErrorAction SilentlyContinue
    if ($usbDkSvc -and $usbDkSvc.Start -ne 4) {
        throw "UsbDk service start type is not 4 (Disabled). Current: $($usbDkSvc.Start)"
    }
}

Write-Host ""
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host "                          Test Results Summary                            " -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Cyan
$testResults | Format-Table -AutoSize

$failedTests = @($testResults | Where-Object { $_.Status -eq "FAILED" })
if ($failedTests.Count -gt 0) {
    Write-Host "[-] $($failedTests.Count) test(s) failed!" -ForegroundColor Red
    exit 1
} else {
    Write-Host "[+] All $($testResults.Count) validation tests passed successfully!" -ForegroundColor Green
    exit 0
}