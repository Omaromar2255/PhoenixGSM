<#
.SYNOPSIS
    Phoenix ADB Isolation Layer Installer
.DESCRIPTION
    Installs the transparent ADB interception proxy into %TEMP%\adb.exe used by Q-Unlocker and other tools.
    Preserves original Google ADB as adb_real.exe.
    Captures:
      - Interactive sub-shell stream (>> AuthKeys, AT commands, prompts)
      - Forensic Artifacts (push and pull of /data/local/tmp/athun, AT, ndx, SRV4_64)
      - Zero latency, byte-transparent passthrough
#>

param(
    [switch]$Uninstall,
    [string]$TargetDir = "$env:LOCALAPPDATA\Temp"
)

$srcBinDir = "c:\Users\pc5\softwer\PhoenixGSM\tools\MonitoringToolkit\AdbMonitor\bin\Release\net8.0"
$adbPath = Join-Path $TargetDir "adb.exe"
$realAdbPath = Join-Path $TargetDir "adb_real.exe"

if ($Uninstall) {
    if (Test-Path $realAdbPath) {
        if (Test-Path $adbPath) { Remove-Item $adbPath -Force }
        Move-Item $realAdbPath $adbPath -Force
        
        # Clean companion files
        @("AdbMonitor.dll", "AdbMonitor.runtimeconfig.json", "AdbMonitor.deps.json") | ForEach-Object {
            $f = Join-Path $TargetDir $_
            if (Test-Path $f) { Remove-Item $f -Force }
        }
        Write-Host "[+] Restored original adb.exe in $TargetDir" -ForegroundColor Green
    } else {
        Write-Host "[-] Original adb_real.exe not found. Nothing to restore." -ForegroundColor Yellow
    }
    return
}

if (-not (Test-Path $srcBinDir)) {
    Write-Host "[-] Compiled AdbMonitor not found at $srcBinDir. Build solution first." -ForegroundColor Red
    return
}

if (Test-Path $adbPath) {
    if (-not (Test-Path $realAdbPath)) {
        Move-Item $adbPath $realAdbPath -Force
        Write-Host "[+] Backed up original adb.exe -> adb_real.exe" -ForegroundColor Green
    }
} else {
    Write-Host "[*] No existing adb.exe in $TargetDir. Locating system adb..." -ForegroundColor Cyan
    $sysAdb = (Get-Command adb -ErrorAction SilentlyContinue).Source
    if ($sysAdb -and (Test-Path $sysAdb)) {
        Copy-Item $sysAdb $realAdbPath -Force
        Write-Host "[+] Copied system adb ($sysAdb) -> $realAdbPath" -ForegroundColor Green
    }
}

# Copy proxy files
Copy-Item (Join-Path $srcBinDir "AdbMonitor.exe") $adbPath -Force
@("AdbMonitor.dll", "AdbMonitor.runtimeconfig.json", "AdbMonitor.deps.json") | ForEach-Object {
    $src = Join-Path $srcBinDir $_
    if (Test-Path $src) {
        Copy-Item $src (Join-Path $TargetDir $_) -Force
    }
}

Write-Host "[+] Phoenix ADB Isolation Layer ACTIVE in $TargetDir" -ForegroundColor Green
Write-Host "    Proxy Hook : $adbPath" -ForegroundColor Gray
Write-Host "    Real ADB   : $realAdbPath" -ForegroundColor Gray
Write-Host "    Vault Dir  : $env:LOCALAPPDATA\PhoenixGSM\Artifacts\PushedFiles" -ForegroundColor Gray
Write-Host "    Logs Dir   : $env:LOCALAPPDATA\PhoenixGSM\Logs\ADB" -ForegroundColor Gray
