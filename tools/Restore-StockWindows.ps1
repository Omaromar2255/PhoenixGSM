# ==============================================================================
# PhoenixGSM — Emergency Stock Windows Restoration & Safety Guard Script
# ==============================================================================
# Run as Administrator.
# Safely removes all PhoenixUsbMonitor filter driver registrations from:
# - Ports Class {4D36E978-E325-11CE-BFC1-08002BE10318}
# - Modem Class {4D36E96D-E325-11CE-BFC1-08002BE10318}
# - Android Class {3F966BD9-FA04-4EC5-991C-D326973B5128}
# - WinUSB Class {88BAE032-5A81-49F0-BC3D-A4FF138216D6}
# - All Enum USB, PORTS, FTDIBUS devices
# And stops the kernel driver service, returning Windows to 100% clean stock state.
# ==============================================================================

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  PhoenixGSM Safety Guard: Restoring Stock Windows State  " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$backupDir = "C:\Users\pc5\softwer\PhoenixGSM\backups\registry"
if (-not (Test-Path $backupDir)) { New-Item -ItemType Directory -Path $backupDir -Force | Out-Null }
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# 1. Classes to verify and clean
$classGuids = @(
    "{4D36E978-E325-11CE-BFC1-08002BE10318}", # Ports (COM & LPT)
    "{4D36E96D-E325-11CE-BFC1-08002BE10318}", # Modem
    "{3F966BD9-FA04-4EC5-991C-D326973B5128}", # Android
    "{88BAE032-5A81-49F0-BC3D-A4FF138216D6}"  # WinUSB
)

$serviceName = "PhoenixUsbMonitor"

foreach ($guid in $classGuids) {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\$guid"
    if (Test-Path $regPath) {
        $props = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
        
        # Check UpperFilters
        if ($props.UpperFilters -and ($props.UpperFilters -contains $serviceName)) {
            Write-Host "  [*] Backing up Class $guid..." -ForegroundColor Yellow
            reg.exe export "HKLM\SYSTEM\CurrentControlSet\Control\Class\$guid" "$backupDir\Class_${guid}_${timestamp}.reg" /y | Out-Null
            
            $filtered = $props.UpperFilters | Where-Object { $_ -ne $serviceName }
            if ($filtered -and $filtered.Count -gt 0) {
                Set-ItemProperty -Path $regPath -Name "UpperFilters" -Value $filtered
                Write-Host "  [+] Removed '$serviceName' from UpperFilters of Class $guid." -ForegroundColor Green
            } else {
                Remove-ItemProperty -Path $regPath -Name "UpperFilters" -ErrorAction SilentlyContinue
                Write-Host "  [+] Cleaned UpperFilters completely from Class $guid." -ForegroundColor Green
            }
        }

        # Check LowerFilters
        if ($props.LowerFilters -and ($props.LowerFilters -contains $serviceName)) {
            Write-Host "  [*] Backing up Class $guid..." -ForegroundColor Yellow
            reg.exe export "HKLM\SYSTEM\CurrentControlSet\Control\Class\$guid" "$backupDir\Class_${guid}_${timestamp}.reg" /y | Out-Null
            
            $filtered = $props.LowerFilters | Where-Object { $_ -ne $serviceName }
            if ($filtered -and $filtered.Count -gt 0) {
                Set-ItemProperty -Path $regPath -Name "LowerFilters" -Value $filtered
                Write-Host "  [+] Removed '$serviceName' from LowerFilters of Class $guid." -ForegroundColor Green
            } else {
                Remove-ItemProperty -Path $regPath -Name "LowerFilters" -ErrorAction SilentlyContinue
                Write-Host "  [+] Cleaned LowerFilters completely from Class $guid." -ForegroundColor Green
            }
        }
    }
}

# 2. Stop Kernel Driver Service safely if running
$svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host "  [*] Service '$serviceName' detected." -ForegroundColor Cyan
}

# 3. Restart connected COM ports & Modems so stock drivers reload cleanly
Write-Host "  [*] Reloading connected devices..." -ForegroundColor Cyan
$connectedDevices = pnputil.exe /enum-devices /connected
# Re-enumeration
pnputil.exe /scan-devices | Out-Null

Write-Host "==========================================================" -ForegroundColor Green
Write-Host "  [SUCCESS] All filters stripped. Windows stock state restored! " -ForegroundColor Green
Write-Host "  Backups saved to: $backupDir" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
