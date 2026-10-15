@echo off
setlocal
title PhoenixGSM - USB and Android Driver Auto-Repair
color 0B

net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [!] Requesting Administrator privileges...
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo ==========================================================================
echo    PhoenixGSM - USB and Android Driver Auto-Repair
echo ==========================================================================
echo.

set "SCRIPT_PATH=%~dp0Repair-UsbAndAndroidDrivers.ps1"
if not exist "%SCRIPT_PATH%" set "SCRIPT_PATH=%~dp0tools\Repair-UsbAndAndroidDrivers.ps1"
if not exist "%SCRIPT_PATH%" set "SCRIPT_PATH=%~dp0..\tools\Repair-UsbAndAndroidDrivers.ps1"

if not exist "%SCRIPT_PATH%" (
    color 0C
    echo [ERROR] Could not find Repair-UsbAndAndroidDrivers.ps1!
    pause
    exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_PATH%" -AutoFix

echo.
echo Operation completed.
pause
