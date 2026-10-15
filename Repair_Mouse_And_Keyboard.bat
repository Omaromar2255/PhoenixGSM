@echo off
setlocal
title PhoenixGSM - USB Mouse and Keyboard Auto-Repair
color 0A

net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [!] Requesting Administrator privileges...
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo ==========================================================================
echo    PhoenixGSM - USB Mouse and Keyboard Instant Auto-Repair
echo    أداة فينيكس الفورية لإصلاح تعطل الماوس ولوحة المفاتيح والـ USB
echo ==========================================================================
echo.

set "SCRIPT_PATH=%~dp0tools\Repair-MouseAndKeyboard.ps1"
if not exist "%SCRIPT_PATH%" set "SCRIPT_PATH=%~dp0Repair-MouseAndKeyboard.ps1"

if not exist "%SCRIPT_PATH%" (
    color 0C
    echo [ERROR] Could not find Repair-MouseAndKeyboard.ps1!
    pause
    exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_PATH%" -AutoFix

echo.
echo Operation completed successfully.
pause
