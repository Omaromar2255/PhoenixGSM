@echo off
setlocal
title PhoenixGSM - Project Build Tool
color 0B

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Build-Project.ps1" %*

if %ERRORLEVEL% NEQ 0 (
    color 0C
    echo.
    echo [ERROR] The build process encountered an error.
)

echo.
echo Press any key to exit...
pause >nul
