@echo off
setlocal
title PhoenixGSM - GitHub Clean Project Archiver

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Compress-GitHubProject.ps1" %*

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] The archive script encountered an error.
)

echo Press any key to exit...
pause >nul
