@echo off
title Phoenix Shielded Console Host
:: Check if Windows Terminal exists
where wt.exe >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [+] Launching Cloaked Console via Windows Terminal [Window Class != ConsoleWindowClass]...
    start wt.exe -p "Command Prompt" cmd.exe /k "powershell -ExecutionPolicy Bypass -File %~dp0Protect-Cmd.ps1"
) else (
    echo [*] Windows Terminal not found. Launching hardened CMD with DACL Shield...
    start cmd.exe /k "powershell -ExecutionPolicy Bypass -File %~dp0Protect-Cmd.ps1"
)
