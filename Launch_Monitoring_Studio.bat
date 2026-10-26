@echo off
title Device Configuration Launcher
if exist "C:\Users\pc5\Documents\GitHub\PhoenixGSMtools\Debug\net8.0-windows\DevConfigStudio.exe" (
    start "" "C:\Users\pc5\Documents\GitHub\PhoenixGSMtools\Debug\net8.0-windows\DevConfigStudio.exe"
) else (
    start "" "C:\Users\pc5\Documents\GitHub\PhoenixGSMtools\Debug\net8.0-windows\MonitoringStudio.exe"
)
