@echo off
title Device Configuration Launcher
if exist "%~dp0tools\MonitoringToolkit\MonitoringStudio\bin\Debug\net8.0-windows\DevConfigStudio.exe" (
    start "" "%~dp0tools\MonitoringToolkit\MonitoringStudio\bin\Debug\net8.0-windows\DevConfigStudio.exe"
) else (
    start "" "%~dp0tools\MonitoringToolkit\MonitoringStudio\bin\Debug\net8.0-windows\MonitoringStudio.exe"
)
