@echo off
chcp 65001 >nul
title Samsung AT RIL Tool Bridge - PhoenixGSM
echo ======================================================================
echo    PhoenixGSM - Standalone Samsung AT Bridge ^& Telemetry Collector
echo ======================================================================
echo.
cd /d "%~dp0"
python at_device_bridge.py %*
echo.
pause
