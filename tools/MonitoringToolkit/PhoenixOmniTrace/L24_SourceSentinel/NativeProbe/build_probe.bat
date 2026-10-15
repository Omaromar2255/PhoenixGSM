@echo off
REM Build script for PhoenixSourceProbe.dll using MSVC cl.exe
echo [PhoenixGSM L24] Building PhoenixSourceProbe.dll...

where cl.exe >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] MSVC cl.exe not found in PATH. Please run from Developer Command Prompt for VS.
    exit /b 1
)

cl.exe /nologo /O2 /LD /EHsc /std:c++17 /DUNICODE /D_UNICODE PhoenixSourceProbe.cpp /link /OUT:PhoenixSourceProbe.dll setupapi.lib advapi32.lib psapi.lib user32.lib

if %ERRORLEVEL% EQU 0 (
    echo [SUCCESS] PhoenixSourceProbe.dll compiled successfully.
) else (
    echo [ERROR] Compilation failed.
)
