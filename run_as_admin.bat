@echo off
title Mini-Shark (Administrator Mode)
cd /d "%~dp0"

:: Check if already Administrator
net session >nul 2>&1
if %errorlevel% == 0 (
    echo =======================================================
    echo  Mini-Shark: Live Wire Packet Sniffing Mode (Admin)
    echo =======================================================
    python run_minishark.py %*
    if errorlevel 1 pause
    exit /b
)

:: Elevate via PowerShell launcher
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_as_admin.ps1" %*
exit /b
