@echo off
:: ==============================================================================
:: Mini-Shark Laptop 2 (Client 2) — One-Click Windows Launcher
:: Automatically requests Administrator privileges and starts PowerShell automation.
:: ==============================================================================

cd /d "%~dp0"
echo Starting Mini-Shark Client 2 Automation...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_client_windows.ps1" %*
