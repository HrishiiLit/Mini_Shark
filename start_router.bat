@echo off
:: ==============================================================================
:: Mini-Shark Laptop 3 (Router) — One-Click Windows Launcher
:: Automatically requests Administrator privileges and starts PowerShell automation.
:: ==============================================================================

cd /d "%~dp0"
echo Starting Mini-Shark Router Automation...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_router.ps1" %*
