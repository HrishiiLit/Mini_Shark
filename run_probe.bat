@echo off
REM ==============================================================================
REM Mini-Shark Zero-Install Portable Probe Runner (Windows)
REM
REM Runs live packet capture on Windows using Scapy + Npcap.
REM
REM Usage:
REM   run_probe.bat --server 192.168.1.5:9000
REM ==============================================================================

cd /d "%~dp0"

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [Error] Python was not found in PATH. Please install Python 3.
    pause
    exit /b 1
)

python run_probe.py %*
