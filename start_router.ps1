<#
.SYNOPSIS
    Mini-Shark Laptop 3 (Intermediate Router) — All-in-One Automation Tool
.DESCRIPTION
    Configures a Windows laptop as an intermediate pure L3 router (Client -> Router -> Server),
    starts Transit Probe 10, and provides an interactive terminal control panel for live
    fault injection (Link 2 drops, Link 1 drops, and status monitoring).
.EXAMPLE
    .\start_router.ps1
    .\start_router.ps1 -ServerIP 192.168.1.20
#>

param (
    [string]$ServerIP = "",
    [string]$ClientIP = ""
)

# ------------------------------------------------------------------------------
# 1. Administrator Check & Self-Elevation
# ------------------------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "`n[*] Requesting Administrator privileges to configure router and packet capture..." -ForegroundColor Yellow
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -ServerIP `"$ServerIP`" -ClientIP `"$ClientIP`""
    exit
}

Clear-Host
Write-Host "╔══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║           MINI-SHARK INTERMEDIATE ROUTER HUB (LAPTOP 3)              ║" -ForegroundColor Cyan
Write-Host "║        Pure L3 Forwarding (No NAT) + Transit Probe 10                ║" -ForegroundColor Cyan
Write-Host "║                    + Live Fault Injection                            ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

# ------------------------------------------------------------------------------
# 2. Interactive IP Configuration
# ------------------------------------------------------------------------------
if ([string]::IsNullOrWhiteSpace($ServerIP)) {
    Write-Host "Enter Central Server Hub IP (Laptop 4) [e.g. 192.168.1.20]: " -NoNewline -ForegroundColor Yellow
    $ServerIP = (Read-Host).Trim()
}

while ([string]::IsNullOrWhiteSpace($ServerIP)) {
    Write-Host "Server IP cannot be empty. Please enter Server IP: " -NoNewline -ForegroundColor Red
    $ServerIP = (Read-Host).Trim()
}

# ------------------------------------------------------------------------------
# 3. Enable Pure L3 IP Forwarding
# ------------------------------------------------------------------------------
Write-Host "`n[1/3] Enabling Windows Pure Layer-3 IP Forwarding..." -ForegroundColor Cyan
$setupRouterScript = Join-Path $ScriptDir "scripts\setup_windows_router.ps1"
if (Test-Path $setupRouterScript) {
    & powershell -ExecutionPolicy Bypass -File $setupRouterScript -Action enable-routing
} else {
    Write-Host "[*] Enabling IP forwarding directly..." -ForegroundColor Yellow
    Set-NetIPInterface -Forwarding Enabled -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "IPEnableRouter" -Value 1 -ErrorAction SilentlyContinue
    Set-Service -Name RemoteAccess -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name RemoteAccess -ErrorAction SilentlyContinue
}

# ------------------------------------------------------------------------------
# 4. Verify Python and Scapy
# ------------------------------------------------------------------------------
Write-Host "`n[2/3] Checking Python & Scapy dependencies..." -ForegroundColor Cyan
try {
    $pythonVersion = python --version 2>&1
    Write-Host "  • Found Python: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "[Error] Python is not installed or not in PATH! Please install Python 3.10+." -ForegroundColor Red
    Pause
    exit 1
}

$hasScapy = python -c "import scapy" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "  • Installing Scapy for Windows Npcap capture..." -ForegroundColor Yellow
    pip install scapy
} else {
    Write-Host "  • Scapy library: OK" -ForegroundColor Green
}

# ------------------------------------------------------------------------------
# 5. Launch Probe 10
# ------------------------------------------------------------------------------
Write-Host "`n[3/3] Launching Transit Probe 10 (Connecting to ${ServerIP}:9000)..." -ForegroundColor Cyan

$probeScript = Join-Path $ScriptDir "run_probe.py"
# Launch Probe 10 in a separate visible console so capture output is always viewable
$probeProcess = Start-Process python -ArgumentList "`"$probeScript`" --server ${ServerIP}:9000 --role router" -PassThru

Write-Host "  [✓] Probe 10 running in dedicated monitor window (PID: $($probeProcess.Id))" -ForegroundColor Green
Write-Host "      Telemetry streaming to ${ServerIP}:9000" -ForegroundColor Gray

# ------------------------------------------------------------------------------
# 6. Interactive Fault Injection Menu Loop
# ------------------------------------------------------------------------------
function Cleanup-And-Exit {
    Write-Host "`n[*] Stopping Probe 10 and cleaning up..." -ForegroundColor Yellow
    if ($probeProcess -and -not $probeProcess.HasExited) {
        Stop-Process -Id $probeProcess.Id -Force -ErrorAction SilentlyContinue
    }
    # Clear any active drop firewall rules
    if (Test-Path $setupRouterScript) {
        & powershell -ExecutionPolicy Bypass -File $setupRouterScript -Action clear-drops
    }
    Write-Host "[✓] Router returned to clean state. Exiting." -ForegroundColor Green
    exit 0
}

# Register Ctrl+C handler
[Console]::TreatControlCAsInput = $false

while ($true) {
    Write-Host "`n======================================================================" -ForegroundColor Cyan
    Write-Host "             ROUTER FAULT INJECTION & CONTROL BENCH                   " -ForegroundColor Cyan
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host "  Server Hub IP : $ServerIP" -ForegroundColor White
    Write-Host "  Probe 10 PID  : $($probeProcess.Id) (Running: $(if (-not $probeProcess.HasExited) {'YES'} else {'NO (Exited!)'}))" -ForegroundColor Gray
    Write-Host "----------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  [1] Inject Link 2 Drop  (Router ──✖──> Server Hub)" -ForegroundColor Yellow
    Write-Host "  [2] Inject Link 1 Drop  (Client ──✖──> Router)" -ForegroundColor Yellow
    Write-Host "  [3] Clear All Drops     (Restore 100% normal transmission)" -ForegroundColor Green
    Write-Host "  [4] Show Router & Drop Status" -ForegroundColor White
    Write-Host "  [5] Restart Probe 10" -ForegroundColor White
    Write-Host "  [6] Exit & Cleanup" -ForegroundColor Red
    Write-Host "----------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "Select an option [1-6]: " -NoNewline -ForegroundColor Cyan

    $choice = Read-Host

    switch ($choice) {
        "1" {
            Write-Host "`n[!] Activating Link 2 Drop towards Server ($ServerIP)..." -ForegroundColor Yellow
            & powershell -ExecutionPolicy Bypass -File $setupRouterScript -Action drop-link2 -ServerIP $ServerIP
            Write-Host "➜ Packets will now turn RED on Dashboard: 'Dropped on Link 2: Router ──✖──> Server Hub'" -ForegroundColor Magenta
        }
        "2" {
            if ([string]::IsNullOrWhiteSpace($ClientIP)) {
                Write-Host "Enter Client IP to drop [e.g. 192.168.1.15]: " -NoNewline -ForegroundColor Yellow
                $ClientIP = (Read-Host).Trim()
            }
            if (-not [string]::IsNullOrWhiteSpace($ClientIP)) {
                Write-Host "`n[!] Activating Link 1 Drop for Client ($ClientIP)..." -ForegroundColor Yellow
                & powershell -ExecutionPolicy Bypass -File $setupRouterScript -Action drop-link1 -ClientIP $ClientIP
            }
        }
        "3" {
            Write-Host "`n[*] Restoring clean link transmission..." -ForegroundColor Green
            & powershell -ExecutionPolicy Bypass -File $setupRouterScript -Action clear-drops
        }
        "4" {
            & powershell -ExecutionPolicy Bypass -File $setupRouterScript -Action status
        }
        "5" {
            if ($probeProcess -and -not $probeProcess.HasExited) {
                Stop-Process -Id $probeProcess.Id -Force -ErrorAction SilentlyContinue
            }
            Write-Host "`n[*] Restarting Probe 10..." -ForegroundColor Cyan
            $probeProcess = Start-Process python -ArgumentList "`"$probeScript`" --server ${ServerIP}:9000 --role router" -PassThru
            Write-Host "[✓] Probe 10 restarted (PID: $($probeProcess.Id))" -ForegroundColor Green
        }
        "6" {
            Cleanup-And-Exit
        }
        Default {
            Write-Host "Invalid option. Please enter 1-6." -ForegroundColor Red
        }
    }
}
