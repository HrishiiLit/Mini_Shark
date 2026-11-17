<#
.SYNOPSIS
    Mini-Shark Laptop 2 (Client 2 — Windows) — All-in-One Automation Tool
.DESCRIPTION
    Configures static routing via the intermediate Windows Router, starts Client Probe 12,
    and provides an interactive menu for generating concurrent background traffic (HTTP / Ping).
.EXAMPLE
    .\start_client_windows.ps1
    .\start_client_windows.ps1 -ServerIP 192.168.1.20 -RouterIP 192.168.1.10
#>

param (
    [string]$ServerIP = "",
    [string]$RouterIP = ""
)

# ------------------------------------------------------------------------------
# 1. Administrator Check & Self-Elevation
# ------------------------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "`n[*] Requesting Administrator privileges to configure routing & packet capture..." -ForegroundColor Yellow
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -ServerIP `"$ServerIP`" -RouterIP `"$RouterIP`""
    exit
}

Clear-Host
Write-Host "╔══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║              MINI-SHARK CLIENT 2 (WINDOWS 10/11)                     ║" -ForegroundColor Cyan
Write-Host "║           Client Probe 12 + Background Traffic Generator             ║" -ForegroundColor Cyan
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

if ([string]::IsNullOrWhiteSpace($RouterIP)) {
    Write-Host "Enter Intermediate Router IP (Laptop 3) [e.g. 192.168.1.10]: " -NoNewline -ForegroundColor Yellow
    $RouterIP = (Read-Host).Trim()
}
while ([string]::IsNullOrWhiteSpace($RouterIP)) {
    Write-Host "Router IP cannot be empty. Please enter Router IP: " -NoNewline -ForegroundColor Red
    $RouterIP = (Read-Host).Trim()
}

# ------------------------------------------------------------------------------
# 3. Configure Static Route via Router
# ------------------------------------------------------------------------------
Write-Host "`n[1/3] Adding static route to Server ($ServerIP) via Router ($RouterIP)..." -ForegroundColor Cyan
route delete $ServerIP 2>$null | Out-Null
$routeOutput = route add $ServerIP mask 255.255.255.255 $RouterIP 2>&1
if ($LASTEXITCODE -eq 0 -or $routeOutput -match "OK!") {
    Write-Host "  • Static route configured: OK" -ForegroundColor Green
} else {
    Write-Host "  • Route command result: $routeOutput" -ForegroundColor Gray
}

# ------------------------------------------------------------------------------
# 4. Check Python and Scapy
# ------------------------------------------------------------------------------
Write-Host "`n[2/3] Checking Python & Scapy dependencies..." -ForegroundColor Cyan
try {
    $pythonVer = python --version 2>&1
    Write-Host "  • Python: $pythonVer" -ForegroundColor Green
} catch {
    Write-Host "[Error] Python not found in PATH! Please install Python 3.10+." -ForegroundColor Red
    Pause
    exit 1
}

$hasScapy = python -c "import scapy" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "  • Installing Scapy..." -ForegroundColor Yellow
    pip install scapy
} else {
    Write-Host "  • Scapy library: OK" -ForegroundColor Green
}

# ------------------------------------------------------------------------------
# 5. Launch Probe 12
# ------------------------------------------------------------------------------
Write-Host "`n[3/3] Launching Client Probe 12 (Connecting to ${ServerIP}:9000)..." -ForegroundColor Cyan
$probeScript = Join-Path $ScriptDir "run_probe.py"
$probeProcess = Start-Process python -ArgumentList "`"$probeScript`" --server ${ServerIP}:9000 --probe-id 12" -PassThru

Write-Host "  [✓] Probe 12 running in monitor window (PID: $($probeProcess.Id))" -ForegroundColor Green
Write-Host "      Telemetry streaming to ${ServerIP}:9000" -ForegroundColor Gray

# ------------------------------------------------------------------------------
# 6. Interactive Traffic Generator Menu
# ------------------------------------------------------------------------------
$trafficProcess = $null

function Stop-Workload {
    if ($script:trafficProcess -and -not $script:trafficProcess.HasExited) {
        Write-Host "`n[*] Stopping active background traffic generator..." -ForegroundColor Yellow
        Stop-Process -Id $script:trafficProcess.Id -Force -ErrorAction SilentlyContinue
        $script:trafficProcess = $null
        Write-Host "[✓] Traffic generator stopped." -ForegroundColor Green
    }
}

function Cleanup-And-Exit {
    Write-Host "`n[*] Stopping Probe 12 and removing static routes..." -ForegroundColor Yellow
    Stop-Workload

    if ($probeProcess -and -not $probeProcess.HasExited) {
        Stop-Process -Id $probeProcess.Id -Force -ErrorAction SilentlyContinue
    }

    Write-Host "[*] Deleting static route to $ServerIP..." -ForegroundColor Cyan
    route delete $ServerIP 2>$null | Out-Null

    Write-Host "[✓] Network restored to clean state. Exiting." -ForegroundColor Green
    exit 0
}

while ($true) {
    $workloadStatus = if ($trafficProcess -and -not $trafficProcess.HasExited) { "RUNNING (PID: $($trafficProcess.Id))" } else { "Idle" }

    Write-Host "`n======================================================================" -ForegroundColor Cyan
    Write-Host "             CLIENT 2 CONTROL BENCH & WORKLOAD (WINDOWS)              " -ForegroundColor Cyan
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host "  Server Hub IP   : $ServerIP" -ForegroundColor White
    Write-Host "  Router IP       : $RouterIP" -ForegroundColor White
    Write-Host "  Probe 12 PID    : $($probeProcess.Id) (Running: $(if (-not $probeProcess.HasExited) {'YES'} else {'NO'}))" -ForegroundColor Gray
    Write-Host "  Active Workload : $workloadStatus" -ForegroundColor $(if ($workloadStatus -match "RUNNING") {"Green"} else {"Gray"})
    Write-Host "----------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  [1] Start Continuous HTTP Workload (5 req/s)" -ForegroundColor Yellow
    Write-Host "  [2] Start Continuous ICMP Ping (ping $ServerIP -t)" -ForegroundColor Yellow
    Write-Host "  [3] Stop Active Workload" -ForegroundColor Gray
    Write-Host "  [4] Restart Probe 12" -ForegroundColor White
    Write-Host "  [5] Show Route Table & Connectivity" -ForegroundColor White
    Write-Host "  [6] Exit & Cleanup" -ForegroundColor Red
    Write-Host "----------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "Select an option [1-6]: " -NoNewline -ForegroundColor Cyan

    $choice = Read-Host

    switch ($choice) {
        "1" {
            Stop-Workload
            $trafficScript = Join-Path $ScriptDir "scripts\traffic_generator.py"
            Write-Host "`n[*] Starting continuous HTTP queries against Server..." -ForegroundColor Yellow
            $trafficProcess = Start-Process python -ArgumentList "`"$trafficScript`" --target $ServerIP --mode http --rate 5" -PassThru
            Write-Host "[✓] HTTP traffic running in background (PID: $($trafficProcess.Id))" -ForegroundColor Green
        }
        "2" {
            Stop-Workload
            Write-Host "`n[*] Starting continuous ping to $ServerIP..." -ForegroundColor Yellow
            $trafficProcess = Start-Process ping -ArgumentList "$ServerIP -t" -PassThru
            Write-Host "[✓] Continuous ping running in background (PID: $($trafficProcess.Id))" -ForegroundColor Green
        }
        "3" {
            Stop-Workload
        }
        "4" {
            if ($probeProcess -and -not $probeProcess.HasExited) {
                Stop-Process -Id $probeProcess.Id -Force -ErrorAction SilentlyContinue
            }
            Write-Host "`n[*] Restarting Probe 12..." -ForegroundColor Cyan
            $probeProcess = Start-Process python -ArgumentList "`"$probeScript`" --server ${ServerIP}:9000 --probe-id 12" -PassThru
            Write-Host "[✓] Probe 12 restarted (PID: $($probeProcess.Id))" -ForegroundColor Green
        }
        "5" {
            Write-Host "`n--- Active Host Route for $ServerIP ---" -ForegroundColor Cyan
            route print $ServerIP
            Write-Host "`n--- Ping Test to $ServerIP ---" -ForegroundColor Cyan
            Test-Connection -ComputerName $ServerIP -Count 2
        }
        "6" {
            Cleanup-And-Exit
        }
        Default {
            Write-Host "Invalid option. Please enter 1-6." -ForegroundColor Red
        }
    }
}
