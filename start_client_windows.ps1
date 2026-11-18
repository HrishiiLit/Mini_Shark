<#
.SYNOPSIS
    Mini-Shark Laptop 2 (Client 2 — Windows) — All-in-One Automation Tool
.DESCRIPTION
    Configures Client 2 as either the Destination / Egress Node (Probe 2) for Client-to-Client tracing,
    or as a concurrent traffic sender (Probe 12).
.EXAMPLE
    .\start_client_windows.ps1
    .\start_client_windows.ps1 -HubIP 192.168.1.20 -RouterIP 192.168.1.10 -Client1IP 192.168.1.15
#>

param (
    [string]$HubIP = "",
    [string]$RouterIP = "",
    [string]$Client1IP = "",
    [int]$Mode = 1
)

# ------------------------------------------------------------------------------
# 1. Administrator Check & Self-Elevation
# ------------------------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "`n[*] Requesting Administrator privileges to configure routing & packet capture..." -ForegroundColor Yellow
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -HubIP `"$HubIP`" -RouterIP `"$RouterIP`" -Client1IP `"$Client1IP`""
    exit
}

Clear-Host
Write-Host "╔══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║              MINI-SHARK CLIENT 2 (WINDOWS 10/11)                     ║" -ForegroundColor Cyan
Write-Host "║          Client-to-Client Destination (Probe 2 / Egress)             ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

# ------------------------------------------------------------------------------
# 2. Interactive IP Configuration
# ------------------------------------------------------------------------------
if ([string]::IsNullOrWhiteSpace($HubIP)) {
    Write-Host "Enter Central Monitoring Hub IP (Laptop 4) [e.g. 192.168.1.20]: " -NoNewline -ForegroundColor Yellow
    $HubIP = (Read-Host).Trim()
}
while ([string]::IsNullOrWhiteSpace($HubIP)) {
    Write-Host "Hub IP cannot be empty. Please enter Hub IP: " -NoNewline -ForegroundColor Red
    $HubIP = (Read-Host).Trim()
}

if ([string]::IsNullOrWhiteSpace($RouterIP)) {
    Write-Host "Enter Intermediate Router IP (Laptop 3) [e.g. 192.168.1.10]: " -NoNewline -ForegroundColor Yellow
    $RouterIP = (Read-Host).Trim()
}
while ([string]::IsNullOrWhiteSpace($RouterIP)) {
    Write-Host "Router IP cannot be empty. Please enter Router IP: " -NoNewline -ForegroundColor Red
    $RouterIP = (Read-Host).Trim()
}

if ([string]::IsNullOrWhiteSpace($Client1IP)) {
    Write-Host "Enter Client 1 IP (Sender - Laptop 1) [e.g. 192.168.1.15, or Enter to skip]: " -NoNewline -ForegroundColor Yellow
    $Client1IP = (Read-Host).Trim()
}

Write-Host "`nSelect Operational Role for Client 2:" -ForegroundColor Cyan
Write-Host "  [1] Destination Receiver Node (Probe 2 - Egress Observer) [RECOMMENDED for Client-to-Client]" -ForegroundColor Green
Write-Host "  [2] Concurrent Traffic Sender (Probe 12 - Ingress Sender)" -ForegroundColor Yellow
Write-Host "Choice [1 or 2, default 1]: " -NoNewline -ForegroundColor Cyan
$modeChoice = (Read-Host).Trim()
if ($modeChoice -eq "2") { $Mode = 2 } else { $Mode = 1 }

# ------------------------------------------------------------------------------
# 3. Configure Return Route via Router (if Client1IP is provided)
# ------------------------------------------------------------------------------
if (-not [string]::IsNullOrWhiteSpace($Client1IP)) {
    Write-Host "`n[1/4] Adding static return route to Client 1 ($Client1IP) via Router ($RouterIP)..." -ForegroundColor Cyan
    route delete $Client1IP 2>$null | Out-Null
    $routeOutput = route add $Client1IP mask 255.255.255.255 $RouterIP 2>&1
    if ($LASTEXITCODE -eq 0 -or $routeOutput -match "OK!") {
        Write-Host "  • Static return route configured: OK" -ForegroundColor Green
    } else {
        Write-Host "  • Route command result: $routeOutput" -ForegroundColor Gray
    }
}

# ------------------------------------------------------------------------------
# 4. Check Python and Scapy
# ------------------------------------------------------------------------------
Write-Host "`n[2/4] Checking Python & Scapy dependencies..." -ForegroundColor Cyan
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
# 5. Launch Probe and Traffic Receiver
# ------------------------------------------------------------------------------
$probeScript = Join-Path $ScriptDir "run_probe.py"
$receiverScript = Join-Path $ScriptDir "scripts\traffic_receiver.py"
$receiverProcess = $null
$trafficProcess = $null

if ($Mode -eq 1) {
    # Destination Node: Probe 2 (Egress)
    Write-Host "`n[3/4] Launching Egress Probe 2 (Connecting to ${HubIP}:9000)..." -ForegroundColor Cyan
    $probeProcess = Start-Process python -ArgumentList "`"$probeScript`" --server ${HubIP}:9000 --role server" -PassThru
    Write-Host "  [✓] Egress Probe 2 running in monitor window (PID: $($probeProcess.Id))" -ForegroundColor Green
    Write-Host "      Observing incoming packets from Client 1 via Router" -ForegroundColor Gray

    # Ensure Windows Firewall allows incoming HTTP (8000, 8001), UDP (9500), and ICMP Ping
    Write-Host "`n[*] Configuring Windows Firewall to allow incoming test traffic..." -ForegroundColor Cyan
    New-NetFirewallRule -DisplayName "MiniShark-Allow-HTTP" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8000,8001 -Profile Any -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -DisplayName "MiniShark-Allow-UDP" -Direction Inbound -Action Allow -Protocol UDP -LocalPort 9500 -Profile Any -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -DisplayName "MiniShark-Allow-ICMP" -Direction Inbound -Action Allow -Protocol ICMPv4 -Profile Any -ErrorAction SilentlyContinue | Out-Null
    Write-Host "  • Windows Firewall allow rules (TCP 8000/8001, UDP 9500, ICMP): ACTIVE" -ForegroundColor Green

    # Launch dual HTTP + UDP receiver service with live receipts
    Write-Host "`n[4/4] Starting Multi-Protocol Traffic Receiver (HTTP :8000 + UDP :9500)..." -ForegroundColor Cyan
    if (Test-Path $receiverScript) {
        $receiverProcess = Start-Process python -ArgumentList "`"$receiverScript`" --http-port 8000 --udp-port 9500" -PassThru
        Write-Host "  [✓] Traffic Receiver running in monitor window (PID: $($receiverProcess.Id))" -ForegroundColor Green
        Write-Host "      Live HTTP GET & UDP stream receipts will appear in that window!" -ForegroundColor Gray
    } else {
        $receiverProcess = Start-Process python -ArgumentList "-m http.server 8000" -WindowStyle Minimized -PassThru
        Write-Host "  [✓] Local HTTP fallback service active on port 8000 (PID: $($receiverProcess.Id))" -ForegroundColor Green
    }
} else {
    # Concurrent Sender Mode: Probe 12 (Ingress)
    Write-Host "`n[3/4] Launching Client Probe 12 (Connecting to ${HubIP}:9000)..." -ForegroundColor Cyan
    $probeProcess = Start-Process python -ArgumentList "`"$probeScript`" --server ${HubIP}:9000 --probe-id 12" -PassThru
    Write-Host "  [✓] Probe 12 running in monitor window (PID: $($probeProcess.Id))" -ForegroundColor Green
}

# ------------------------------------------------------------------------------
# 6. Interactive Control Bench Menu Loop
# ------------------------------------------------------------------------------
function Stop-Processes {
    if ($script:receiverProcess -and -not $script:receiverProcess.HasExited) {
        Stop-Process -Id $script:receiverProcess.Id -Force -ErrorAction SilentlyContinue
    }
    if ($script:trafficProcess -and -not $script:trafficProcess.HasExited) {
        Stop-Process -Id $script:trafficProcess.Id -Force -ErrorAction SilentlyContinue
    }
    if ($script:probeProcess -and -not $script:probeProcess.HasExited) {
        Stop-Process -Id $script:probeProcess.Id -Force -ErrorAction SilentlyContinue
    }
}

function Cleanup-And-Exit {
    Write-Host "`n[*] Stopping services and removing static routes..." -ForegroundColor Yellow
    Stop-Processes

    if (-not [string]::IsNullOrWhiteSpace($Client1IP)) {
        Write-Host "[*] Deleting static return route to $Client1IP..." -ForegroundColor Cyan
        route delete $Client1IP 2>$null | Out-Null
    }

    # Clear firewall rules
    Remove-NetFirewallRule -DisplayName "MiniShark-Client2-Drop" -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName "MiniShark-Allow-HTTP" -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName "MiniShark-Allow-UDP" -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName "MiniShark-Allow-ICMP" -ErrorAction SilentlyContinue

    Write-Host "[✓] Client 2 restored to clean state. Exiting." -ForegroundColor Green
    exit 0
}

while ($true) {
    Write-Host "`n======================================================================" -ForegroundColor Cyan
    if ($Mode -eq 1) {
        Write-Host "     CLIENT 2 (DESTINATION NODE / PROBE 2) CONTROL BENCH              " -ForegroundColor Cyan
    } else {
        Write-Host "     CLIENT 2 (CONCURRENT SENDER / PROBE 12) CONTROL BENCH            " -ForegroundColor Cyan
    }
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host "  Telemetry Hub IP: $HubIP" -ForegroundColor White
    Write-Host "  Router IP       : $RouterIP" -ForegroundColor White
    Write-Host "  Client 1 IP     : $(if ($Client1IP) {$Client1IP} else {'(Not specified)'})" -ForegroundColor White
    Write-Host "  Probe PID       : $($probeProcess.Id) (Running: $(if (-not $probeProcess.HasExited) {'YES'} else {'NO'}))" -ForegroundColor Gray
    if ($Mode -eq 1) {
        Write-Host "  HTTP Receiver   : Port 8000 (Active PID: $($receiverProcess.Id))" -ForegroundColor Green
    }
    Write-Host "----------------------------------------------------------------------" -ForegroundColor DarkGray
    if ($Mode -eq 1) {
        Write-Host "  [1] Show Connectivity to Client 1 & Router (Ping test)" -ForegroundColor Yellow
        Write-Host "  [2] Inject Link 2 Drop at Receiver (Inbound Firewall Block)" -ForegroundColor Red
        Write-Host "  [3] Clear Injected Drops (Restore 100% normal transmission)" -ForegroundColor Green
        Write-Host "  [4] Restart Egress Probe 2" -ForegroundColor White
        Write-Host "  [5] Exit & Cleanup" -ForegroundColor Red
    } else {
        Write-Host "  [1] Start Continuous HTTP Workload (5 req/s)" -ForegroundColor Yellow
        Write-Host "  [2] Start Continuous ICMP Ping" -ForegroundColor Yellow
        Write-Host "  [3] Stop Active Workload" -ForegroundColor Gray
        Write-Host "  [4] Restart Probe 12" -ForegroundColor White
        Write-Host "  [5] Exit & Cleanup" -ForegroundColor Red
    }
    Write-Host "----------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "Select an option [1-5]: " -NoNewline -ForegroundColor Cyan

    $choice = Read-Host

    if ($Mode -eq 1) {
        switch ($choice) {
            "1" {
                if ($Client1IP) {
                    Write-Host "`n--- Testing Connectivity to Client 1 ($Client1IP) ---" -ForegroundColor Cyan
                    Test-Connection -ComputerName $Client1IP -Count 2
                }
                Write-Host "`n--- Testing Connectivity to Router ($RouterIP) ---" -ForegroundColor Cyan
                Test-Connection -ComputerName $RouterIP -Count 2
            }
            "2" {
                Write-Host "`n[!] Blocking inbound traffic from Router / Client 1 to simulate Link 2 drop..." -ForegroundColor Yellow
                Remove-NetFirewallRule -DisplayName "MiniShark-Client2-Drop" -ErrorAction SilentlyContinue
                New-NetFirewallRule -DisplayName "MiniShark-Client2-Drop" -Direction Inbound -Action Block -RemoteAddress $RouterIP -Profile Any | Out-Null
                Write-Host "[✓] Inbound block active. Packets from Router will be dropped before reaching Client 2!" -ForegroundColor Green
                Write-Host "    Dashboard will show: 'Dropped on Link 2: Router ──✖──> Destination (Probe 2)'" -ForegroundColor Magenta
            }
            "3" {
                Write-Host "`n[*] Restoring clean reception..." -ForegroundColor Green
                Remove-NetFirewallRule -DisplayName "MiniShark-Client2-Drop" -ErrorAction SilentlyContinue
                Write-Host "[✓] Firewall drop rules cleared." -ForegroundColor Green
            }
            "4" {
                if ($probeProcess -and -not $probeProcess.HasExited) {
                    Stop-Process -Id $probeProcess.Id -Force -ErrorAction SilentlyContinue
                }
                Write-Host "`n[*] Restarting Egress Probe 2..." -ForegroundColor Cyan
                $probeProcess = Start-Process python -ArgumentList "`"$probeScript`" --server ${HubIP}:9000 --role server" -PassThru
                Write-Host "[✓] Egress Probe 2 restarted (PID: $($probeProcess.Id))" -ForegroundColor Green
            }
            "5" {
                Cleanup-And-Exit
            }
            Default {
                Write-Host "Invalid option. Please enter 1-5." -ForegroundColor Red
            }
        }
    } else {
        switch ($choice) {
            "1" {
                if ($trafficProcess -and -not $trafficProcess.HasExited) { Stop-Process -Id $trafficProcess.Id -Force }
                $trafficScript = Join-Path $ScriptDir "scripts\traffic_generator.py"
                $target = if ($Client1IP) { $Client1IP } else { $HubIP }
                Write-Host "`n[*] Starting continuous HTTP queries against $target..." -ForegroundColor Yellow
                $trafficProcess = Start-Process python -ArgumentList "`"$trafficScript`" --target $target --mode http --rate 5" -PassThru
                Write-Host "[✓] HTTP traffic running in background (PID: $($trafficProcess.Id))" -ForegroundColor Green
            }
            "2" {
                if ($trafficProcess -and -not $trafficProcess.HasExited) { Stop-Process -Id $trafficProcess.Id -Force }
                $target = if ($Client1IP) { $Client1IP } else { $HubIP }
                Write-Host "`n[*] Starting continuous ping to $target..." -ForegroundColor Yellow
                $trafficProcess = Start-Process ping -ArgumentList "$target -t" -PassThru
                Write-Host "[✓] Continuous ping running in background (PID: $($trafficProcess.Id))" -ForegroundColor Green
            }
            "3" {
                if ($trafficProcess -and -not $trafficProcess.HasExited) {
                    Stop-Process -Id $trafficProcess.Id -Force
                    Write-Host "[✓] Workload stopped." -ForegroundColor Green
                }
            }
            "4" {
                if ($probeProcess -and -not $probeProcess.HasExited) {
                    Stop-Process -Id $probeProcess.Id -Force -ErrorAction SilentlyContinue
                }
                Write-Host "`n[*] Restarting Probe 12..." -ForegroundColor Cyan
                $probeProcess = Start-Process python -ArgumentList "`"$probeScript`" --server ${HubIP}:9000 --probe-id 12" -PassThru
                Write-Host "[✓] Probe 12 restarted (PID: $($probeProcess.Id))" -ForegroundColor Green
            }
            "5" {
                Cleanup-And-Exit
            }
            Default {
                Write-Host "Invalid option. Please enter 1-5." -ForegroundColor Red
            }
        }
    }
}
