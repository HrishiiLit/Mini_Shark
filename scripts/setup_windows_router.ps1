<#
.SYNOPSIS
    Mini-Shark Windows Intermediate Router Configuration & Fault Injection Tool
.DESCRIPTION
    Configures a Windows laptop as an intermediate pure L3 router (Client -> Router -> Server)
    and provides controlled fault injection (Link 1 vs Link 2 packet drops).
.EXAMPLE
    .\scripts\setup_windows_router.ps1 -Action enable-routing
    .\scripts\setup_windows_router.ps1 -Action drop-link1 -ClientIP 192.168.1.15
    .\scripts\setup_windows_router.ps1 -Action drop-link2 -ServerIP 192.168.1.20
    .\scripts\setup_windows_router.ps1 -Action clear-drops
    .\scripts\setup_windows_router.ps1 -Action status
#>

param (
    [Parameter(Mandatory=$true, Position=0)]
    [ValidateSet("enable-routing", "drop-link1", "drop-link2", "clear-drops", "status")]
    [string]$Action,

    [Parameter(Mandatory=$false)]
    [string]$ClientIP = "",

    [Parameter(Mandatory=$false)]
    [string]$ServerIP = ""
)

# Ensure running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[Error] This script must be run in PowerShell as Administrator!" -ForegroundColor Red
    exit 1
}

function Enable-Routing {
    Write-Host "`n[*] Enabling IPv4 Packet Forwarding on all network interfaces..." -ForegroundColor Cyan
    Set-NetIPInterface -Forwarding Enabled -ErrorAction SilentlyContinue

    Write-Host "[*] Setting registry key IPEnableRouter = 1..." -ForegroundColor Cyan
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "IPEnableRouter" -Value 1

    Write-Host "[*] Enabling and starting Routing and Remote Access service..." -ForegroundColor Cyan
    Set-Service -Name RemoteAccess -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name RemoteAccess -ErrorAction SilentlyContinue

    Write-Host "[*] Ensuring Windows Firewall allows forwarded traffic & ICMP..." -ForegroundColor Cyan
    New-NetFirewallRule -DisplayName "MiniShark-Allow-Forwarding" -Direction Inbound -Action Allow -Protocol Any -Profile Any -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -DisplayName "MiniShark-Allow-ICMP" -Direction Inbound -Action Allow -Protocol ICMPv4 -Profile Any -ErrorAction SilentlyContinue | Out-Null

    Write-Host "`n[✓] SUCCESS: Windows Pure Layer-3 Routing is now ENABLED!" -ForegroundColor Green
    Write-Host "    Note: If this is the first time enabling IPEnableRouter, a system reboot may be required if services don't start." -ForegroundColor Yellow
}

function Drop-Link1 {
    if (-not $ClientIP) {
        Write-Host "[Error] Please provide -ClientIP (e.g. .\setup_windows_router.ps1 -Action drop-link1 -ClientIP 192.168.1.15)" -ForegroundColor Red
        return
    }
    Write-Host "`n[!] Injecting drop on Link 1 (Client $ClientIP ──✖──> Router)..." -ForegroundColor Yellow
    Remove-NetFirewallRule -DisplayName "MiniShark-Drop-Link1" -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName "MiniShark-Drop-Link1" -Direction Inbound -Action Block -RemoteAddress $ClientIP -Profile Any | Out-Null
    Write-Host "[✓] Link 1 drop ACTIVE. Traffic from $ClientIP is dropped at router ingress." -ForegroundColor Green
    Write-Host "    Mini-Shark will attribute these as: Dropped on Link 1: Client ──✖──> Router" -ForegroundColor Yellow
}

function Drop-Link2 {
    if (-not $ServerIP) {
        Write-Host "[Error] Please provide -ServerIP (e.g. .\setup_windows_router.ps1 -Action drop-link2 -ServerIP 192.168.1.20)" -ForegroundColor Red
        return
    }
    Write-Host "`n[!] Injecting drop on Link 2 (Router ──✖──> Server Hub $ServerIP)..." -ForegroundColor Yellow
    Remove-NetFirewallRule -DisplayName "MiniShark-Drop-Link2" -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName "MiniShark-Drop-Link2" -Direction Outbound -Action Block -RemoteAddress $ServerIP -Profile Any | Out-Null
    Write-Host "[✓] Link 2 drop ACTIVE. Traffic forwarded towards $ServerIP is blocked at router egress." -ForegroundColor Green
    Write-Host "    Mini-Shark will attribute these as: Dropped on Link 2: Router ──✖──> Server Hub" -ForegroundColor Yellow
}

function Clear-Drops {
    Write-Host "`n[*] Removing all injected drop rules..." -ForegroundColor Cyan
    Remove-NetFirewallRule -DisplayName "MiniShark-Drop-Link1" -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName "MiniShark-Drop-Link2" -ErrorAction SilentlyContinue
    Write-Host "[✓] All drop rules removed. Network transmission restored to 100% normal." -ForegroundColor Green
}

function Show-Status {
    Write-Host "`n=== Windows Router Status ===" -ForegroundColor Cyan
    $reg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "IPEnableRouter" -ErrorAction SilentlyContinue
    Write-Host "Registry IPEnableRouter: $($reg.IPEnableRouter)"
    $svc = Get-Service -Name RemoteAccess -ErrorAction SilentlyContinue
    Write-Host "RemoteAccess Service   : $($svc.Status)"
    Write-Host "`n--- Network Interfaces Forwarding State ---"
    Get-NetIPInterface -AddressFamily IPv4 | Select-Object InterfaceAlias, InterfaceIndex, Forwarding | Format-Table -AutoSize

    Write-Host "--- Active Mini-Shark Drop Rules ---"
    $rules = Get-NetFirewallRule -DisplayName "MiniShark-Drop-*" -ErrorAction SilentlyContinue
    if ($rules) {
        $rules | Select-Object DisplayName, Direction, Action, Enabled | Format-Table -AutoSize
    } else {
        Write-Host "No active drop rules (Links are clean)." -ForegroundColor Green
    }
}

switch ($Action) {
    "enable-routing" { Enable-Routing }
    "drop-link1"     { Drop-Link1 }
    "drop-link2"     { Drop-Link2 }
    "clear-drops"    { Clear-Drops }
    "status"         { Show-Status }
}
