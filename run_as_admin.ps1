# Mini-Shark Administrator Mode Launcher
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "`n[*] Requesting Administrator permissions for Npcap raw packet capture..." -ForegroundColor Yellow
    $argList = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if ($args.Count -gt 0) {
        $argList += " " + ($args -join " ")
    }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $argList
    exit
}

$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $PSCommandPath }
Set-Location $ScriptDir

# Clear any conflicting portproxy rules on 8001/9000 (from cross-laptop forwarding)
try {
    $proxyTable = netsh interface portproxy show v4tov4 | Out-String
    if ($proxyTable -match "8001|9000") {
        Write-Host "[*] Found conflicting Windows portproxy rules on ports 8001/9000." -ForegroundColor Yellow
        Write-Host "    Clearing portproxy so Mini-Shark can bind directly to default ports..." -ForegroundColor Yellow
        netsh interface portproxy delete v4tov4 listenport=8001 listenaddress=0.0.0.0 2>$null | Out-Null
        netsh interface portproxy delete v4tov4 listenport=9000 listenaddress=0.0.0.0 2>$null | Out-Null
    }
} catch {}

# Resolve python interpreter
$pyCmd = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $pyCmd -or $pyCmd -like "*WindowsApps*") {
    $candidates = @(
        "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python310\python.exe",
        "C:\Program Files\Python311\python.exe",
        "C:\Program Files\Python312\python.exe",
        "C:\Program Files\Python310\python.exe"
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) {
            $pyCmd = $c
            break
        }
    }
}
if (-not $pyCmd) { $pyCmd = "python" }

Write-Host "=======================================================" -ForegroundColor Green
Write-Host " Mini-Shark: Live Wire Packet Sniffing Mode (Admin)" -ForegroundColor Green
Write-Host " Python   : $pyCmd" -ForegroundColor Cyan
Write-Host " Directory: $ScriptDir" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Green

& $pyCmd run_minishark.py $args

if ($LASTEXITCODE -ne 0) {
    Write-Host "`n[Mini-Shark] Server exited with code $LASTEXITCODE." -ForegroundColor Red
    Read-Host "Press Enter to exit..."
}
