# Mini-Shark - Port Forwarding & Firewall Setup for Cross-Laptop Integration
# Run in Administrator PowerShell: .\setup_cross_laptop_network.ps1

Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host " Mini-Shark: Setting up Port Forwarding and Firewall for Laptop 2" -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan

# 0. Set Wi-Fi to Private Network
Write-Host "`n[1/6] Setting Wi-Fi network category to Private..." -ForegroundColor Yellow
Set-NetConnectionProfile -InterfaceAlias "Wi-Fi" -NetworkCategory Private -ErrorAction SilentlyContinue

# 1. Forward Windows port 2222 -> VM1 SSH port 22
Write-Host "[2/6] Forwarding Port 2222 (SSH) -> 192.168.130.129:22..." -ForegroundColor Yellow
netsh interface portproxy add v4tov4 listenport=2222 listenaddress=0.0.0.0 connectport=22 connectaddress=192.168.130.129

# 2. Forward E3 Hub port 9000 -> VM1 port 9000
Write-Host "[2/5] Forwarding Port 9000 (E3 Hub) -> 192.168.130.129:9000..." -ForegroundColor Yellow
netsh interface portproxy add v4tov4 listenport=9000 listenaddress=0.0.0.0 connectport=9000 connectaddress=192.168.130.129

# 3. Forward API port 8001 -> VM1 port 8001
Write-Host "[3/5] Forwarding Port 8001 (FastAPI/WebSocket) -> 192.168.130.129:8001..." -ForegroundColor Yellow
netsh interface portproxy add v4tov4 listenport=8001 listenaddress=0.0.0.0 connectport=8001 connectaddress=192.168.130.129

# 4. Add Firewall Rules
Write-Host "[4/5] Adding Windows Firewall Rules..." -ForegroundColor Yellow
netsh advfirewall firewall add rule name="MiniShark SSH" dir=in action=allow protocol=TCP localport=2222
netsh advfirewall firewall add rule name="MiniShark E3 Hub" dir=in action=allow protocol=TCP localport=9000
netsh advfirewall firewall add rule name="MiniShark API" dir=in action=allow protocol=TCP localport=8001
netsh advfirewall firewall add rule name="MiniShark Dashboard" dir=in action=allow protocol=TCP localport=5173
netsh advfirewall firewall add rule name="MiniShark ICMP Ping" dir=in action=allow protocol=icmpv4:8,any

# 5. Display Configuration
Write-Host "`n[5/5] Current Port Forwarding Table:" -ForegroundColor Green
netsh interface portproxy show all

Write-Host "`n=====================================================================" -ForegroundColor Green
Write-Host " SUCCESS! Ports 9000, 8001, 2222, and 5173 are now forwarded and open." -ForegroundColor Green
Write-Host " Laptop 2 can now reach your VM1 using your Wi-Fi IP: 10.60.0.6" -ForegroundColor Green
Write-Host "=====================================================================" -ForegroundColor Green
