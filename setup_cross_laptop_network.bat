@echo off
:: Mini-Shark - Port Forwarding & Firewall Setup for Cross-Laptop Integration
:: Run this file as Administrator (Right click -> Run as administrator)

echo =====================================================================
echo  Mini-Shark: Setting up Port Forwarding and Firewall for Laptop 2
echo =====================================================================
echo.

:: 0. Set Wi-Fi to Private Network (Enables Local Discovery)
echo [1/7] Switching Wi-Fi profile from Public to Private...
powershell -Command "Set-NetConnectionProfile -InterfaceAlias 'Wi-Fi' -NetworkCategory Private"

:: 1. Forward Windows port 2222 -> VM1 SSH port 22
echo [2/7] Forwarding Port 2222 (SSH) to VM1 (192.168.130.129:22)...
netsh interface portproxy add v4tov4 listenport=2222 listenaddress=0.0.0.0 connectport=22 connectaddress=192.168.130.129

:: 2. Forward E3 Hub port 9000 -> VM1 port 9000
echo [2/6] Forwarding Port 9000 (E3 Hub) to VM1 (192.168.130.129:9000)...
netsh interface portproxy add v4tov4 listenport=9000 listenaddress=0.0.0.0 connectport=9000 connectaddress=192.168.130.129

:: 3. Forward API port 8001 -> VM1 port 8001
echo [3/6] Forwarding Port 8001 (FastAPI/WebSocket) to VM1 (192.168.130.129:8001)...
netsh interface portproxy add v4tov4 listenport=8001 listenaddress=0.0.0.0 connectport=8001 connectaddress=192.168.130.129

:: 4. Add Firewall Rules
echo [4/6] Adding Windows Firewall Rules...
netsh advfirewall firewall add rule name="MiniShark SSH" dir=in action=allow protocol=TCP localport=2222
netsh advfirewall firewall add rule name="MiniShark E3 Hub" dir=in action=allow protocol=TCP localport=9000
netsh advfirewall firewall add rule name="MiniShark API" dir=in action=allow protocol=TCP localport=8001
netsh advfirewall firewall add rule name="MiniShark Dashboard" dir=in action=allow protocol=TCP localport=5173
netsh advfirewall firewall add rule name="MiniShark ICMP Ping" dir=in action=allow protocol=icmpv4:8,any

:: 5. Display Configuration
echo.
echo [5/6] Verifying Port Forwarding Table:
netsh interface portproxy show all

echo.
echo =====================================================================
echo  SUCCESS! Ports 9000, 8001, 2222, and 5173 are now forwarded and open.
echo  Laptop 2 can now connect to Laptop 1 using IP: 10.60.0.6
echo =====================================================================
pause
