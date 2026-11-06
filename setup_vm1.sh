#!/bin/bash
# =============================================================
# Mini-Shark — VM1 (Central Hub) Setup Script
# IP: 192.168.130.129
# Runs: E3 server (port 9000) + FastAPI (port 8001) + Probe 2
# =============================================================

set -e
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

echo -e "${CYAN}"
echo "=================================================="
echo "  Mini-Shark VM1 — Central Hub Setup"
echo "  IP: 192.168.130.129"
echo "=================================================="
echo -e "${NC}"

# Step 1: System packages
echo -e "${YELLOW}[1/6] Installing system packages...${NC}"
sudo apt update -qq
sudo apt install -y python3 python3-pip python3-venv git curl net-tools iproute2 \
                    tcpdump nmap netcat-openbsd 2>&1 | tail -5

# Node.js for dashboard
if ! command -v node &> /dev/null; then
    echo -e "${YELLOW}Installing Node.js...${NC}"
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - 2>&1 | tail -3
    sudo apt install -y nodejs 2>&1 | tail -3
fi
echo -e "${GREEN}✓ System packages ready${NC}"

# Step 2: Clone repo
echo -e "${YELLOW}[2/6] Setting up Mini-Shark repository...${NC}"
if [ ! -d "$HOME/Mini_Shark" ]; then
    git clone https://github.com/HrishiiLit/Mini_Shark.git "$HOME/Mini_Shark"
else
    echo "  Repo exists, pulling latest..."
    cd "$HOME/Mini_Shark" && git fetch origin && git checkout integration && git pull origin integration
fi
cd "$HOME/Mini_Shark"
git checkout integration
echo -e "${GREEN}✓ Repository ready on integration branch${NC}"

# Step 3: Python virtual environment
echo -e "${YELLOW}[3/6] Creating Python virtual environment...${NC}"
cd "$HOME/Mini_Shark"
python3 -m venv .venv
source .venv/bin/activate
pip install -q -r requirements.txt
pip install -q scapy
echo -e "${GREEN}✓ Python environment ready${NC}"

# Step 4: Frontend dependencies
echo -e "${YELLOW}[4/6] Installing frontend dependencies...${NC}"
cd "$HOME/Mini_Shark/frontend"
npm install --silent
echo -e "${GREEN}✓ Frontend ready${NC}"

# Step 5: Capture permissions
echo -e "${YELLOW}[5/6] Setting packet capture permissions...${NC}"
PYTHON_PATH=$(which python3)
sudo setcap cap_net_raw,cap_net_admin=eip $PYTHON_PATH
echo -e "${GREEN}✓ Capture permissions set (no sudo needed)${NC}"

# Step 6: Firewall
echo -e "${YELLOW}[6/6] Opening firewall ports...${NC}"
sudo ufw allow 9000/tcp comment "MiniShark E3 telemetry" 2>/dev/null || true
sudo ufw allow 8001/tcp comment "MiniShark API" 2>/dev/null || true
sudo ufw allow 5173/tcp comment "MiniShark Dashboard" 2>/dev/null || true
echo -e "${GREEN}✓ Firewall configured${NC}"

# Instructions
echo ""
echo -e "${CYAN}=================================================="
echo "  VM1 Setup Complete!"
echo "=================================================="
echo ""
echo "  Network:"
echo "    VM1 (this machine) : 192.168.130.129"
echo "    VM2 (Probe 1)      : 192.168.130.128"
echo "    Windows Host       : 192.168.130.1"
echo ""
echo "  Now run these commands in SEPARATE terminals:"
echo ""
echo "  Terminal 1 — Start Central Server:"
echo "    cd ~/Mini_Shark"
echo "    source .venv/bin/activate"
echo "    python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 8001"
echo ""
echo "  Terminal 2 — Start Dashboard:"
echo "    cd ~/Mini_Shark/frontend"
echo "    VITE_API_HOST=http://192.168.130.129:8001 npm run dev -- --host 0.0.0.0"
echo ""
echo "  Terminal 3 — Start Probe 2 (this machine as server-side observer):"
echo "    cd ~/Mini_Shark"
echo "    source .venv/bin/activate"
echo "    python3 run_probe.py --probe-id 2 --server 127.0.0.1:9000"
echo ""
echo "  Browser (on Windows host):"
echo "    http://192.168.130.129:5173"
echo -e "${NC}"
