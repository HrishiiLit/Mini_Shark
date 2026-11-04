#!/bin/bash
# =============================================================
# Mini-Shark — VM2 (Probe 1) Setup Script
# IP: 192.168.130.128
# Runs: Probe 1 — captures traffic and sends to VM1
# =============================================================

set -e
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

echo -e "${CYAN}"
echo "=================================================="
echo "  Mini-Shark VM2 — Probe 1 Setup"
echo "  IP: 192.168.130.128"
echo "  Sends telemetry to VM1: 192.168.130.129:9000"
echo "=================================================="
echo -e "${NC}"

# ── Step 1: System packages ──────────────────────────────────
echo -e "${YELLOW}[1/4] Installing system packages...${NC}"
sudo apt update -qq
sudo apt install -y python3 python3-pip python3-venv git curl \
                    tcpdump nmap netcat-openbsd 2>&1 | tail -5
echo -e "${GREEN}✓ System packages ready${NC}"

# ── Step 2: Clone repo ───────────────────────────────────────
echo -e "${YELLOW}[2/4] Setting up Mini-Shark repository...${NC}"
if [ ! -d "$HOME/Mini_Shark" ]; then
    git clone https://github.com/HrishiiLit/Mini_Shark.git "$HOME/Mini_Shark"
else
    echo "  Repo exists, pulling latest..."
    cd "$HOME/Mini_Shark" && git fetch origin
fi
cd "$HOME/Mini_Shark"
git checkout integration
git pull origin integration
echo -e "${GREEN}✓ Repository ready on integration branch${NC}"

# ── Step 3: Python venv ──────────────────────────────────────
echo -e "${YELLOW}[3/4] Creating Python virtual environment...${NC}"
cd "$HOME/Mini_Shark"
python3 -m venv .venv
source .venv/bin/activate
pip install -q -r requirements.txt
pip install -q scapy
echo -e "${GREEN}✓ Python environment ready${NC}"

# ── Step 4: Capture permissions ──────────────────────────────
echo -e "${YELLOW}[4/4] Setting packet capture permissions...${NC}"
PYTHON_PATH=$(which python3)
sudo setcap cap_net_raw,cap_net_admin=eip $PYTHON_PATH
echo -e "${GREEN}✓ Capture permissions set${NC}"

# ── Verify connectivity to VM1 ────────────────────────────────
echo ""
echo -e "${YELLOW}Checking connectivity to VM1 (192.168.130.129)...${NC}"
if ping -c 3 192.168.130.129 &>/dev/null; then
    echo -e "${GREEN}✓ VM1 reachable${NC}"
else
    echo -e "${RED}✗ Cannot reach VM1 — check network settings${NC}"
fi

if nc -zv 192.168.130.129 9000 &>/dev/null 2>&1; then
    echo -e "${GREEN}✓ E3 port 9000 open on VM1${NC}"
else
    echo -e "${YELLOW}⚠ Port 9000 not yet open (start server on VM1 first)${NC}"
fi

# ── Print start instructions ─────────────────────────────────
echo ""
echo -e "${CYAN}=================================================="
echo "  VM2 Setup Complete!"
echo "=================================================="
echo ""
echo "  IMPORTANT: Start VM1 server FIRST, then run:"
echo ""
echo "  Terminal 1 — Start Probe 1:"
echo "    cd ~/Mini_Shark"
echo "    source .venv/bin/activate"
echo "    python3 run_probe.py --probe-id 1 --server 192.168.130.129:9000"
echo ""
echo "  Terminal 2 — Generate test traffic (TC-01):"
echo "    ping -c 20 192.168.130.129"
echo "    curl http://192.168.130.129:8001/health"
echo ""
echo "  Terminal 3 — Inject packet loss (TC-02):"
echo "    sudo tc qdisc add dev ens33 root netem loss 15%"
echo "    ping -c 30 192.168.130.129"
echo "    sudo tc qdisc del dev ens33 root"
echo ""
echo "  Terminal 4 — Inject delay/bufferbloat (TC-03):"
echo "    sudo tc qdisc add dev ens33 root netem delay 75ms 15ms"
echo "    curl http://192.168.130.129:8001/health"
echo "    sudo tc qdisc del dev ens33 root"
echo ""
echo "  Terminal 5 — DNS exfil test (TC-04):"
echo "    python3 test_anomalies.py"
echo -e "${NC}"
