#!/usr/bin/env bash
# ==============================================================================
# Mini-Shark Laptop 4 (Central Server Hub) — All-in-One Runner
#
# Launches:
#   1. Backend API (FastAPI) & E3 Telemetry Ingestion Hub (ports 8001 & 9000)
#   2. React Web Dashboard (port 5173)
#   3. Local Egress Probe 2 (connected to 127.0.0.1:9000)
#
# Everything is managed in one terminal. Pressing Ctrl+C gracefully terminates
# all child processes.
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

# Color codes
CLR_RESET="\033[0m"
CLR_BOLD="\033[1m"
CLR_GREEN="\033[0;32m"
CLR_BLUE="\033[0;34m"
CLR_CYAN="\033[0;36m"
CLR_YELLOW="\033[1;33m"
CLR_RED="\033[0;31m"
CLR_MAGENTA="\033[0;35m"

LOG_DIR="${SCRIPT_DIR}/logs"
PID_FILE="${SCRIPT_DIR}/.server_pids"
mkdir -p "${LOG_DIR}"

echo -e "${CLR_CYAN}${CLR_BOLD}"
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║             MINI-SHARK CENTRAL SERVER HUB (LAPTOP 4)                ║"
echo "║          Backend (:8001) + E3 Hub (:9000) + Web UI (:5173)           ║"
echo "║                     + Egress Probe 2                                 ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo -e "${CLR_RESET}"

# ------------------------------------------------------------------------------
# 1. Pre-flight Checks & Sudo Authentication
# ------------------------------------------------------------------------------
echo -e "${CLR_BOLD}[1/5] Checking environment & privileges...${CLR_RESET}"

# Detect LAN IP
PRIMARY_IFACE=$(ip route show default 2>/dev/null | awk '{print $5}' | head -n1)
if [ -n "${PRIMARY_IFACE}" ]; then
    SERVER_IP=$(ip -4 addr show dev "${PRIMARY_IFACE}" 2>/dev/null | awk '/inet / {print $2}' | cut -d/ -f1 | head -n1)
fi
if [ -z "${SERVER_IP}" ]; then
    SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
fi
if [ -z "${SERVER_IP}" ]; then
    SERVER_IP="127.0.0.1"
fi

echo -e "  • Primary Network Interface : ${CLR_YELLOW}${PRIMARY_IFACE:-auto}${CLR_RESET}"
echo -e "  • Server LAN IP Address     : ${CLR_GREEN}${CLR_BOLD}${SERVER_IP}${CLR_RESET}"
echo -e "    ${CLR_CYAN}➜ Tell teammates on Laptop 1, 2, and 3 to use this IP!${CLR_RESET}"

# Check for Python 3
if ! command -v python3 >/dev/null 2>&1; then
    echo -e "${CLR_RED}Error: python3 is not installed.${CLR_RESET}" >&2
    exit 1
fi

# Check for Node.js and npm
if ! command -v node >/dev/null 2>&1; then
    echo -e "${CLR_RED}Error: node is not installed. Run: sudo pacman -S --needed nodejs${CLR_RESET}" >&2
    exit 1
fi

if ! command -v npm >/dev/null 2>&1; then
    echo -e "${CLR_RED}Error: npm is not installed.${CLR_RESET}" >&2
    echo -e "${CLR_YELLOW}Fix on Arch / Omarchy Linux:  sudo pacman -S --needed npm${CLR_RESET}" >&2
    exit 1
fi

# Request sudo credentials upfront for Probe 2 (raw socket AF_PACKET)
SUDO_PREFIX=""
if [ "$EUID" -ne 0 ]; then
    echo -e "  • Requesting sudo privileges for Egress Probe 2..."
    sudo -v || {
        echo -e "${CLR_RED}Error: sudo access is required for raw socket packet capture.${CLR_RESET}" >&2
        exit 1
    }
    # Keep sudo credentials alive in background during session
    ( while true; do sudo -n true; sleep 50; kill -0 "$$" || exit; done ) 2>/dev/null &
    SUDO_KEEP_ALIVE_PID=$!
    SUDO_PREFIX="sudo"
fi

# ------------------------------------------------------------------------------
# 2. Kernel & Firewall Settings
# ------------------------------------------------------------------------------
echo -e "\n${CLR_BOLD}[2/5] Configuring kernel & firewall rules...${CLR_RESET}"

# Disable ICMP redirects (prevents client bypass in hairpin routing)
${SUDO_PREFIX} sysctl -w net.ipv4.conf.all.accept_redirects=0 >/dev/null 2>&1 || true
${SUDO_PREFIX} sysctl -w net.ipv4.conf.default.accept_redirects=0 >/dev/null 2>&1 || true
echo -e "  • ICMP redirects disabled: ${CLR_GREEN}OK${CLR_RESET}"

# Ensure firewall ports are open if ufw is active
if command -v ufw >/dev/null 2>&1; then
    if ${SUDO_PREFIX} ufw status 2>/dev/null | grep -q "Status: active"; then
        echo -e "  • UFW firewall active; ensuring ports 8001, 9000, 5173, 9500 are allowed..."
        ${SUDO_PREFIX} ufw allow 8001/tcp >/dev/null 2>&1 || true
        ${SUDO_PREFIX} ufw allow 9000/tcp >/dev/null 2>&1 || true
        ${SUDO_PREFIX} ufw allow 5173/tcp >/dev/null 2>&1 || true
        ${SUDO_PREFIX} ufw allow 9500/udp >/dev/null 2>&1 || true
        echo -e "  • Firewall rules configured: ${CLR_GREEN}OK${CLR_RESET}"
    fi
fi

# Optional Method A static return routing prompt
echo -ne "${CLR_YELLOW}  • Do you want to configure Method A return routes via Router now? [y/N]: ${CLR_RESET}"
read -r CONFIGURE_ROUTES
if [[ "${CONFIGURE_ROUTES}" =~ ^[Yy]$ ]]; then
    ${SUDO_PREFIX} "${SCRIPT_DIR}/scripts/setup_server_network.sh" add
fi

# ------------------------------------------------------------------------------
# 2b. Egress Probe 2 Configuration (Local vs Remote Client 2)
# ------------------------------------------------------------------------------
echo -e "\n${CLR_CYAN}[2b/5] Configuring Local Egress Probe 2...${CLR_RESET}"
RUN_LOCAL_PROBE="Y"
if [ "$1" = "--no-probe" ] || [ "$1" = "--hub-only" ]; then
    RUN_LOCAL_PROBE="N"
    echo -e "  • Egress Probe 2: ${CLR_YELLOW}Disabled via CLI flag${CLR_RESET}"
else
    echo -e "  • Egress Probe 2: ${CLR_GREEN}Enabled (Running Probe 2 on this Server Hub)${CLR_RESET}"
fi

# ------------------------------------------------------------------------------
# 3. Python Virtualenv & Frontend Dependencies
# ------------------------------------------------------------------------------
echo -e "\n${CLR_BOLD}[3/5] Verifying dependencies...${CLR_RESET}"

# Setup Python virtual environment
if [ ! -d ".venv" ]; then
    echo -e "  • Creating Python virtual environment in .venv..."
    python3 -m venv .venv
fi

# Activate venv
# shellcheck disable=SC1091
source ".venv/bin/activate"

# Check if backend packages are installed
if ! python3 -c "import fastapi, uvicorn, dpkt, sqlalchemy" >/dev/null 2>&1; then
    echo -e "  • Installing Python backend dependencies (requirements.txt)..."
    pip install -r requirements.txt
else
    echo -e "  • Python virtual environment & packages: ${CLR_GREEN}OK${CLR_RESET}"
fi

# Check frontend node_modules
if [ ! -d "frontend/node_modules" ]; then
    echo -e "  • Installing frontend npm packages (this only runs once)..."
    ( cd frontend && npm install )
else
    echo -e "  • Frontend dependencies: ${CLR_GREEN}OK${CLR_RESET}"
fi

# ------------------------------------------------------------------------------
# 4. Check for Port Conflicts
# ------------------------------------------------------------------------------
echo -e "\n${CLR_BOLD}[4/5] Checking port availability...${CLR_RESET}"

check_port() {
    local port="$1"
    local name="$2"
    if ss -tuln 2>/dev/null | grep -q ":${port} "; then
        echo -e "${CLR_YELLOW}Warning: Port ${port} (${name}) appears to already be in use!${CLR_RESET}"
        echo -e "         Run ./stop_server.sh or check with: ss -tulnp | grep :${port}"
    else
        echo -e "  • Port ${port} (${name}): ${CLR_GREEN}Available${CLR_RESET}"
    fi
}

check_port 8001 "FastAPI Backend"
check_port 9000 "E3 TCP Ingestion"
check_port 5173 "Vite React Dashboard"

# ------------------------------------------------------------------------------
# 5. Launch All Components
# ------------------------------------------------------------------------------
echo -e "\n${CLR_BOLD}[5/5] Launching all Server services...${CLR_RESET}"

BACKEND_LOG="${LOG_DIR}/backend.log"
FRONTEND_LOG="${LOG_DIR}/frontend.log"
PROBE_LOG="${LOG_DIR}/probe.log"

# Clear old logs
: > "${BACKEND_LOG}"
: > "${FRONTEND_LOG}"
: > "${PROBE_LOG}"

# Cleanup handler on exit or Ctrl+C
cleanup() {
    echo -e "\n${CLR_YELLOW}[*] Shutting down all Server processes...${CLR_RESET}"
    if [ -f "${PID_FILE}" ]; then
        while IFS= read -r pid; do
            if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
                kill -TERM "$pid" 2>/dev/null || true
            fi
        done < "${PID_FILE}"
        rm -f "${PID_FILE}"
    fi

    # Kill probe if running with sudo
    ${SUDO_PREFIX} pkill -f "run_probe.py.*--role server" 2>/dev/null || true

    if [ -n "${SUDO_KEEP_ALIVE_PID:-}" ]; then
        kill "${SUDO_KEEP_ALIVE_PID}" 2>/dev/null || true
    fi

    echo -e "${CLR_GREEN}[✓] All server processes stopped cleanly.${CLR_RESET}"
    exit 0
}

trap cleanup INT TERM EXIT

# --- Launch Component 1: FastAPI Backend & E3 Hub (:8001 & :9000) ---
python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 8001 > "${BACKEND_LOG}" 2>&1 &
BACKEND_PID=$!
echo "${BACKEND_PID}" > "${PID_FILE}"
echo -e "  [1] Backend & E3 Hub started   (PID: ${BACKEND_PID}) -> Logs: ${BACKEND_LOG}"

# Wait for backend to bind port 8001/9000
for _ in {1..30}; do
    if ss -tuln 2>/dev/null | grep -q ":8001 "; then
        break
    fi
    sleep 0.2
done

# --- Launch Component 2: Frontend Dashboard (:5173) ---
( cd frontend && npm run dev -- --host 0.0.0.0 > "${FRONTEND_LOG}" 2>&1 ) &
FRONTEND_PID=$!
echo "${FRONTEND_PID}" >> "${PID_FILE}"
echo -e "  [2] React UI Dashboard started (PID: ${FRONTEND_PID}) -> Logs: ${FRONTEND_LOG}"

# --- Launch Component 3: Egress Probe 2 (:9000) ---
if [ "${RUN_LOCAL_PROBE}" = "Y" ]; then
    ${SUDO_PREFIX} python3 "${SCRIPT_DIR}/run_probe.py" --server 127.0.0.1:9000 --role server > "${PROBE_LOG}" 2>&1 &
    PROBE_PID=$!
    echo "${PROBE_PID}" >> "${PID_FILE}"
    echo -e "  [3] Local Egress Probe 2 started (PID: ${PROBE_PID}) -> Logs: ${PROBE_LOG}"
else
    echo -e "  [3] Local Egress Probe 2: ${CLR_GREEN}Disabled (Running Remotely on Client 2)${CLR_RESET}"
fi

echo ""
echo -e "${CLR_GREEN}${CLR_BOLD}======================================================================${CLR_RESET}"
echo -e "${CLR_GREEN}${CLR_BOLD}   SERVER HUB IS FULLY OPERATIONAL AND READY FOR 4-LAPTOP RUN!        ${CLR_RESET}"
echo -e "${CLR_GREEN}${CLR_BOLD}======================================================================${CLR_RESET}"
echo -e "  • Dashboard (Local)   : ${CLR_BOLD}http://localhost:5173${CLR_RESET}"
echo -e "  • Dashboard (Network) : ${CLR_BOLD}${CLR_CYAN}http://${SERVER_IP}:5173${CLR_RESET}"
echo -e "  • Backend REST API    : ${CLR_BOLD}http://${SERVER_IP}:8001${CLR_RESET}"
echo -e "  • E3 Telemetry Hub    : ${CLR_BOLD}tcp://${SERVER_IP}:9000${CLR_RESET}"
if [ "${RUN_LOCAL_PROBE}" = "Y" ]; then
    echo -e "  • Egress Probe Mode   : ${CLR_BOLD}Local Probe 2 (Active)${CLR_RESET}"
else
    echo -e "  • Egress Probe Mode   : ${CLR_BOLD}Remote (Listening on :9000 for Client 2 Probe 2)${CLR_RESET}"
fi
echo ""
echo -e "${CLR_YELLOW}Press Ctrl+C at any time to cleanly stop all 3 services.${CLR_RESET}"
echo -e "----------------------------------------------------------------------"
echo -e "${CLR_MAGENTA}Unified Live Event Stream (Ctrl+C to quit):${CLR_RESET}\n"

# Stream unified log output with prefixes
# shellcheck disable=SC2024
tail -n 0 -f "${BACKEND_LOG}" 2>/dev/null | sed --unbuffered 's/^/\x1b[34m[Backend]\x1b[0m /' &
TAIL1_PID=$!
# shellcheck disable=SC2024
tail -n 0 -f "${FRONTEND_LOG}" 2>/dev/null | sed --unbuffered 's/^/\x1b[32m[ViteUI]\x1b[0m  /' &
TAIL2_PID=$!
# shellcheck disable=SC2024
tail -n 0 -f "${PROBE_LOG}" 2>/dev/null | sed --unbuffered 's/^/\x1b[33m[Probe2]\x1b[0m  /' &
TAIL3_PID=$!

# Wait indefinitely until interrupted
wait
