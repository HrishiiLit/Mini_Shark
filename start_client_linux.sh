#!/usr/bin/env bash
# ==============================================================================
# Mini-Shark Laptop 1 (Client 1 — Arch Linux) — All-in-One Automation Tool
#
# Automatically:
#   1. Prompts for Server IP and Router IP in the terminal (if not passed as args)
#   2. Disables ICMP redirects to prevent hairpin bypass
#   3. Adds static route to Server via Router
#   4. Starts Client Probe (Probe 11) streaming telemetry to Server Hub
#   5. Provides interactive test bench for workloads & fault injection (Link 1 drop)
#   6. Cleans up routing, iptables, and processes on exit
#
# Usage:
#   ./start_client_linux.sh
#   ./start_client_linux.sh 192.168.1.20 192.168.1.10
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

CLR_RESET="\033[0m"
CLR_BOLD="\033[1m"
CLR_GREEN="\033[0;32m"
CLR_CYAN="\033[0;36m"
CLR_YELLOW="\033[1;33m"
CLR_RED="\033[0;31m"
CLR_MAGENTA="\033[0;35m"

echo -e "${CLR_CYAN}${CLR_BOLD}"
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║             MINI-SHARK CLIENT 1 (ARCH LINUX / LINUX)                 ║"
echo "║            Client Probe 11 + Traffic Generator & Tests               ║"
echo "║                   + Link 1 Drop Fault Injection                      ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo -e "${CLR_RESET}"

# Request sudo privileges upfront
if [[ $EUID -ne 0 ]]; then
    echo -e "${CLR_YELLOW}[*] Requesting sudo privileges for raw socket probe & routing...${CLR_RESET}"
    sudo -v || { echo -e "${CLR_RED}Error: sudo access is required.${CLR_RESET}"; exit 1; }
    ( while true; do sudo -n true; sleep 50; kill -0 "$$" || exit; done ) 2>/dev/null &
    SUDO_KEEP_ALIVE_PID=$!
fi

# ------------------------------------------------------------------------------
# 1. Interactive IP Configuration
# ------------------------------------------------------------------------------
HUB_IP="${1:-}"
ROUTER_IP="${2:-}"
DEST_IP="${3:-}"

if [ -z "${HUB_IP}" ]; then
    echo -ne "${CLR_YELLOW}Enter Central Telemetry Hub IP (Laptop 4) [e.g. 192.168.1.20]: ${CLR_RESET}"
    read -r HUB_IP
fi
while [ -z "${HUB_IP}" ]; do
    echo -ne "${CLR_RED}Hub IP cannot be empty. Please enter Hub IP: ${CLR_RESET}"
    read -r HUB_IP
done

if [ -z "${ROUTER_IP}" ]; then
    echo -ne "${CLR_YELLOW}Enter Intermediate Router IP (Laptop 3) [e.g. 192.168.1.10]: ${CLR_RESET}"
    read -r ROUTER_IP
fi
while [ -z "${ROUTER_IP}" ]; do
    echo -ne "${CLR_RED}Router IP cannot be empty. Please enter Router IP: ${CLR_RESET}"
    read -r ROUTER_IP
done

if [ -z "${DEST_IP}" ]; then
    echo -ne "${CLR_YELLOW}Enter Destination Target IP (Client 2) [Press Enter for Hub IP ${HUB_IP}]: ${CLR_RESET}"
    read -r DEST_IP
    DEST_IP="${DEST_IP:-${HUB_IP}}"
fi

echo -e "\n${CLR_CYAN}[1/3] Configuring Network & Hairpin Routing...${CLR_RESET}"
# Disable ICMP redirects
sudo sysctl -w net.ipv4.conf.all.accept_redirects=0 >/dev/null 2>&1 || true
sudo sysctl -w net.ipv4.conf.default.accept_redirects=0 >/dev/null 2>&1 || true
echo -e "  • ICMP redirects: ${CLR_GREEN}Disabled${CLR_RESET}"

# Configure host route to Destination via Router
sudo ip route replace "${DEST_IP}/32" via "${ROUTER_IP}"
echo -e "  • Route to Target ${DEST_IP}/32 via Router ${ROUTER_IP}: ${CLR_GREEN}Configured${CLR_RESET}"

# ------------------------------------------------------------------------------
# 2. Launch Client Probe 11
# ------------------------------------------------------------------------------
echo -e "\n${CLR_CYAN}[2/3] Launching Client Probe 11...${CLR_RESET}"
LOG_DIR="${SCRIPT_DIR}/logs"
mkdir -p "${LOG_DIR}"
PROBE_LOG="${LOG_DIR}/client1_probe.log"
WORKLOAD_LOG="${LOG_DIR}/client1_workload.log"
: > "${PROBE_LOG}"
: > "${WORKLOAD_LOG}"

# Auto probe ID or pass --probe-id 11 streaming to Hub
sudo python3 "${SCRIPT_DIR}/run_probe.py" --server "${HUB_IP}:9000" --probe-id 11 > "${PROBE_LOG}" 2>&1 &
PROBE_PID=$!
echo -e "  [✓] Client Probe 11 started (PID: ${PROBE_PID}) -> Logs: ${PROBE_LOG}"

# ------------------------------------------------------------------------------
# 3. Cleanup Handler
# ------------------------------------------------------------------------------
WORKLOAD_PID=""
LINK1_DROP_ACTIVE=0

cleanup() {
    echo -e "\n${CLR_YELLOW}[*] Shutting down Client 1 processes & restoring network...${CLR_RESET}"

    if [ -n "${WORKLOAD_PID}" ] && kill -0 "${WORKLOAD_PID}" 2>/dev/null; then
        kill "${WORKLOAD_PID}" 2>/dev/null || true
    fi

    if [ -n "${PROBE_PID}" ]; then
        sudo kill "${PROBE_PID}" 2>/dev/null || true
        sudo pkill -f "run_probe.py.*--probe-id 11" 2>/dev/null || true
    fi

    # Clear iptables drop rule if set
    if [ "${LINK1_DROP_ACTIVE}" -eq 1 ]; then
        sudo iptables -D OUTPUT -d "${DEST_IP}" -m statistic --mode random --probability 0.3 -j DROP 2>/dev/null || true
    fi

    # Remove static route
    sudo ip route del "${DEST_IP}/32" 2>/dev/null || true

    if [ -n "${SUDO_KEEP_ALIVE_PID:-}" ]; then
        kill "${SUDO_KEEP_ALIVE_PID}" 2>/dev/null || true
    fi

    echo -e "${CLR_GREEN}[✓] Host routes and processes cleared. Exiting.${CLR_RESET}"
    exit 0
}

trap cleanup INT TERM EXIT

stop_active_workload() {
    if [ -n "${WORKLOAD_PID}" ] && kill -0 "${WORKLOAD_PID}" 2>/dev/null; then
        kill "${WORKLOAD_PID}" 2>/dev/null || true
        echo -e "${CLR_GREEN}[✓] Stopped active workload generator (PID: ${WORKLOAD_PID})${CLR_RESET}"
        WORKLOAD_PID=""
    fi
}

# ------------------------------------------------------------------------------
# 4. Interactive Test Bench Menu
# ------------------------------------------------------------------------------
while true; do
    echo -e "\n${CLR_CYAN}======================================================================${CLR_RESET}"
    echo -e "${CLR_CYAN}${CLR_BOLD}         CLIENT 1 TEST BENCH & WORKLOAD GENERATOR (ARCH LINUX)        ${CLR_RESET}"
    echo -e "${CLR_CYAN}======================================================================${CLR_RESET}"
    echo -e "  Telemetry Hub IP: ${CLR_BOLD}${HUB_IP}${CLR_RESET}"
    echo -e "  Router IP       : ${CLR_BOLD}${ROUTER_IP}${CLR_RESET}"
    echo -e "  Destination IP  : ${CLR_BOLD}${DEST_IP}${CLR_RESET}"
    echo -e "  Probe 11 PID    : ${PROBE_PID}"
    echo -e "  Active Workload : $([ -n "${WORKLOAD_PID}" ] && kill -0 "${WORKLOAD_PID}" 2>/dev/null && echo -e "${CLR_GREEN}RUNNING (PID: ${WORKLOAD_PID})${CLR_RESET}" || echo -e "Idle")"
    echo -e "  Link 1 Drop     : $([ "${LINK1_DROP_ACTIVE}" -eq 1 ] && echo -e "${CLR_RED}ACTIVE (30% DROP towards ${DEST_IP})${CLR_RESET}" || echo -e "${CLR_GREEN}CLEAN (0% DROP)${CLR_RESET}")"
    echo -e "----------------------------------------------------------------------"
    echo -e "  ${CLR_YELLOW}[1] Start Mixed Workload (HTTP + UDP stream @ 10 pkts/s)${CLR_RESET}"
    echo -e "  ${CLR_YELLOW}[2] Start HTTP Queries Workload (5 req/s)${CLR_RESET}"
    echo -e "  ${CLR_YELLOW}[3] Start UDP Audio/Media Stream (25 pkts/s)${CLR_RESET}"
    echo -e "  ${CLR_MAGENTA}[4] Run Live DNS Exfiltration Test (Triggers H > 4.2 bits alert)${CLR_RESET}"
    echo -e "  ${CLR_RED}[5] Inject Link 1 Drop (Sender 30% drop via iptables)${CLR_RESET}"
    echo -e "  ${CLR_GREEN}[6] Clear Link 1 Drop (Restore 100% clean transmission)${CLR_RESET}"
    echo -e "  [7] Tail Live Probe 11 Logs (Press Ctrl+C to return to menu)"
    echo -e "  [8] Stop Running Workload"
    echo -e "  ${CLR_RED}[9] Exit & Cleanup${CLR_RESET}"
    echo -e "----------------------------------------------------------------------"
    echo -ne "${CLR_CYAN}Select an option [1-9]: ${CLR_RESET}"
    read -r choice

    case "$choice" in
        1)
            stop_active_workload
            echo -e "${CLR_YELLOW}[*] Starting mixed background workload to ${DEST_IP}...${CLR_RESET}"
            python3 "${SCRIPT_DIR}/scripts/traffic_generator.py" --target "${DEST_IP}" --mode mixed --rate 10 > "${WORKLOAD_LOG}" 2>&1 &
            WORKLOAD_PID=$!
            echo -e "${CLR_GREEN}[✓] Mixed workload running in background (PID: ${WORKLOAD_PID})${CLR_RESET}"
            ;;
        2)
            stop_active_workload
            echo -e "${CLR_YELLOW}[*] Starting continuous HTTP workload to ${DEST_IP}...${CLR_RESET}"
            python3 "${SCRIPT_DIR}/scripts/traffic_generator.py" --target "${DEST_IP}" --mode http --rate 5 > "${WORKLOAD_LOG}" 2>&1 &
            WORKLOAD_PID=$!
            echo -e "${CLR_GREEN}[✓] HTTP workload running in background (PID: ${WORKLOAD_PID})${CLR_RESET}"
            ;;
        3)
            stop_active_workload
            echo -e "${CLR_YELLOW}[*] Starting high-speed UDP media stream to ${DEST_IP}:9500...${CLR_RESET}"
            python3 "${SCRIPT_DIR}/scripts/traffic_generator.py" --target "${DEST_IP}" --mode udp-stream --rate 25 > "${WORKLOAD_LOG}" 2>&1 &
            WORKLOAD_PID=$!
            echo -e "${CLR_GREEN}[✓] UDP stream running in background (PID: ${WORKLOAD_PID})${CLR_RESET}"
            ;;
        4)
            echo -e "${CLR_MAGENTA}[*] Injecting high-entropy DNS exfiltration queries to ${DEST_IP}:53...${CLR_RESET}"
            python3 "${SCRIPT_DIR}/test_anomalies.py" --dns --target "${DEST_IP}" || true
            echo -e "${CLR_GREEN}[✓] Check Dashboard at http://${HUB_IP}:5173 for DNS_EXFIL_SUSPECTED alert!${CLR_RESET}"
            ;;
        5)
            echo -e "${CLR_RED}[!] Injecting Link 1 drop (30% random packet drop on Client towards ${DEST_IP})...${CLR_RESET}"
            sudo iptables -A OUTPUT -d "${DEST_IP}" -m statistic --mode random --probability 0.3 -j DROP
            LINK1_DROP_ACTIVE=1
            echo -e "${CLR_GREEN}[✓] Drop active. Dashboard will show: 'Dropped on Link 1: Client ──✖──> Router'${CLR_RESET}"
            ;;
        6)
            echo -e "${CLR_GREEN}[*] Removing Link 1 drop rule...${CLR_RESET}"
            sudo iptables -D OUTPUT -d "${DEST_IP}" -m statistic --mode random --probability 0.3 -j DROP 2>/dev/null || true
            LINK1_DROP_ACTIVE=0
            echo -e "${CLR_GREEN}[✓] Link 1 restored to 100% normal transmission.${CLR_RESET}"
            ;;
        7)
            echo -e "${CLR_MAGENTA}--- Streaming Probe 11 logs (Press Ctrl+C to return) ---${CLR_RESET}"
            trap 'echo ""' INT
            tail -n 25 -f "${PROBE_LOG}"
            trap cleanup INT TERM EXIT
            ;;
        8)
            stop_active_workload
            ;;
        9)
            cleanup
            ;;
        *)
            echo -e "${CLR_RED}Invalid option.${CLR_RESET}"
            ;;
    esac
done
