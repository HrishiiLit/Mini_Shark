#!/usr/bin/env bash
# ==============================================================================
# Mini-Shark Laptop 3 (Intermediate Router) — Linux All-in-One Automation Tool
#
# Configures a Linux laptop as an intermediate pure L3 router (Client -> Router -> Server),
# starts Transit Probe 10, and provides an interactive terminal control panel for live
# fault injection (Link 2 drops, Link 1 drops, delay, and status monitoring).
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
echo "║           MINI-SHARK INTERMEDIATE ROUTER HUB (LAPTOP 3)              ║"
echo "║        Pure L3 Forwarding (No NAT) + Transit Probe 10                ║"
echo "║                    + Live Fault Injection                            ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo -e "${CLR_RESET}"

# Sudo check
if [[ $EUID -ne 0 ]]; then
    echo -e "${CLR_YELLOW}[*] Requesting sudo privileges for router configuration & packet capture...${CLR_RESET}"
    exec sudo "$0" "$@"
fi

SERVER_IP="${1:-}"
if [ -z "${SERVER_IP}" ]; then
    echo -ne "${CLR_YELLOW}Enter Central Server Hub IP (Laptop 4) [e.g. 192.168.1.20]: ${CLR_RESET}"
    read -r SERVER_IP
fi

while [ -z "${SERVER_IP}" ]; do
    echo -ne "${CLR_RED}Server IP cannot be empty. Please enter Server IP: ${CLR_RESET}"
    read -r SERVER_IP
done

# Enable IP forwarding
echo -e "\n${CLR_CYAN}[1/2] Enabling IPv4 packet forwarding (No NAT)...${CLR_RESET}"
sysctl -w net.ipv4.ip_forward=1 >/dev/null
iptables -P FORWARD ACCEPT 2>/dev/null || true
echo -e "  • IPv4 Forwarding: ${CLR_GREEN}Enabled${CLR_RESET}"

# Launch Probe 10 in background
echo -e "\n${CLR_CYAN}[2/2] Launching Transit Probe 10 (Connecting to ${SERVER_IP}:9000)...${CLR_RESET}"
LOG_DIR="${SCRIPT_DIR}/logs"
mkdir -p "${LOG_DIR}"
ROUTER_PROBE_LOG="${LOG_DIR}/router_probe.log"
: > "${ROUTER_PROBE_LOG}"

python3 "${SCRIPT_DIR}/run_probe.py" --server "${SERVER_IP}:9000" --role router > "${ROUTER_PROBE_LOG}" 2>&1 &
PROBE_PID=$!
echo -e "  [✓] Probe 10 started (PID: ${PROBE_PID}) -> Logs: ${ROUTER_PROBE_LOG}"

cleanup() {
    echo -e "\n${CLR_YELLOW}[*] Stopping Probe 10 and clearing fault injections...${CLR_RESET}"
    kill "${PROBE_PID}" 2>/dev/null || true
    if [ -f "${SCRIPT_DIR}/scripts/setup_router.sh" ]; then
        "${SCRIPT_DIR}/scripts/setup_router.sh" clear-drops >/dev/null 2>&1 || true
    fi
    echo -e "${CLR_GREEN}[✓] Router clean. Exiting.${CLR_RESET}"
    exit 0
}

trap cleanup INT TERM EXIT

while true; do
    echo -e "\n${CLR_CYAN}======================================================================${CLR_RESET}"
    echo -e "${CLR_CYAN}${CLR_BOLD}             ROUTER FAULT INJECTION & CONTROL BENCH                   ${CLR_RESET}"
    echo -e "${CLR_CYAN}======================================================================${CLR_RESET}"
    echo -e "  Telemetry Hub IP: ${CLR_BOLD}${SERVER_IP}${CLR_RESET}"
    echo -e "  Probe 10 PID    : ${PROBE_PID}"
    echo -e "----------------------------------------------------------------------"
    echo -e "  ${CLR_YELLOW}[1] Inject Link 2 Drop (Router ──✖──> Destination / Client 2)${CLR_RESET}"
    echo -e "  ${CLR_YELLOW}[2] Inject Link 1 Drop (Client 1 ──✖──> Router)${CLR_RESET}"
    echo -e "  ${CLR_GREEN}[3] Clear All Drops    (Restore normal transmission)${CLR_RESET}"
    echo -e "  [4] Show Router & Link Status"
    echo -e "  [5] Tail Live Probe 10 Logs (Ctrl+C to return to menu)"
    echo -e "  ${CLR_RED}[6] Exit & Cleanup${CLR_RESET}"
    echo -e "----------------------------------------------------------------------"
    echo -ne "${CLR_CYAN}Select an option [1-6]: ${CLR_RESET}"
    read -r choice

    case "$choice" in
        1)
            echo -ne "${CLR_YELLOW}Enter drop percentage [default 20%]: ${CLR_RESET}"
            read -r pct
            pct="${pct:-20}"
            "${SCRIPT_DIR}/scripts/setup_router.sh" drop-link2 "$pct"
            ;;
        2)
            echo -ne "${CLR_YELLOW}Enter drop percentage [default 20%]: ${CLR_RESET}"
            read -r pct
            pct="${pct:-20}"
            "${SCRIPT_DIR}/scripts/setup_router.sh" drop-link1 "$pct"
            ;;
        3)
            "${SCRIPT_DIR}/scripts/setup_router.sh" clear-drops
            ;;
        4)
            "${SCRIPT_DIR}/scripts/setup_router.sh" status
            ;;
        5)
            echo -e "${CLR_MAGENTA}--- Streaming Probe 10 logs (Press Ctrl+C to return) ---${CLR_RESET}"
            trap 'echo ""' INT
            tail -n 30 -f "${ROUTER_PROBE_LOG}"
            trap cleanup INT TERM EXIT
            ;;
        6)
            cleanup
            ;;
        *)
            echo -e "${CLR_RED}Invalid option.${CLR_RESET}"
            ;;
    esac
done
