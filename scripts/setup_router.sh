#!/usr/bin/env bash
# ==============================================================================
# Mini-Shark Intermediate Router Configuration & Fault Injection Tool
#
# Configures a Linux laptop as an intermediate pure L3 router (Client -> Router -> Server)
# and provides controlled fault injection (Link 1 vs Link 2 packet drops and latency).
#
# Usage:
#   sudo ./scripts/setup_router.sh enable-routing
#   sudo ./scripts/setup_router.sh drop-link1 15       # Injects 15% drop on Link 1
#   sudo ./scripts/setup_router.sh drop-link2 20       # Injects 20% drop on Link 2
#   sudo ./scripts/setup_router.sh clear-drops         # Restores clean link
#   sudo ./scripts/setup_router.sh status              # Shows active routing & drops
# ==============================================================================

set -e

IFACE_LINK1="${IFACE_LINK1:-eth0}"      # Ingress interface from Client PCs
IFACE_LINK2="${IFACE_LINK2:-eth1}"      # Egress interface to Server PC

COLOR_GREEN="\033[0;32m"
COLOR_YELLOW="\033[1;33m"
COLOR_RED="\033[0;31m"
COLOR_RESET="\033[0m"

function check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${COLOR_RED}Error: This script must be run as root (sudo).${COLOR_RESET}"
        exit 1
    fi
}

function enable_routing() {
    check_root
    echo -e "${COLOR_GREEN}[*] Enabling IPv4 Packet Forwarding...${COLOR_RESET}"
    sysctl -w net.ipv4.ip_forward=1 >/dev/null

    echo -e "${COLOR_GREEN}[*] Disabling NAT/MASQUERADE to preserve BLAKE2b packet invariants...${COLOR_RESET}"
    iptables -P FORWARD ACCEPT 2>/dev/null || true

    echo -e "${COLOR_GREEN}[✓] Router ready for pure L3 forwarding across physical subnets.${COLOR_RESET}"
    echo -e "    Link 1 Interface (Clients): ${COLOR_YELLOW}${IFACE_LINK1}${COLOR_RESET}"
    echo -e "    Link 2 Interface (Server) : ${COLOR_YELLOW}${IFACE_LINK2}${COLOR_RESET}"
}

function drop_link1() {
    check_root
    local percent="${1:-15}"
    echo -e "${COLOR_YELLOW}[!] Injecting ${percent}% packet drop on Link 1 (${IFACE_LINK1} - Client -> Router)...${COLOR_RESET}"
    tc qdisc del dev "${IFACE_LINK1}" root 2>/dev/null || true
    tc qdisc add dev "${IFACE_LINK1}" root netem loss "${percent}%"
    echo -e "${COLOR_GREEN}[✓] Link 1 drop active. Packets dropped before reaching the router.${COLOR_RESET}"
    echo -e "    Mini-Shark will attribute these as: ${COLOR_YELLOW}Dropped on Link 1: Client ──✖──> Router${COLOR_RESET}"
}

function drop_link2() {
    check_root
    local percent="${1:-15}"
    echo -e "${COLOR_YELLOW}[!] Injecting ${percent}% packet drop on Link 2 (${IFACE_LINK2} - Router -> Server)...${COLOR_RESET}"
    tc qdisc del dev "${IFACE_LINK2}" root 2>/dev/null || true
    tc qdisc add dev "${IFACE_LINK2}" root netem loss "${percent}%"
    echo -e "${COLOR_GREEN}[✓] Link 2 drop active. Packets observed at router, but lost before server.${COLOR_RESET}"
    echo -e "    Mini-Shark will attribute these as: ${COLOR_YELLOW}Dropped on Link 2: Router ──✖──> Server Hub${COLOR_RESET}"
}

function clear_drops() {
    check_root
    echo -e "${COLOR_GREEN}[*] Clearing all artificial packet drops and latency rules...${COLOR_RESET}"
    tc qdisc del dev "${IFACE_LINK1}" root 2>/dev/null || true
    tc qdisc del dev "${IFACE_LINK2}" root 2>/dev/null || true
    echo -e "${COLOR_GREEN}[✓] Network links restored to 100% healthy transmission.${COLOR_RESET}"
}

function inject_delay() {
    check_root
    local iface="${1:-${IFACE_LINK2}}"
    local delay_ms="${2:-40}"
    echo -e "${COLOR_YELLOW}[!] Injecting ${delay_ms}ms bufferbloat latency on ${iface}...${COLOR_RESET}"
    tc qdisc del dev "${iface}" root 2>/dev/null || true
    tc qdisc add dev "${iface}" root netem delay "${delay_ms}ms"
    echo -e "${COLOR_GREEN}[✓] Latency active. Mini-Shark will report high-latency alert.${COLOR_RESET}"
}

function show_status() {
    echo -e "\n=== Router & Link Status ==="
    echo -e "IP Forwarding: $(sysctl -n net.ipv4.ip_forward)"
    echo -e "\n--- Link 1 (${IFACE_LINK1}) tc qdisc ---"
    tc qdisc show dev "${IFACE_LINK1}" 2>/dev/null || echo "No active queuing discipline"
    echo -e "\n--- Link 2 (${IFACE_LINK2}) tc qdisc ---"
    tc qdisc show dev "${IFACE_LINK2}" 2>/dev/null || echo "No active queuing discipline"
    echo -e "\n--- Active IPv4 Routes ---"
    ip -4 route show
    echo ""
}

case "$1" in
    enable-routing)
        enable_routing
        ;;
    drop-link1)
        drop_link1 "$2"
        ;;
    drop-link2)
        drop_link2 "$2"
        ;;
    clear-drops)
        clear_drops
        ;;
    delay)
        inject_delay "$2" "$3"
        ;;
    status)
        show_status
        ;;
    *)
        echo "Usage: sudo $0 {enable-routing|drop-link1 [pct]|drop-link2 [pct]|clear-drops|delay [iface] [ms]|status}"
        exit 1
        ;;
esac
