#!/usr/bin/env bash
# ==============================================================================
# Mini-Shark Laptop 4 (Server) — Static Route Setup (Method A Hairpin Routing)
#
# When all 4 laptops share the same Wi-Fi or Hotspot, this script ensures
# traffic returning to clients is routed via the Windows Router (Laptop 3)
# instead of going directly across the Wi-Fi AP.
#
# Usage:
#   sudo ./scripts/setup_server_network.sh add
#   sudo ./scripts/setup_server_network.sh add <ROUTER_IP> <CLIENT1_IP> [CLIENT2_IP]
#   sudo ./scripts/setup_server_network.sh show
#   sudo ./scripts/setup_server_network.sh clear
# ==============================================================================

set -e

CLR_RESET="\033[0m"
CLR_GREEN="\033[0;32m"
CLR_YELLOW="\033[1;33m"
CLR_CYAN="\033[0;36m"
CLR_RED="\033[0;31m"

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${CLR_RED}Error: This script must be run as root (sudo).${CLR_RESET}" >&2
        exit 1
    fi
}

ACTION="${1:-show}"
shift || true

case "${ACTION}" in
    add)
        check_root
        ROUTER_IP="${1:-}"
        CLIENTS=("${@:2}")

        if [ -z "${ROUTER_IP}" ]; then
            echo -ne "${CLR_YELLOW}Enter Intermediate Router IP (Laptop 3) [e.g. 192.168.1.10]: ${CLR_RESET}"
            read -r ROUTER_IP
        fi
        while [ -z "${ROUTER_IP}" ]; do
            echo -ne "${CLR_RED}Router IP cannot be empty. Please enter Router IP: ${CLR_RESET}"
            read -r ROUTER_IP
        done

        if [ ${#CLIENTS[@]} -eq 0 ]; then
            echo -ne "${CLR_YELLOW}Enter Client 1 IP (Laptop 1) [e.g. 192.168.1.15]: ${CLR_RESET}"
            read -r c1
            if [ -n "$c1" ]; then CLIENTS+=("$c1"); fi

            echo -ne "${CLR_YELLOW}Enter Client 2 IP (Laptop 2) [e.g. 192.168.1.16, or Enter to skip]: ${CLR_RESET}"
            read -r c2
            if [ -n "$c2" ]; then CLIENTS+=("$c2"); fi
        fi

        if [ ${#CLIENTS[@]} -eq 0 ]; then
            echo -e "${CLR_RED}Error: At least one client IP must be specified.${CLR_RESET}"
            exit 1
        fi

        echo -e "\n${CLR_CYAN}[*] Disabling ICMP redirects...${CLR_RESET}"
        sysctl -w net.ipv4.conf.all.accept_redirects=0
        sysctl -w net.ipv4.conf.default.accept_redirects=0

        for client in "${CLIENTS[@]}"; do
            echo -e "${CLR_GREEN}[*] Adding route: ${client}/32 via router ${ROUTER_IP}...${CLR_RESET}"
            ip route replace "${client}/32" via "${ROUTER_IP}"
        done
        echo -e "${CLR_GREEN}[✓] Return routing configured successfully.${CLR_RESET}"
        ;;

    del|clear)
        check_root
        CLIENTS=("$@")
        if [ ${#CLIENTS[@]} -eq 0 ]; then
            # Auto-detect any /32 routes
            EXISTING=$(ip -4 route show | grep "/32" | awk '{print $1}')
            if [ -z "${EXISTING}" ]; then
                echo -e "${CLR_YELLOW}No active /32 host routes found.${CLR_RESET}"
                exit 0
            fi
            echo -e "${CLR_YELLOW}Removing active /32 host routes:${CLR_RESET}"
            for r in ${EXISTING}; do
                echo -e "  • Removing ${r}..."
                ip route del "${r}" 2>/dev/null || true
            done
        else
            for client in "${CLIENTS[@]}"; do
                echo -e "${CLR_YELLOW}[*] Removing route for ${client}/32...${CLR_RESET}"
                ip route del "${client}/32" 2>/dev/null || true
            done
        fi
        echo -e "${CLR_GREEN}[✓] Routes cleared.${CLR_RESET}"
        ;;

    show|status)
        echo -e "\n=== Current Server Host Routes ==="
        ip -4 route show | grep "/32" || echo "No custom /32 host routes currently configured."
        echo ""
        echo "ICMP Redirects Status:"
        echo "  net.ipv4.conf.all.accept_redirects = $(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null || echo 'unknown')"
        echo "  net.ipv4.conf.default.accept_redirects = $(sysctl -n net.ipv4.conf.default.accept_redirects 2>/dev/null || echo 'unknown')"
        echo ""
        ;;

    *)
        echo "Usage: sudo $0 {add|show|clear}"
        exit 1
        ;;
esac
