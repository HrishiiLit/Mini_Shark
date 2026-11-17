#!/usr/bin/env bash
# ==============================================================================
# Mini-Shark Laptop 4 (Server) — Stop All Server Services
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="${SCRIPT_DIR}/.server_pids"

CLR_RESET="\033[0m"
CLR_GREEN="\033[0;32m"
CLR_YELLOW="\033[1;33m"

echo -e "${CLR_YELLOW}[*] Stopping all Mini-Shark Server services...${CLR_RESET}"

# Stop by recorded PIDs
if [ -f "${PID_FILE}" ]; then
    while IFS= read -r pid; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null || true
            sleep 0.1
            kill -KILL "$pid" 2>/dev/null || true
        fi
    done < "${PID_FILE}"
    rm -f "${PID_FILE}"
fi

# Stop any dangling processes by pattern
pkill -f "uvicorn backend.main:app" 2>/dev/null || true
pkill -f "vite" 2>/dev/null || true
sudo pkill -f "run_probe.py.*--role server" 2>/dev/null || true

# Free ports if fuser is installed
if command -v fuser >/dev/null 2>&1; then
    sudo fuser -k 8001/tcp 2>/dev/null || true
    sudo fuser -k 9000/tcp 2>/dev/null || true
    sudo fuser -k 5173/tcp 2>/dev/null || true
fi

echo -e "${CLR_GREEN}[✓] All server processes and ports cleared.${CLR_RESET}"
