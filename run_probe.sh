#!/usr/bin/env bash
# ==============================================================================
# Mini-Shark Zero-Install Portable Probe Runner (Linux / macOS)
#
# Runs live packet capture and telemetry streaming directly using Python 3
# standard library without requiring pip install or virtual environments.
#
# Usage:
#   # Client laptop (auto-derives unique probe ID):
#   sudo ./run_probe.sh --server 192.168.1.5:9000
#
#   # Intermediate router laptop:
#   sudo ./run_probe.sh --server 192.168.1.5:9000 --role router
#
#   # Server machine:
#   sudo ./run_probe.sh --server 127.0.0.1:9000 --role server
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

# Check for Python 3
if command -v python3 >/dev/null 2>&1; then
    PY_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    PY_BIN="python"
else
    echo "Error: Python 3 was not found on this system. Please install Python 3."
    exit 1
fi

# Ensure running as root on Linux for AF_PACKET raw sockets
if [[ "$(uname)" == "Linux" ]] && [[ $EUID -ne 0 ]]; then
    echo "[!] Live packet capture requires raw socket privileges. Re-running with sudo..."
    exec sudo "${PY_BIN}" "${SCRIPT_DIR}/run_probe.py" "$@"
fi

exec "${PY_BIN}" "${SCRIPT_DIR}/run_probe.py" "$@"
