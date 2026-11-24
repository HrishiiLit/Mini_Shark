"""Mini-Shark — Universal One-Laptop Launcher.

Starts the central server (FastAPI REST + WebSocket on port 8001,
E3 TCP probe ingestion on port 9000), serves the clean Wireshark &
Observatory frontend, and optionally opens your browser.

Usage:
    python run_minishark.py
    python run_minishark.py --no-browser
    python run_minishark.py --port 8001 --probe
"""

import argparse
import os
import socket
import sys
import time
import webbrowser

# Add current workspace directory to sys.path and set CWD
_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
try:
    os.chdir(_ROOT)
except Exception:
    pass


def check_and_elevate():
    """On Windows, auto-elevate to Administrator mode for Npcap raw packet capture."""
    if sys.platform != "win32":
        return
    if "--no-elevate" in sys.argv:
        return
    import ctypes
    try:
        if ctypes.windll.shell32.IsUserAnAdmin() == 0:
            print("\n  [Notice] Mini-Shark requires Administrator privileges for Npcap raw packet capture.")
            print("  Requesting Windows Administrator elevation (UAC prompt)...")
            script_path = os.path.abspath(__file__)
            args_str = " ".join(f'"{arg}"' for arg in sys.argv[1:])
            ret = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, f'"{script_path}" {args_str}'.strip(), _ROOT, 1
            )
            if ret > 32:
                sys.exit(0)
    except Exception:
        pass


def _find_free_port(preferred: int, host: str = "0.0.0.0") -> int:
    """Find the preferred port, or the next available TCP port."""
    for port in range(preferred, preferred + 50):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((host, port))
                return port
            except OSError:
                continue
    return preferred


def main():
    check_and_elevate()

    parser = argparse.ArgumentParser(description="Mini-Shark Single-Laptop Launcher")
    parser.add_argument("--host", default="0.0.0.0", help="HTTP API host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8001, help="HTTP API port (default: 8001)")
    parser.add_argument("--e3-port", type=int, default=9000, help="E3 TCP ingestion port (default: 9000)")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically open web browser")
    args = parser.parse_args()

    # Determine free ports to avoid [Errno 10048] port conflicts
    http_port = _find_free_port(args.port, args.host)
    if http_port != args.port:
        print(f"  [Notice] Port {args.port} is in use (e.g. portproxy); auto-selected Port {http_port} for Web UI.")

    e3_port = _find_free_port(args.e3_port, args.host)
    if e3_port != args.e3_port:
        print(f"  [Notice] Port {args.e3_port} is in use; auto-selected Port {e3_port} for E3 Telemetry Hub.")

    os.environ["MINISHARK_TELEMETRY_HOST"] = args.host
    os.environ["MINISHARK_TELEMETRY_PORT"] = str(e3_port)

    # Check for Windows Administrator privileges
    if sys.platform == "win32":
        try:
            import ctypes
            if ctypes.windll.shell32.IsUserAnAdmin() == 0:
                print("\n  [WARNING] Mini-Shark is running WITHOUT Administrator privileges!")
                print("  Npcap requires Administrator rights to capture live wire packets.")
                print("  To capture real packets, please launch via 'run_as_admin.bat' or an elevated terminal.\n")
            else:
                print("  [Privileges] Running with Administrator rights (Npcap Real Wire Capture active).")
        except Exception:
            pass

    url = f"http://localhost:{http_port}/"

    print("=" * 65)
    print("  MINI-SHARK: Network Traffic Monitoring & Protocol Analysis")
    print("  Team 07 · KLE Technological University · CSE(AI)")
    print("=" * 65)
    print(f"  [Frontend & REST API]  : {url}")
    print(f"  [Interactive 3D View]  : {url}dashboard")
    print(f"  [Interactive API Docs] : {url}docs")
    print(f"  [E3 Telemetry Hub]     : {args.host}:{e3_port}")
    print("=" * 65)
    print("  Press Ctrl+C to stop the server cleanly.")
    print("=" * 65)

    if not args.no_browser:
        def _open():
            time.sleep(1.2)
            try:
                webbrowser.open(url)
            except Exception:
                pass
        import threading
        threading.Thread(target=_open, daemon=True).start()

    try:
        import uvicorn
        uvicorn.run("backend.main:app", host=args.host, port=http_port, reload=False, log_level="info")
    except KeyboardInterrupt:
        print("\n  [Mini-Shark] Server stopped cleanly.")


if __name__ == "__main__":
    main()
