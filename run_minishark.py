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
import sys
import time
import webbrowser

# Add current workspace directory to sys.path
_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


def main():
    parser = argparse.ArgumentParser(description="Mini-Shark Single-Laptop Launcher")
    parser.add_argument("--host", default="0.0.0.0", help="HTTP API host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8001, help="HTTP API port (default: 8001)")
    parser.add_argument("--e3-port", type=int, default=9000, help="E3 TCP ingestion port (default: 9000)")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically open web browser")
    args = parser.parse_args()

    os.environ["MINISHARK_TELEMETRY_HOST"] = "0.0.0.0"
    os.environ["MINISHARK_TELEMETRY_PORT"] = str(args.e3_port)

    url = f"http://localhost:{args.port}/"

    print("=" * 65)
    print("  MINI-SHARK: Network Traffic Monitoring & Protocol Analysis")
    print("  Team 07 · KLE Technological University · CSE(AI)")
    print("=" * 65)
    print(f"  [Frontend & REST API]  : {url}")
    print(f"  [Interactive 3D View]  : {url}dashboard")
    print(f"  [Interactive API Docs] : {url}docs")
    print(f"  [E3 Telemetry Hub]     : 0.0.0.0:{args.e3_port}")
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
        uvicorn.run("backend.main:app", host=args.host, port=args.port, reload=False, log_level="info")
    except KeyboardInterrupt:
        print("\n  [Mini-Shark] Server stopped cleanly.")


if __name__ == "__main__":
    main()
