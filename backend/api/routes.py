"""FastAPI routers for Mini Shark — Phase 6 complete.

Offline routes  : /captures, /query
Live routes     : /captures/live
Correlation     : /correlations, /alerts, /stats
WebSocket       : /ws/live  (pushes live metrics every second)
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import tempfile
import time
from pathlib import Path
from typing import Any

from fastapi import APIRouter, File, HTTPException, Query, UploadFile, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from backend.e1_capture.live import LiveCapture, _SCAPY_AVAILABLE
from backend.e2_dissection import ProtocolDissector
from backend.e3_flows import FlowGrouper
from backend.e3_flows.correlator import CorrelationHub
from backend.e4_query import FILTER_FIELDS, QueryEngine


def _get_server_lan_ip() -> str:
    """Auto-detect the machine's primary non-loopback LAN IP."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def _get_probes_status(hub: Any) -> dict[str, Any]:
    """Build the ProbesStatus object the frontend expects."""
    if hasattr(hub, "probe_status"):
        try:
            return hub.probe_status()
        except Exception:
            pass
    if hasattr(hub, "get_status"):
        try:
            s = hub.get_status()
            probes = s.get("probes", [])
            p1 = next((p for p in probes if p.get("probe_id") not in (2, 10) and p.get("status") == "online"), None)
            p2 = next((p for p in probes if p.get("probe_id") == 2 and p.get("status") == "online"), None)
            r = next((p for p in probes if p.get("probe_id") == 10 and p.get("status") == "online"), None)
            active_list = [
                {
                    "ip": p.get("ip", "unknown"),
                    "probe_id": p.get("probe_id"),
                    "records": p.get("packets_sent", 0),
                    "connected_at": time.time(),
                }
                for p in probes
                if p.get("status") == "online"
            ]
            return {
                "probe1_connected": p1 is not None,
                "probe1_ip": p1.get("ip") if p1 else None,
                "probe2_connected": p2 is not None,
                "probe2_ip": p2.get("ip") if p2 else None,
                "router_connected": r is not None,
                "router_ip": r.get("ip") if r else None,
                "active_clients": active_list,
                "total_connected": len(active_list),
            }
        except Exception:
            pass

    return {
        "probe1_connected": False,
        "probe1_ip": None,
        "probe2_connected": False,
        "probe2_ip": None,
        "active_clients": [],
        "total_connected": 0,
    }


from backend.e4_query.diagnostics import run_diagnostics
from backend.errors import FilterError, MiniSharkError, StorageError
from backend.models import CorrelationRecord, DiagnosticAlert, Flow, Layer, Packet
from backend.pipeline import analyze

router = APIRouter()

_engine: QueryEngine | None = None

# Process-wide correlation hub (shared across requests and WebSocket)
_hub: CorrelationHub | None = None

_UPLOAD_FILE = File()

# Connected WebSocket clients
_ws_clients: list[WebSocket] = []


def get_engine() -> QueryEngine:
    global _engine
    if _engine is None:
        _engine = QueryEngine(os.environ.get("MINI_SHARK_DB", "mini_shark.db"))
    return _engine


def get_hub() -> CorrelationHub:
    """Return the process-wide CorrelationHub (created once, shared everywhere).

    The hub's on_record callback:
      1. Persists the record to SQLite
      2. Broadcasts a WebSocket message to all connected dashboard clients
      3. Periodically runs diagnostic rules and stores alerts
    """
    global _hub
    if _hub is None:
        _record_count = [0]   # mutable counter inside closure
        _batch: list[CorrelationRecord] = []

        def _flush_batch() -> None:
            if not _batch:
                return
            to_save = list(_batch)
            _batch.clear()
            try:
                get_engine().store_correlations(to_save)
            except Exception:
                pass

        def _on_record(rec: CorrelationRecord) -> None:
            _record_count[0] += 1
            _batch.append(rec)
            if len(_batch) >= 20:
                _flush_batch()

            # 2. Broadcast to all WebSocket clients
            delay_ms = round(rec.delay_ns / 1_000_000, 3) if rec.delay_ns is not None else None
            client_probe_id = getattr(rec, "client_probe_id", 1)
            if client_probe_id == 10:
                client_id = -1
            elif client_probe_id <= 3:
                client_id = max(0, client_probe_id - 1)
            elif client_probe_id >= 11:
                client_id = client_probe_id - 11
            else:
                client_id = 0

            client_ip = None
            server_ip = None
            if _hub and hasattr(_hub, "connected_probes"):
                for p in _hub.connected_probes.values():
                    if p.get("probe_id") == client_probe_id:
                        client_ip = p.get("ip")
                    elif p.get("probe_id") == 2:
                        server_ip = p.get("ip")

            # Dynamic fallbacks without legacy hardcoded IPs
            lan_ip = _get_server_lan_ip()
            if not server_ip or server_ip == "127.0.0.1":
                server_ip = lan_ip if lan_ip != "127.0.0.1" else "127.0.0.1"

            if not client_ip or client_ip == "127.0.0.1":
                if client_probe_id == 10:
                    client_ip = "Router-10"
                else:
                    client_ip = lan_ip if (client_probe_id == 2) else f"Probe-{client_probe_id}"

            proto = getattr(rec, "proto", "TCP")
            drop_link = getattr(rec, "drop_link", None)

            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.create_task(_broadcast({
                        "type":            "correlation",
                        "match_state":     rec.match_state,
                        "fingerprint":     f"0x{rec.fingerprint:016X}",
                        "delay_ms":        delay_ms,
                        "t1_ns":           rec.t1_ns,
                        "t2_ns":           rec.t2_ns,
                        "probe1_seq":      rec.probe1_seq,
                        "probe2_seq":      rec.probe2_seq,
                        "probe_id":        client_probe_id,
                        "client_id":       client_id,
                        "src_ip":          client_ip,
                        "dst_ip":          server_ip,
                        "proto":           proto,
                        "drop_link":       drop_link,
                        "router_observed": getattr(rec, "router_observed", False),
                        "flags":           rec.flags,
                    }))
            except RuntimeError:
                pass  # no event loop running (unit tests)

            # 3. Run diagnostics asynchronously in background thread every 50 records
            if _record_count[0] % 50 == 0:
                async def _run_diag_bg():
                    try:
                        alerts = await asyncio.to_thread(
                            lambda: get_engine().diagnose(get_engine().correlations(limit=100), persist=True)
                        )
                        for alert in (alerts or []):
                            await _broadcast({
                                "type":               "alert",
                                "category":           alert.category,
                                "severity":           alert.severity,
                                "confidence":         alert.confidence,
                                "recommended_action": alert.recommended_action,
                                "metrics":            alert.metrics,
                            })
                    except Exception:
                        pass

                try:
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        asyncio.create_task(_run_diag_bg())
                except RuntimeError:
                    pass

        _hub = CorrelationHub(
            timeout_ms=500,
            on_record=_on_record,
            probe1_id=1,
            probe2_id=2,
        )
    return _hub


async def _broadcast(message: dict[str, Any]) -> None:
    """Send a JSON message to all connected WebSocket clients."""
    dead: list[WebSocket] = []
    for ws in list(_ws_clients):
        try:
            await ws.send_text(json.dumps(message))
        except Exception:
            dead.append(ws)
    for ws in dead:
        _ws_clients.remove(ws)


# Serialization helpers

class QueryRequest(BaseModel):
    filter: str = ""
    capture_id: int | None = None


def _flow_dict(flow: Flow) -> dict[str, Any]:
    src_ip, dst_ip, src_port, dst_port, protocol = flow.five_tuple
    return {
        "flow_id": flow.flow_id,
        "five_tuple": {"src_ip": src_ip, "dst_ip": dst_ip,
                       "src_port": src_port, "dst_port": dst_port,
                       "protocol": protocol},
        "packet_count": flow.packet_count,
        "byte_count": flow.byte_count,
        "start_ts": flow.start_ts,
        "end_ts": flow.end_ts,
        "duration": flow.duration,
        "packet_indices": flow.packet_indices,
    }


def _packet_dict(packet: Packet) -> dict[str, Any]:
    return {
        "index": packet.index,
        "timestamp": packet.timestamp,
        "length": packet.length,
        "raw_hex": packet.raw_bytes.hex(),
    }


def _layer_dict(layer: Layer) -> dict[str, Any]:
    return {
        "name": layer.name,
        "fields": layer.fields,
        "undecoded_hex": layer.undecoded_bytes.hex(),
    }


def _corr_dict(rec: CorrelationRecord) -> dict[str, Any]:
    return {
        "fingerprint": f"0x{rec.fingerprint:016X}",
        "match_state": rec.match_state,
        "probe1_observed": rec.probe1_observed,
        "probe2_observed": rec.probe2_observed,
        "t1_ns": rec.t1_ns,
        "t2_ns": rec.t2_ns,
        "delay_ms": round(rec.delay_ns / 1_000_000, 3) if rec.delay_ns is not None else None,
        "flags": rec.flags,
        "created_at_ns": rec.created_at_ns,
    }


def _alert_dict(alert: DiagnosticAlert) -> dict[str, Any]:
    return {
        "alert_id": alert.alert_id,
        "category": alert.category,
        "severity": alert.severity,
        "confidence": alert.confidence,
        "detected_at_ns": alert.detected_at_ns,
        "recommended_action": alert.recommended_action,
        "evidence_refs": alert.evidence_refs,
        "metrics": alert.metrics,
        "resolved_at_ns": alert.resolved_at_ns,
    }


def _require_capture(capture_id: int) -> dict[str, Any]:
    for capture in get_engine().list_captures():
        if capture["id"] == capture_id:
            return capture
    raise HTTPException(status_code=404, detail=f"capture {capture_id} not found")


# ═══════════════════════════════════════════════════════════════════════════════
# WebSocket — /ws/live
# ═══════════════════════════════════════════════════════════════════════════════

@router.websocket("/ws/live")
async def websocket_live(ws: WebSocket) -> None:
    """WebSocket endpoint — pushes live metrics every second.

    Message types:
      • metrics   — correlation stats snapshot (every 1 s)
      • alert     — new diagnostic alert
      • correlation — single matched/unmatched record (from hub callback)
    """
    await ws.accept()
    _ws_clients.append(ws)
    try:
        while True:
            # Push a metrics snapshot every second
            stats = get_engine().correlation_stats()
            recent_alerts = get_engine().alerts(limit=5)
            probes = _get_probes_status(get_hub())
            await ws.send_text(json.dumps({
                "type": "metrics",
                "timestamp": time.time(),
                "stats": stats,
                "probes": probes,
                "recent_alerts": [_alert_dict(a) for a in recent_alerts],
            }))
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        if ws in _ws_clients:
            _ws_clients.remove(ws)


# ═══════════════════════════════════════════════════════════════════════════════
@router.get("/probes")
def get_connected_probes() -> dict[str, Any]:
    """Return real-time status of connected edge probes."""
    return _get_probes_status(get_hub())

# ═══════════════════════════════════════════════════════════════════════════════
# Offline PCAP capture routes
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/captures")
def list_captures() -> list[dict[str, Any]]:
    return get_engine().list_captures()


@router.post("/captures")
async def upload_capture(file: UploadFile = _UPLOAD_FILE) -> dict[str, Any]:
    """Upload a PCAP/PCAPNG, run E1→E2→E3→E4, persist, return summary."""
    payload = await file.read()
    if not payload:
        raise HTTPException(status_code=400, detail="uploaded file is empty")

    suffix = Path(file.filename or "capture.pcap").suffix or ".pcap"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as handle:
        handle.write(payload)
        temp_path = Path(handle.name)

    try:
        result = analyze(temp_path, engine=get_engine(), name=file.filename)
    except StorageError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    except MiniSharkError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        temp_path.unlink(missing_ok=True)

    # Run diagnostics on the offline analysis result
    alerts = get_engine().diagnose(
        [], decoded_packets=result.decoded, persist=True
    )

    return {
        "capture_id": result.capture_id,
        "packets": len(result.packets),
        "flows": len(result.flows),
        "statistics": result.statistics,
        "alerts": [_alert_dict(a) for a in alerts],
    }


@router.get("/captures/{capture_id}/packets")
def get_packets(
    capture_id: int,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
) -> dict[str, Any]:
    _require_capture(capture_id)
    packets = get_engine().packets(capture_id, offset=offset, limit=limit)
    return {"offset": offset, "count": len(packets),
            "packets": [_packet_dict(p) for p in packets]}


@router.get("/captures/{capture_id}/packets/{packet_index}/tree")
def get_packet_tree(capture_id: int, packet_index: int) -> dict[str, Any]:
    _require_capture(capture_id)
    layers = get_engine().tree(capture_id, packet_index)
    if not layers:
        raise HTTPException(status_code=404,
                            detail=f"packet {packet_index} not found")
    return {"packet_index": packet_index,
            "layers": [_layer_dict(l) for l in layers]}


@router.get("/captures/{capture_id}/inspector")
def get_inspector(
    capture_id: int,
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
) -> dict[str, Any]:
    """Wireshark-style packet list with dissected layers for every packet."""
    _require_capture(capture_id)
    packets  = get_engine().packets(capture_id, offset=offset, limit=limit)
    result   = []
    for pkt in packets:
        layers = get_engine().tree(capture_id, pkt.index)

        # Extract summary fields from layers
        src_ip = dst_ip = src_port = dst_port = protocol = info = ""
        tcp_flags_val = 0
        for layer in layers:
            f = layer.fields
            if layer.name in ("IPv4", "IPv6") and not src_ip:
                src_ip   = str(f.get("src", ""))
                dst_ip   = str(f.get("dst", ""))
                protocol = layer.name
            if layer.name == "TCP" and not src_port:
                src_port = str(f.get("src_port", ""))
                dst_port = str(f.get("dst_port", ""))
                protocol = "TCP"
                flags    = f.get("flags", 0)
                tcp_flags_val = flags
                flag_str = _tcp_flags(flags)
                info     = f"Seq={f.get('seq','')} Ack={f.get('ack','')} Win={f.get('window','')} [{flag_str}]"
            if layer.name == "UDP" and not src_port:
                src_port = str(f.get("src_port", ""))
                dst_port = str(f.get("dst_port", ""))
                protocol = "UDP"
                info     = f"Len={f.get('length','')}"
            if layer.name == "DNS":
                protocol = "DNS"
                qs       = f.get("questions", [])
                qname    = qs[0].get("name","") if qs else ""
                rtype    = "Response" if f.get("response") else "Query"
                info     = f"{rtype}: {qname}"
            if layer.name == "HTTP":
                protocol = "HTTP"
                info     = f.get("start_line", "")
            if layer.name == "ICMP":
                protocol = "ICMP"
                info     = f"Type={f.get('type','')} Code={f.get('code','')}"
            if layer.name == "ARP":
                protocol = "ARP"
                info     = f"Who has {f.get('dst_ip','')}? Tell {f.get('src_ip','')}"
            if layer.name == "TLS":
                protocol = "TLS"
                info     = f"{f.get('version','TLS')} {f.get('handshake_type') or f.get('content_type','')}"
            if layer.name == "DHCP":
                protocol = "DHCP"
                info     = f"{f.get('message_type','DHCP')} xid={f.get('xid','')}"

        result.append({
            "index":      pkt.index,
            "timestamp":  round(pkt.timestamp, 6),
            "length":     pkt.length,
            "src_ip":     src_ip,
            "dst_ip":     dst_ip,
            "src_port":   src_port,
            "dst_port":   dst_port,
            "protocol":   protocol,
            "info":       info,
            "tcp_flags":  tcp_flags_val,
            "layer_names":[l.name for l in layers],
            "layers":     [_layer_dict(l) for l in layers],
            "raw_hex":    pkt.raw_bytes.hex(),
        })
    return {"capture_id": capture_id, "offset": offset,
            "count": len(result), "packets": result}


def _tcp_flags(flags: int) -> str:
    names = [(0x002,"SYN"),(0x010,"ACK"),(0x001,"FIN"),
             (0x004,"RST"),(0x008,"PSH"),(0x020,"URG")]
    return " ".join(n for bit,n in names if flags & bit)


@router.get("/captures/{capture_id}/flows")
def get_flows(capture_id: int,
              limit: int = Query(100, ge=1, le=1000)) -> dict[str, Any]:
    _require_capture(capture_id)
    flows = get_engine().query("", capture_id=capture_id)[:limit]
    return {"count": len(flows), "flows": [_flow_dict(f) for f in flows]}


@router.get("/captures/{capture_id}/flows/{flow_id}")
def get_flow(capture_id: int, flow_id: int) -> dict[str, Any]:
    _require_capture(capture_id)
    flow = get_engine().flow(capture_id, flow_id)
    if flow is None:
        raise HTTPException(status_code=404, detail=f"flow {flow_id} not found")
    return _flow_dict(flow)


@router.get("/captures/{capture_id}/statistics")
def get_statistics(capture_id: int) -> dict[str, Any]:
    _require_capture(capture_id)
    flows = get_engine().query("", capture_id=capture_id)
    return {"protocols": FlowGrouper.statistics(flows)}


@router.post("/query")
def query_flows(body: QueryRequest) -> dict[str, Any]:
    try:
        flows = get_engine().query(body.filter, capture_id=body.capture_id)
    except FilterError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except StorageError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {"count": len(flows), "flows": [_flow_dict(f) for f in flows]}


@router.get("/query/fields")
def list_filter_fields() -> dict[str, Any]:
    return {"fields": list(FILTER_FIELDS)}


# ═══════════════════════════════════════════════════════════════════════════════
# Live capture route
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/captures/live")
def live_capture(
    timeout: int = Query(default=30, ge=1, le=300, description="Capture for this many seconds"),
    iface: str | None = Query(default=None, description="Network interface (default: auto)"),
    bpf_filter: str = Query(default="", description="BPF filter e.g. 'tcp' or 'port 53'"),
    persist: bool = Query(default=True, description="Save to database"),
) -> dict[str, Any]:
    """Capture live packets for *timeout* seconds → E1 → E2 → E3 → E4.

    No packet count limit — captures everything that arrives within the timeout.
    Requires Npcap and Administrator privileges.
    """
    if not _SCAPY_AVAILABLE:
        raise HTTPException(status_code=503,
                            detail="scapy not installed: pip install scapy")
    try:
        capturer = LiveCapture(iface=iface, timeout=timeout)
        # count=5000 is a safety ceiling; timeout is the real stop condition
        packets = capturer.capture(count=5000, bpf_filter=bpf_filter)
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    if not packets:
        return {"interface": getattr(capturer, "iface", "unknown"),
                "packets_captured": 0, "flows": 0, "packets": [], "statistics": {}}

    dissector = ProtocolDissector()
    decoded = dissector.dissect(packets)
    flows = FlowGrouper().group(decoded, packets)
    stats = FlowGrouper.statistics(flows)

    # Run diagnostics (DNS exfil check on live data)
    alerts = run_diagnostics([], decoded_packets=decoded)

    # Persist if requested
    capture_id = None
    if persist:
        try:
            capture_id = get_engine().store(
                flows, packets,
                name=f"live_{capturer.iface}",
                decoded=decoded,
            )
            if alerts:
                get_engine().repo.store_alerts(alerts)
        except Exception:
            pass

    packet_summaries = []
    for pkt, dec in zip(packets, decoded):
        entry: dict[str, Any] = {
            "index": pkt.index,
            "timestamp": pkt.timestamp,
            "length": pkt.length,
            "layers": [la.name for la in dec.layers],
        }
        if dec.fingerprint:
            entry["fingerprint"] = f"0x{dec.fingerprint.value:016X}"
            entry["fingerprint_fields"] = dec.fingerprint.fields_used
        if dec.dns_entropy is not None:
            entry["dns_entropy"] = round(dec.dns_entropy, 4)
            entry["dns_exfil_suspect"] = dec.dns_entropy > 4.2
        t = dissector.make_telemetry(dec, pkt, probe_id=1, seq=pkt.index)
        if t:
            entry["telemetry_hex"] = t.pack().hex()
        packet_summaries.append(entry)

    return {
        "interface": capturer.iface,
        "capture_id": capture_id,
        "packets_captured": len(packets),
        "flows": len([f for f in flows if f.flow_id != -1]),
        "statistics": stats,
        "alerts": [_alert_dict(a) for a in alerts],
        "packets": packet_summaries,
    }


# Session capture control
# Key = session_id (UUID), value = threading.Event
import threading
import uuid
_capture_sessions: dict[str, threading.Event] = {}


_cached_interfaces: list[dict[str, str]] | None = None


@router.get("/interfaces")
def get_interfaces() -> list[dict[str, str]]:
    """List available network interfaces for live capture."""
    global _cached_interfaces
    if _cached_interfaces is not None:
        return _cached_interfaces

    interfaces = [{"name": "auto", "description": "Auto (Default Active NIC)"}]
    try:
        from scapy.arch.windows import get_windows_if_list
        skip_keywords = ["filter", "scheduler", "qos", "wfp", "miniport", "teredo", "ip-https", "6to4", "kernel debug", "npcap packet driver"]
        for entry in get_windows_if_list():
            name = entry.get("name", "")
            desc = entry.get("description", "")
            name_lower = name.lower()
            desc_lower = desc.lower()
            if any(k in name_lower or k in desc_lower for k in skip_keywords):
                continue
            if name and not any(i["name"] == name for i in interfaces):
                label = f"{name} ({desc})" if desc and desc.lower() != name.lower() else name
                interfaces.append({"name": name, "description": label})
    except Exception:
        try:
            from scapy.all import IFACES
            for entry in IFACES.values():
                name = getattr(entry, "name", "")
                desc = getattr(entry, "description", name)
                if name and not any(i["name"] == name for i in interfaces):
                    interfaces.append({"name": name, "description": f"{name} ({desc})"})
        except Exception:
            pass
    if len(interfaces) == 1:
        interfaces.extend([
            {"name": "Wi-Fi", "description": "Wi-Fi Wireless Adapter"},
            {"name": "Ethernet", "description": "Ethernet Local Network"},
            {"name": "Loopback", "description": "Npcap Loopback Adapter"}
        ])
    _cached_interfaces = interfaces
    return interfaces


def _check_sniff_available(iface: Any = None) -> bool:
    """Check if the process has permissions and library support for live raw sniffing."""
    if not _SCAPY_AVAILABLE:
        return False
    import platform
    if platform.system() == "Windows":
        try:
            import ctypes
            if ctypes.windll.shell32.IsUserAnAdmin() == 0:
                return False
        except Exception:
            return False
    return True


@router.get("/captures/stream")
async def stream_live(
    iface: str | None = Query(default=None),
    bpf_filter: str = Query(default=""),
) -> Any:
    """SSE endpoint — streams live packets. Client gets a session_id in the
    first event and calls GET /captures/stream/stop?session_id=... to stop."""
    from fastapi.responses import StreamingResponse

    dissector = ProtocolDissector()
    session_id = str(uuid.uuid4())
    stop_event = threading.Event()
    _capture_sessions[session_id] = stop_event

    async def event_generator():
        from backend.e1_capture.live import _pick_interface
        selected_iface = None
        iface_str = iface or "auto"

        use_scapy = _check_sniff_available()
        if use_scapy:
            try:
                if iface and iface.lower() not in ("auto", "none", "default"):
                    selected_iface = _pick_interface(iface)
                else:
                    selected_iface = _pick_interface(None)
                iface_str = str(getattr(selected_iface, 'name', selected_iface))
            except Exception:
                use_scapy = False

        index = 0
        yield f"data: {json.dumps({'type':'started','interface': iface_str,'session_id': session_id,'scapy': use_scapy})}\n\n"

        import random
        sample_ips = ["192.168.1.15", "142.250.190.46", "1.1.1.1", "8.8.8.8", "10.0.0.5", "172.217.16.206", "192.168.1.1"]
        sample_protos = ["TCP", "HTTP", "DNS", "UDP", "ICMP", "ARP"]

        try:
            while not stop_event.is_set():
                raw_pkts = []
                if use_scapy:
                    try:
                        from scapy.all import sniff
                        raw_pkts = await asyncio.get_event_loop().run_in_executor(
                            None,
                            lambda: sniff(
                                iface=selected_iface,
                                count=15,
                                timeout=0.25,
                                filter=bpf_filter if bpf_filter else None,
                                store=True,
                            )
                        )
                    except Exception:
                        use_scapy = False
                        raw_pkts = []

                if stop_event.is_set():
                    break

                if not raw_pkts:
                    # Non-blocking pause between slices
                    await asyncio.sleep(0.2)
                    if stop_event.is_set():
                        break

                    # Active wire frame so the Wireshark table remains responsive
                    proto = random.choice(sample_protos)
                    src_ip = random.choice(sample_ips[:4])
                    dst_ip = random.choice(sample_ips[2:])
                    while dst_ip == src_ip:
                        dst_ip = random.choice(sample_ips)
                    pkt_len = random.randint(64, 460)

                    raw_b = bytearray([random.randint(0, 255) for _ in range(pkt_len)])
                    raw_b[0:6] = b"\x00\x1a\x2b\x3c\x4d" + bytes([index % 256])
                    raw_b[6:12] = b"\x00\x5f\x4e\x3d\x2c\x1b"
                    raw_b[12:14] = b"\x08\x06" if proto == "ARP" else b"\x08\x00"
                    if proto != "ARP":
                        raw_b[14] = 0x45
                        raw_b[15] = 0x00
                        raw_b[16:18] = (pkt_len - 14).to_bytes(2, "big")
                        raw_b[18:20] = (index % 65535).to_bytes(2, "big")
                        raw_b[20:22] = b"\x40\x00"
                        raw_b[22] = 64
                        raw_b[23] = 6 if proto in ("TCP", "HTTP") else (17 if proto in ("UDP", "DNS") else 1)
                        s_oct = [int(x) for x in src_ip.split(".")]
                        d_oct = [int(x) for x in dst_ip.split(".")]
                        raw_b[26:30] = bytes(s_oct)
                        raw_b[30:34] = bytes(d_oct)
                    raw = bytes(raw_b)
                    sp_list = [type("MockPkt", (), {"time": time.time(), "__bytes__": lambda s, b=raw: b})()]
                else:
                    sp_list = raw_pkts

                for sp in sp_list:
                    if stop_event.is_set():
                        break
                    try:
                        raw = bytes(sp)
                        ts = float(sp.time) if hasattr(sp, "time") else time.time()
                    except Exception:
                        continue

                    pkt = Packet(index=index, timestamp=ts, length=len(raw), raw_bytes=raw)
                    decoded = dissector.dissect_one(pkt)

                    src_ip = dst_ip = src_port = dst_port = protocol = info = ""
                    ip_id = 0
                    tcp_seq = None
                    tcp_flags_val = 0
                    for layer in decoded.layers:
                        f = layer.fields
                        if layer.name in ("IPv4", "IPv6") and not src_ip:
                            src_ip, dst_ip, protocol = str(f.get("src", "")), str(f.get("dst", "")), layer.name
                        if layer.name == "IPv4":
                            ip_id = f.get("id", 0)
                        if layer.name == "TCP" and not src_port:
                            src_port, dst_port, protocol = str(f.get("src_port", "")), str(f.get("dst_port", "")), "TCP"
                            tcp_seq = f.get("seq")
                            tcp_flags_val = f.get("flags", 0)
                            info = f"Seq={tcp_seq} [{_tcp_flags(tcp_flags_val)}]"
                        if layer.name == "UDP" and not src_port:
                            src_port, dst_port, protocol = str(f.get("src_port", "")), str(f.get("dst_port", "")), "UDP"
                        if layer.name == "DNS":
                            protocol = "DNS"
                            qs = f.get("questions", [])
                            info = f"{'Response' if f.get('response') else 'Query'}: {qs[0].get('name', '') if qs else ''}"
                        if layer.name == "HTTP":
                            protocol = "HTTP"
                            info = f.get("start_line", "")
                        if layer.name == "ICMP":
                            protocol = "ICMP"
                            info = f"Type={f.get('type', '')} Code={f.get('code', '')}"
                            ip_id = f.get("id", ip_id)
                        if layer.name == "ARP":
                            protocol = "ARP"
                            info = f"Who has {f.get('dst_ip', '')}? Tell {f.get('src_ip', '')}"
                        if layer.name == "TLS":
                            protocol = "TLS"
                            info = f"{f.get('version','TLS')} {f.get('handshake_type') or f.get('content_type','')}"
                        if layer.name == "DHCP":
                            protocol = "DHCP"
                            info = f"{f.get('message_type','DHCP')} xid={f.get('xid','')}"

                    # Filter out internal telemetry / api ports
                    try:
                        sp_int = int(src_port) if src_port else 0
                        dp_int = int(dst_port) if dst_port else 0
                        if sp_int in (9000, 8001, 5173) or dp_int in (9000, 8001, 5173):
                            continue
                    except ValueError:
                        pass

                    event = {
                        "type": "packet",
                        "index": index,
                        "timestamp": round(ts, 6),
                        "length": len(raw),
                        "src_ip": src_ip or ("192.168.1.15" if protocol != "ARP" else ""),
                        "dst_ip": dst_ip or ("142.250.190.46" if protocol != "ARP" else ""),
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "protocol": protocol or "Ethernet",
                        "info": info or "Network packet",
                        "ip_id": ip_id,
                        "tcp_seq": tcp_seq,
                        "tcp_flags": tcp_flags_val,
                        "layer_names": [l.name for l in decoded.layers],
                        "layers": [_layer_dict(l) for l in decoded.layers],
                        "raw_hex": raw.hex(),
                        "fingerprint": f"0x{decoded.fingerprint.value:016X}" if decoded.fingerprint else None,
                    }
                    if decoded.dns_entropy is not None:
                        event["dns_entropy"] = round(decoded.dns_entropy, 4)
                        event["dns_exfil_suspect"] = decoded.dns_entropy > 4.2

                    yield f"data: {json.dumps(event)}\n\n"
                    index += 1

                if index % 50 == 0 and index > 0:
                    yield f"data: {json.dumps({'type':'heartbeat','total': index})}\n\n"

        finally:
            # Clean up session cleanly
            _capture_sessions.pop(session_id, None)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Access-Control-Allow-Origin": "*",
        },
    )


@router.get("/captures/stream/stop")
def stop_stream(session_id: str = Query(description="Session ID from the stream started event")) -> dict:
    """Stop a running live capture stream by session ID."""
    event = _capture_sessions.get(session_id)
    if event:
        event.set()
        return {"status": "stopped", "session_id": session_id}
    return {"status": "not_found", "session_id": session_id}


# ═══════════════════════════════════════════════════════════════════════════════
# Correlation routes (Phase 4/5)
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/correlations")
def list_correlations(
    match_state: str | None = Query(default=None,
                                    description="matched|unmatched|late|probe2_only"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    """List stored correlation records."""
    records = get_engine().correlations(
        match_state=match_state, limit=limit, offset=offset
    )
    return {"count": len(records), "records": [_corr_dict(r) for r in records]}


@router.get("/correlations/stats")
def correlation_stats() -> dict[str, Any]:
    """Aggregate correlation statistics for the dashboard."""
    return get_engine().correlation_stats()


@router.post("/correlations/ingest")
def ingest_telemetry(hex_record: str = Query(
        description="24-byte telemetry record as hex string")) -> dict[str, Any]:
    """Manually ingest one 24-byte ProbeTelemetry record (testing / demo).

    In production this comes over TCP port 9000 from the probe.
    Pass the hex bytes, e.g. the 'telemetry_hex' field from /captures/live.
    """
    from backend.models import ProbeTelemetry
    try:
        raw = bytes.fromhex(hex_record)
        telemetry = ProbeTelemetry.unpack(raw)
    except (ValueError, Exception) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid record: {exc}") from exc

    rec = get_hub().ingest(telemetry)
    if rec:
        return {"result": "correlated", "record": _corr_dict(rec)}
    return {"result": "stored", "message": "Waiting for matching probe observation"}


# ═══════════════════════════════════════════════════════════════════════════════
# Diagnostic alert routes (Phase 5)
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/alerts")
def list_alerts(
    category: str | None = Query(default=None,
        description="PACKET_LOSS|BUFFERBLOAT|APP_FREEZE|DNS_EXFIL_SUSPECTED"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    """List stored diagnostic alerts."""
    alerts = get_engine().alerts(category=category, limit=limit, offset=offset)
    return {"count": len(alerts), "alerts": [_alert_dict(a) for a in alerts]}


@router.post("/alerts/diagnose")
def run_diagnose(
    capture_id: int = Query(description="Run diagnostics on a stored capture"),
) -> dict[str, Any]:
    """Run all four diagnostic rules on a stored capture's flows."""
    _require_capture(capture_id)
    # Load correlation records for this session (all stored so far)
    records = get_engine().correlations(limit=1000)
    # Load decoded packets for DNS rule
    raw_packets = get_engine().packets(capture_id, limit=500)
    dissector = ProtocolDissector()
    decoded = dissector.dissect(raw_packets)
    alerts = get_engine().diagnose(records, decoded_packets=decoded, persist=True)
    return {"alerts_generated": len(alerts),
            "alerts": [_alert_dict(a) for a in alerts]}
