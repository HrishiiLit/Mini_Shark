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
from backend.e4_query.diagnostics import run_diagnostics
from backend.errors import FilterError, MiniSharkError, StorageError
from backend.models import CorrelationRecord, DiagnosticAlert, Flow, Layer, Packet
from backend.pipeline import analyze

router = APIRouter()

_engine: QueryEngine | None = None

# Process-wide correlation hub (shared across requests and WebSocket)
_hub: CorrelationHub | None = None

_UPLOAD_FILE = File()

# ── Connected WebSocket clients ──────────────────────────────────────────────
_ws_clients: list[WebSocket] = []


def get_engine() -> QueryEngine:
    global _engine
    if _engine is None:
        _engine = QueryEngine(os.environ.get("MINI_SHARK_DB", "mini_shark.db"))
    return _engine


def get_hub() -> CorrelationHub:
    global _hub
    if _hub is None:
        def _on_record(rec: CorrelationRecord) -> None:
            # persist + broadcast every correlation record
            try:
                get_engine().store_correlation(rec)
            except Exception:
                pass
            asyncio.create_task(_broadcast({
                "type": "correlation",
                "match_state": rec.match_state,
                "fingerprint": f"0x{rec.fingerprint:016X}",
                "delay_ms": round(rec.delay_ns / 1_000_000, 3) if rec.delay_ns is not None else None,
                "flags": rec.flags,
            }))

        _hub = CorrelationHub(timeout_ms=500, on_record=_on_record)
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


# ── Serialization helpers ────────────────────────────────────────────────────

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
            await ws.send_text(json.dumps({
                "type": "metrics",
                "timestamp": time.time(),
                "stats": stats,
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

@router.post("/captures/live")
def live_capture(
    count: int = Query(default=20, ge=1, le=500),
    iface: str | None = Query(default=None),
    bpf_filter: str = Query(default=""),
    timeout: int = Query(default=15, ge=1, le=60),
    persist: bool = Query(default=True, description="Save to database"),
) -> dict[str, Any]:
    """Capture live packets → E1 → E2 → E3 → E4 pipeline."""
    if not _SCAPY_AVAILABLE:
        raise HTTPException(status_code=503,
                            detail="scapy not installed: pip install scapy")
    try:
        capturer = LiveCapture(iface=iface, timeout=timeout)
        packets = capturer.capture(count=count, bpf_filter=bpf_filter)
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
