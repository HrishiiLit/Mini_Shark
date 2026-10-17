"""Thin FastAPI routers for Mini Shark.

Routes validate input, call one engine and serialise the answer - no engine
logic lives here (see ``docs/api_routes.md``).
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

from fastapi import APIRouter, File, HTTPException, Query, UploadFile
from pydantic import BaseModel

from backend.e3_flows import FlowGrouper
from backend.e4_query import FILTER_FIELDS, QueryEngine
from backend.errors import FilterError, MiniSharkError, StorageError
from backend.models import Flow, Layer, Packet
from backend.pipeline import analyze

router = APIRouter()

_engine: QueryEngine | None = None

_UPLOAD_FILE = File()


def get_engine() -> QueryEngine:
    """Process-wide E4 instance (SQLite path comes from the environment)."""
    global _engine
    if _engine is None:
        _engine = QueryEngine(os.environ.get("MINI_SHARK_DB", "mini_shark.db"))
    return _engine


class QueryRequest(BaseModel):
    filter: str = ""
    capture_id: int | None = None


def _flow_dict(flow: Flow) -> dict[str, Any]:
    src_ip, dst_ip, src_port, dst_port, protocol = flow.five_tuple
    return {
        "flow_id": flow.flow_id,
        "five_tuple": {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
        },
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


def _require_capture(capture_id: int) -> dict[str, Any]:
    for capture in get_engine().list_captures():
        if capture["id"] == capture_id:
            return capture
    raise HTTPException(status_code=404, detail=f"capture {capture_id} not found")


@router.get("/captures")
def list_captures() -> list[dict[str, Any]]:
    return get_engine().list_captures()


@router.post("/captures")
async def upload_capture(file: UploadFile = _UPLOAD_FILE) -> dict[str, Any]:
    """Upload a capture, run all four engines and store the result."""
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

    return {
        "capture_id": result.capture_id,
        "packets": len(result.packets),
        "flows": len(result.flows),
        "statistics": result.statistics,
    }


@router.get("/captures/{capture_id}/packets")
def get_packets(
    capture_id: int,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
) -> dict[str, Any]:
    _require_capture(capture_id)
    packets = get_engine().packets(capture_id, offset=offset, limit=limit)
    return {
        "offset": offset,
        "count": len(packets),
        "packets": [_packet_dict(packet) for packet in packets],
    }


@router.get("/captures/{capture_id}/packets/{packet_index}/tree")
def get_packet_tree(capture_id: int, packet_index: int) -> dict[str, Any]:
    _require_capture(capture_id)
    layers = get_engine().tree(capture_id, packet_index)
    if not layers:
        raise HTTPException(
            status_code=404, detail=f"packet {packet_index} not found or not decoded"
        )
    return {
        "packet_index": packet_index,
        "layers": [_layer_dict(layer) for layer in layers],
    }


@router.get("/captures/{capture_id}/flows")
def get_flows(
    capture_id: int, limit: int = Query(100, ge=1, le=1000)
) -> dict[str, Any]:
    _require_capture(capture_id)
    flows = get_engine().query("", capture_id=capture_id)[:limit]
    return {"count": len(flows), "flows": [_flow_dict(flow) for flow in flows]}


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
    return {"count": len(flows), "flows": [_flow_dict(flow) for flow in flows]}


@router.get("/query/fields")
def list_filter_fields() -> dict[str, Any]:
    return {"fields": list(FILTER_FIELDS)}
