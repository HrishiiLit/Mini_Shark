"""End-to-end analysis pipeline: E1 -> E2 -> E3 -> (optionally) E4.

The API and the integration tests both drive the engines through this module,
so engine wiring lives in exactly one place.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from .e1_capture import CaptureLoader
from .e2_dissection import ProtocolDissector
from .e3_flows import FlowGrouper
from .e4_query import QueryEngine
from .models import DecodedPacket, Flow, Packet

_CHUNK = 1 << 20


@dataclass(frozen=True)
class AnalysisResult:
    """Everything one capture produced, ready to serialise or assert on."""

    packets: list[Packet]
    decoded: list[DecodedPacket]
    flows: list[Flow]
    capture_id: int | None = None

    @property
    def statistics(self) -> dict[str, dict[str, float]]:
        return FlowGrouper.statistics(self.flows)


def analyze(
    path: str | Path,
    *,
    engine: QueryEngine | None = None,
    name: str | None = None,
) -> AnalysisResult:
    """Run the four engines over a capture file.

    ``engine`` is optional: without it the result is computed in memory and
    nothing is persisted.
    """
    file_path = Path(path)
    packets = CaptureLoader().load_capture(str(file_path))
    decoded = ProtocolDissector().dissect(packets)
    flows = FlowGrouper().group(decoded, packets)

    capture_id = None
    if engine is not None:
        capture_id = engine.store(
            flows,
            packets,
            name=name or file_path.name,
            file_hash=sha256_file(file_path),
            decoded=decoded,
        )
    return AnalysisResult(
        packets=packets, decoded=decoded, flows=flows, capture_id=capture_id
    )


def sha256_file(path: str | Path) -> str:
    """Content hash so the same capture is not stored twice by accident."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while chunk := handle.read(_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()
