"""Traffic query and reporting engine (E4).

Combines :class:`~backend.e4_query.storage.CaptureStore` (persistence) with
:mod:`backend.e4_query.filters` (safe filter compilation) behind the
``EngineE4`` contract:

- ``store(flows, packets)``  - atomically persist an analysis result
- ``query(filter)``          - return the flows matching a filter expression
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from backend.interfaces import EngineE4
from backend.models import DecodedPacket, Flow, Layer, Packet

from .filters import compile_filter
from .storage import CaptureStore


class QueryEngine(EngineE4):
    """Default E4 implementation backed by SQLite."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self._repo = CaptureStore(db_path)

    @property
    def repo(self) -> CaptureStore:
        return self._repo

    def store(
        self,
        flows: list[Flow],
        packets: list[Packet],
        *,
        name: str = "capture",
        file_hash: str | None = None,
        decoded: Sequence[DecodedPacket] | None = None,
    ) -> int:
        """Persist packets, protocol layers and flows; returns the capture id."""
        return self._repo.persist(
            name=name,
            file_hash=file_hash,
            packets=packets,
            flows=flows,
            decoded=decoded,
        )

    def query(self, sql_like: str, capture_id: int | None = None) -> list[Flow]:
        """Return flows matching ``sql_like`` (a filter expression).

        Raises :class:`~backend.errors.FilterSyntaxError` on a malformed
        filter; an empty result is an empty list, never an error (UC-08).
        """
        where, params = compile_filter(sql_like)
        return self._repo.fetch_flows(capture_id=capture_id, where=where, params=params)

    def list_captures(self) -> list[dict[str, Any]]:
        return self._repo.list_captures()

    def packets(
        self, capture_id: int, offset: int = 0, limit: int = 50
    ) -> list[Packet]:
        return self._repo.fetch_packets(capture_id, offset=offset, limit=limit)

    def tree(self, capture_id: int, packet_index: int) -> list[Layer]:
        return self._repo.fetch_layers(capture_id, packet_index)

    def flow(self, capture_id: int, flow_id: int) -> Flow | None:
        return self._repo.fetch_flow(capture_id, flow_id)

    def close(self) -> None:
        self._repo.close()
