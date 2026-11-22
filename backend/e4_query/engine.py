"""Traffic query and reporting engine (E4) — Phase 5 extended.

Combines :class:`~backend.e4_query.storage.CaptureStore` (persistence) with
:mod:`backend.e4_query.filters` (safe filter compilation) and the new
diagnostic rule engine behind the ``EngineE4`` contract.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from backend.interfaces import EngineE4
from backend.models import (
    CorrelationRecord,
    DecodedPacket,
    DiagnosticAlert,
    Flow,
    Layer,
    Packet,
)

from .diagnostics import run_diagnostics
from .filters import compile_filter
from .storage import CaptureStore


class QueryEngine(EngineE4):
    """Default E4 implementation backed by SQLite."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self._repo = CaptureStore(db_path)

    @property
    def repo(self) -> CaptureStore:
        return self._repo

    # Offline storage

    def store(
        self,
        flows: list[Flow],
        packets: list[Packet],
        *,
        name: str = "capture",
        file_hash: str | None = None,
        decoded: Sequence[DecodedPacket] | None = None,
    ) -> int:
        """Persist packets, layers and flows; returns the capture id."""
        return self._repo.persist(
            name=name,
            file_hash=file_hash,
            packets=packets,
            flows=flows,
            decoded=decoded,
        )

    def query(self, sql_like: str, capture_id: int | None = None) -> list[Flow]:
        """Return flows matching ``sql_like`` filter expression."""
        where, params = compile_filter(sql_like)
        return self._repo.fetch_flows(capture_id=capture_id, where=where, params=params)

    def list_captures(self) -> list[dict[str, Any]]:
        return self._repo.list_captures()

    def packets(self, capture_id: int, offset: int = 0, limit: int = 50) -> list[Packet]:
        return self._repo.fetch_packets(capture_id, offset=offset, limit=limit)

    def tree(self, capture_id: int, packet_index: int) -> list[Layer]:
        return self._repo.fetch_layers(capture_id, packet_index)

    def flow(self, capture_id: int, flow_id: int) -> Flow | None:
        return self._repo.fetch_flow(capture_id, flow_id)

    # Distributed correlation storage

    def store_correlation(self, record: CorrelationRecord) -> int:
        """Persist one CorrelationRecord; returns its DB row id."""
        return self._repo.store_correlation(record)

    def store_correlations(self, records: Sequence[CorrelationRecord]) -> None:
        """Bulk-persist correlation records."""
        self._repo.store_correlations(records)

    def store_alert(self, alert: DiagnosticAlert) -> int:
        """Persist one DiagnosticAlert; returns its DB row id."""
        return self._repo.store_alert(alert)

    def correlations(
        self,
        match_state: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[CorrelationRecord]:
        """Retrieve stored correlation records."""
        return self._repo.fetch_correlations(
            match_state=match_state, limit=limit, offset=offset
        )

    def alerts(
        self,
        category: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[DiagnosticAlert]:
        """Retrieve stored diagnostic alerts."""
        return self._repo.fetch_alerts(category=category, limit=limit, offset=offset)

    def correlation_stats(self) -> dict[str, Any]:
        """Aggregate stats for the live dashboard."""
        return self._repo.correlation_stats()

    def diagnose(
        self,
        records: Sequence[CorrelationRecord],
        decoded_packets: Sequence[DecodedPacket] | None = None,
        persist: bool = True,
    ) -> list[DiagnosticAlert]:
        """Run diagnostic rules and optionally persist the resulting alerts."""
        alerts = run_diagnostics(records, decoded_packets)
        if persist and alerts:
            self._repo.store_alerts(alerts)
        return alerts

    def close(self) -> None:
        self._repo.close()

