"""Engine E3 - Flow & Traffic Analysis / Multi-Point Correlation Hub.

Contains:
  - FlowGrouper: offline five-tuple conversation grouping (Phase 1).
  - CorrelationEngine: O(1) hash table + min-heap deadline matching (Phase 4).
  - TelemetryServer: Asyncio TCP port 9000 telemetry ingestion (Phase 4).
  - TelemetryClient: Client streaming utility for probe telemetry (Phase 4).
"""

from __future__ import annotations

from .correlation import CorrelationEngine
from .engine import FlowGrouper
from .ingestion import ConnectedProbe, TelemetryClient, TelemetryServer

__all__ = [
    "ConnectedProbe",
    "CorrelationEngine",
    "FlowGrouper",
    "TelemetryClient",
    "TelemetryServer",
]
