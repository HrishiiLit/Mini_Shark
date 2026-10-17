"""Engine E3 - Flow & Traffic Analysis.

Groups decoded packets into five-tuple flows and computes per-flow and
per-protocol statistics deterministically.
"""

from __future__ import annotations

from .engine import FlowGrouper

__all__ = ["FlowGrouper"]
