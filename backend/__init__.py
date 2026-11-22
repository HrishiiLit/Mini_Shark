"""Mini Shark backend package.

Layout (see ``docs/implementation.md``):

- ``e1_capture``    Engine E1 - Packet & Frame Processing
- ``e2_dissection`` Engine E2 - Protocol Dissection
- ``e3_flows``      Engine E3 - Flow & Traffic Analysis
- ``e4_query``      Engine E4 - Traffic Query & Reporting
- ``api``           Thin FastAPI routers that only call the engines
"""

from __future__ import annotations

__all__ = ["e1_capture", "e2_dissection", "e3_flows", "e4_query"]
