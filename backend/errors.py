"""Typed errors raised by the Mini Shark engines.

Every engine failure that a caller (API, tests, CLI) is expected to handle
derives from :class:`MiniSharkError`, so a single ``except`` can translate
engine problems into HTTP responses.
"""

from __future__ import annotations


class MiniSharkError(Exception):
    """Base class for all Mini Shark engine errors."""


class CaptureError(MiniSharkError):
    """Base class for E1 capture loading errors."""


class CorruptCaptureError(CaptureError):
    """Capture is truncated, malformed or otherwise unreadable."""


class UnsupportedFormatError(CaptureError):
    """File is not a PCAP/PCAPNG capture."""


class DissectionError(MiniSharkError):
    """E2 could not produce a protocol tree for a packet."""


class StorageError(MiniSharkError):
    """E4 persistence failure; never claim data was stored when raised."""


class FilterError(MiniSharkError):
    """Base class for E4 filter/query errors."""


class FilterSyntaxError(FilterError):
    """Filter expression is malformed or references an unknown field."""
