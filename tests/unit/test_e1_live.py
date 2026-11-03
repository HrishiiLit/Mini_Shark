"""Verify the Scapy adapter without needing a capture driver or privileges."""

from __future__ import annotations

import pytest
from helpers import tcp_frame

from backend.e1_capture import live


def test_live_adapter_preserves_bytes_timestamp_and_capture_options(monkeypatch):
    frame = tcp_frame()

    class Captured:
        time = 1_700_000_000.125

        def __bytes__(self):
            return frame

    options = {}

    def sniff(**kwargs):
        options.update(kwargs)
        return [Captured()]

    monkeypatch.setattr(live, "_SCAPY_AVAILABLE", True)
    monkeypatch.setattr(live, "_pick_interface", lambda iface: iface)
    monkeypatch.setattr(live, "sniff", sniff, raising=False)
    packets = live.LiveCapture(iface="test", timeout=2).capture(5, "tcp")
    assert options == {
        "iface": "test",
        "count": 5,
        "store": True,
        "timeout": 2,
        "filter": "tcp",
    }
    assert packets[0].raw_bytes == frame
    assert packets[0].timestamp == Captured.time
    assert packets[0].length == len(frame)


def test_live_adapter_contains_capture_errors(monkeypatch):
    def sniff(**_kwargs):
        raise OSError("interface lost")

    monkeypatch.setattr(live, "_SCAPY_AVAILABLE", True)
    monkeypatch.setattr(live, "_pick_interface", lambda iface: iface)
    monkeypatch.setattr(live, "sniff", sniff, raising=False)
    with pytest.raises(RuntimeError, match="interface lost"):
        live.LiveCapture(iface="test").capture()


def test_missing_scapy_has_actionable_error(monkeypatch):
    monkeypatch.setattr(live, "_SCAPY_AVAILABLE", False)
    with pytest.raises(RuntimeError, match="scapy is not installed"):
        live.LiveCapture()
