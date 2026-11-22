"""Unit tests for Engine E3 — Correlation Hub (correlation.py).

Tests:
  - O(1) matching of Probe 1 and Probe 2 telemetry
  - Accurate transit delay calculation (ΔT = T2 - T1)
  - Timeout expiry producing 'unmatched' records
  - Late arrival after expiry producing 'late' records
  - Duplicate Probe 2 detection and suppression
  - Clock skew detection (negative delay and implausible delay)
  - Out-of-order arrival (Probe 2 before Probe 1)
  - Bounded memory / heap capacity eviction
  - Subscriber callbacks and event stream
  - Introspection metrics and statistics
"""

from __future__ import annotations

import pytest

from backend.e3_flows.correlation import CorrelationEngine
from backend.models import (
    CorrelationFlags,
    CorrelationRecord,
    MatchState,
    ProbeTelemetry,
)


@pytest.fixture(autouse=True)
def replay_clock(monkeypatch):
    # Existing fixtures use historical capture timestamps. Replay explicitly
    # controls server time rather than relying on the host's real wall clock.
    original = CorrelationEngine.__init__

    def initialize(self, *args, **kwargs):
        kwargs.setdefault("clock_ns", lambda: 0)
        original(self, *args, **kwargs)

    monkeypatch.setattr(CorrelationEngine, "__init__", initialize)


def _make_telemetry(
    fingerprint: int = 0x8F3A2B194E5C0D1A,
    timestamp_ns: int = 1_700_000_000_000_000_000,
    seq: int = 1,
    probe_id: int = 1,
    type_flags: int = 0x11,  # format version 1, record type 1
    captured_len: int = 64,
) -> ProbeTelemetry:
    return ProbeTelemetry(
        fingerprint=fingerprint,
        timestamp_ns=timestamp_ns,
        seq=seq,
        probe_id=probe_id,
        type_flags=type_flags,
        captured_len=captured_len,
    )


class TestCorrelationEngineMatching:
    def test_in_order_match_computes_exact_delay(self):
        engine = CorrelationEngine(timeout_ms=500)
        fp = 0x123456789ABCDEF0
        t1 = 1_000_000_000_000
        t2 = 1_000_005_000_000  # +5 ms (5,000,000 ns)

        # Probe 1 sends record
        res1 = engine.process_telemetry(_make_telemetry(fp, t1, seq=10, probe_id=1))
        assert res1 is None  # Waiting for Probe 2
        assert engine.get_stats()["correlation"]["in_flight"] == 1

        # Probe 2 sends matching record
        res2 = engine.process_telemetry(_make_telemetry(fp, t2, seq=20, probe_id=2))
        assert res2 is not None
        assert res2.match_state == MatchState.MATCHED.value
        assert res2.delay_ns == 5_000_000
        assert res2.delay_ms == pytest.approx(5.0)
        assert res2.flags == 0
        assert res2.probe1_seq == 10
        assert res2.probe2_seq == 20
        assert res2.probe1_observed is True
        assert res2.probe2_observed is True

        # In-flight count decremented
        assert engine.get_stats()["correlation"]["in_flight"] == 0
        assert engine.matched_total == 1

    def test_negative_delay_flags_clock_skew(self):
        engine = CorrelationEngine(timeout_ms=500)
        fp = 0xCAFEBABE00000001
        t1 = 1_000_005_000_000
        t2 = 1_000_000_000_000  # T2 is before T1 (-5 ms)

        engine.process_telemetry(_make_telemetry(fp, t1, probe_id=1))
        res = engine.process_telemetry(_make_telemetry(fp, t2, probe_id=2))

        assert res is not None
        assert res.match_state == MatchState.MATCHED.value
        assert res.delay_ns == -5_000_000
        assert res.flags & CorrelationFlags.CLOCK_SKEW_SUSPECT
        assert engine.clock_suspect_flags == 1

    def test_implausible_large_delay_flags_clock_skew(self):
        engine = CorrelationEngine(
            timeout_ms=500, clock_skew_threshold_ns=1_000_000_000
        )
        fp = 0xCAFEBABE00000002
        t1 = 1_000_000_000_000
        t2 = 1_002_000_000_000  # +2s (> 1s threshold)

        engine.process_telemetry(_make_telemetry(fp, t1, probe_id=1))
        res = engine.process_telemetry(_make_telemetry(fp, t2, probe_id=2))

        assert res is not None
        assert res.flags & CorrelationFlags.CLOCK_SKEW_SUSPECT

    def test_duplicate_probe2_telemetry_is_ignored(self):
        engine = CorrelationEngine()
        fp = 0xDEADBEEF00000003
        t1 = 1_000_000_000_000
        t2 = 1_000_002_000_000

        engine.process_telemetry(_make_telemetry(fp, t1, probe_id=1))
        res1 = engine.process_telemetry(_make_telemetry(fp, t2, probe_id=2))
        assert res1 is not None

        # Duplicate Probe 2 record arrives
        res2 = engine.process_telemetry(_make_telemetry(fp, t2, probe_id=2))
        assert res2 is None
        assert engine.duplicates_ignored == 1
        assert engine.matched_total == 1


class TestCorrelationEngineExpiryAndLateMatches:
    def test_timeout_emits_unmatched_record(self):
        engine = CorrelationEngine(timeout_ms=500)
        fp = 0x9999999900000001
        t1 = 1_000_000_000_000
        deadline = t1 + 500_000_000

        engine.process_telemetry(_make_telemetry(fp, t1, seq=42, probe_id=1))

        # Check before deadline: no expiry
        expired = engine.expire_deadlines(current_time_ns=deadline - 1)
        assert len(expired) == 0

        # Check at/after deadline: unmatched emitted
        expired = engine.expire_deadlines(current_time_ns=deadline)
        assert len(expired) == 1
        rec = expired[0]
        assert rec.fingerprint == fp
        assert rec.match_state == MatchState.UNMATCHED.value
        assert rec.probe1_observed is True
        assert rec.probe2_observed is False
        assert rec.t1_ns == t1
        assert rec.t2_ns is None
        assert rec.delay_ns is None
        assert rec.probe1_seq == 42
        assert engine.unmatched_total == 1
        assert engine.get_stats()["correlation"]["in_flight"] == 0

    def test_late_arrival_after_timeout_transitions_to_late_match(self):
        engine = CorrelationEngine(timeout_ms=500)
        fp = 0x9999999900000002
        t1 = 1_000_000_000_000
        deadline = t1 + 500_000_000

        engine.process_telemetry(_make_telemetry(fp, t1, seq=100, probe_id=1))
        engine.expire_deadlines(current_time_ns=deadline + 1)
        assert engine.unmatched_total == 1

        # Probe 2 arrives late (at deadline + 100 ms)
        t2 = deadline + 100_000_000
        late_res = engine.process_telemetry(
            _make_telemetry(fp, t2, seq=200, probe_id=2)
        )

        assert late_res is not None
        assert late_res.match_state == MatchState.LATE.value
        assert late_res.fingerprint == fp
        assert late_res.delay_ns == t2 - t1
        assert late_res.probe1_seq == 100
        assert late_res.probe2_seq == 200
        assert engine.late_total == 1

    def test_probe2_arriving_before_probe1_matches_out_of_order(self):
        engine = CorrelationEngine(timeout_ms=500)
        fp = 0x8888888800000003
        t1 = 1_000_000_000_000
        t2 = 1_000_004_000_000  # +4 ms

        # Probe 2 arrives first
        res1 = engine.process_telemetry(_make_telemetry(fp, t2, seq=55, probe_id=2))
        assert res1 is None

        # Probe 1 arrives shortly after
        res2 = engine.process_telemetry(_make_telemetry(fp, t1, seq=44, probe_id=1))
        assert res2 is not None
        assert res2.match_state == MatchState.MATCHED.value
        assert res2.delay_ns == 4_000_000
        assert res2.probe1_seq == 44
        assert res2.probe2_seq == 55

    def test_probe2_only_expires_if_probe1_never_seen(self):
        engine = CorrelationEngine(probe2_grace_ms=100)
        fp = 0x8888888800000004
        t2 = 1_000_000_000_000

        engine.process_telemetry(_make_telemetry(fp, t2, seq=77, probe_id=2))
        expired = engine.expire_deadlines(current_time_ns=t2 + 200_000_000)

        assert len(expired) == 1
        rec = expired[0]
        assert rec.match_state == MatchState.PROBE2_ONLY.value
        assert rec.probe1_observed is False
        assert rec.probe2_observed is True
        assert rec.probe2_seq == 77
        assert engine.probe2_only_total == 1


class TestCorrelationEngineRobustness:
    def test_heap_cap_enforces_bounded_memory(self):
        cap = 5
        engine = CorrelationEngine(timeout_ms=500, heap_cap=cap)

        # Ingest 7 Probe 1 packets without Probe 2
        for i in range(7):
            engine.process_telemetry(
                _make_telemetry(fingerprint=i + 1, timestamp_ns=1000 + i, probe_id=1)
            )

        # Capacity was capped at 5
        assert len(engine._table) <= cap
        assert engine.heap_cap_hits >= 2
        assert engine.unmatched_total >= 2

    def test_subscriber_callback_receives_all_events(self):
        engine = CorrelationEngine(timeout_ms=500)
        events: list[CorrelationRecord] = []
        engine.subscribe(events.append)

        fp1 = 0x1111111100000001
        fp2 = 0x2222222200000002

        # 1. Match event
        engine.process_telemetry(_make_telemetry(fp1, 1000, probe_id=1))
        engine.process_telemetry(_make_telemetry(fp1, 2000, probe_id=2))
        assert len(events) == 1
        assert events[0].match_state == MatchState.MATCHED.value

        # 2. Timeout event
        engine.process_telemetry(_make_telemetry(fp2, 3000, probe_id=1))
        engine.expire_deadlines(current_time_ns=3000 + 500_000_000)
        assert len(events) == 2
        assert events[1].match_state == MatchState.UNMATCHED.value

    def test_invalid_telemetry_format_version_is_rejected(self):
        engine = CorrelationEngine()
        # Version 2 in nibble (0x21)
        bad_record = _make_telemetry(type_flags=0x21)
        res = engine.process_telemetry(bad_record)
        assert res is None
        assert engine.version_mismatches == 1

    def test_get_stats_contains_expected_keys(self):
        engine = CorrelationEngine()
        fp = 0x5555555500000001
        engine.process_telemetry(_make_telemetry(fp, 1000, probe_id=1))
        engine.process_telemetry(_make_telemetry(fp, 5000, probe_id=2))

        stats = engine.get_stats()
        assert "correlation" in stats
        assert "structures" in stats
        assert "latency" in stats
        assert stats["correlation"]["matched_total"] == 1
        assert stats["latency"]["count"] == 1


def test_deadline_checked_before_matching_without_timer_tick():
    now = [1_000_000_000]
    engine = CorrelationEngine(clock_ns=lambda: now[0])
    events = []
    engine.subscribe(events.append)
    engine.process_telemetry(_make_telemetry(timestamp_ns=now[0]))
    now[0] += 500_000_000
    result = engine.process_telemetry(_make_telemetry(timestamp_ns=now[0], probe_id=2))
    assert [event.match_state for event in events] == ["unmatched", "late"]
    assert result.deadline_ns == now[0]
    stats = engine.get_stats()["correlation"]
    assert stats["late_recoveries"] == 1
    assert stats["uncorrected_unmatched_total"] == 0


def test_repeated_fingerprint_pairs_fifo_and_deduplicates_each_observation():
    engine = CorrelationEngine()
    for seq in (1, 2):
        record = _make_telemetry(timestamp_ns=1000 + seq, seq=seq)
        engine.process_telemetry(record)
        engine.process_telemetry(record)
    results = [
        engine.process_telemetry(
            _make_telemetry(timestamp_ns=2000 + seq, seq=seq, probe_id=2)
        )
        for seq in (10, 11)
    ]
    assert [(r.probe1_seq, r.probe2_seq) for r in results] == [(1, 10), (2, 11)]
    assert results[0].flags & CorrelationFlags.COLLISION_DISAMBIGUATED
    assert engine.matched_total == 2
    assert engine.duplicates_ignored == 2
    assert engine.get_stats()["structures"]["heap_entries"] == 0


def test_length_disambiguates_collision_and_reverse_deadline_uses_t1():
    engine = CorrelationEngine()
    for length in (64, 128):
        engine.process_telemetry(_make_telemetry(captured_len=length))
    result = engine.process_telemetry(_make_telemetry(probe_id=2, captured_len=128))
    assert result is not None
    assert engine.get_stats()["correlation"]["in_flight"] == 1
    reverse = CorrelationEngine()
    reverse.process_telemetry(_make_telemetry(timestamp_ns=2000, probe_id=2))
    match = reverse.process_telemetry(_make_telemetry(timestamp_ns=1000))
    assert match.deadline_ns == 1000 + reverse.timeout_ns


def test_late_observation_cannot_steal_newer_same_fingerprint():
    engine = CorrelationEngine()
    engine.process_telemetry(_make_telemetry(timestamp_ns=1000, seq=1))
    engine.expire_deadlines(500_001_000)
    engine.process_telemetry(_make_telemetry(timestamp_ns=600_000_000, seq=2))
    late = engine.process_telemetry(
        _make_telemetry(timestamp_ns=700_000_000, probe_id=2, seq=3)
    )
    assert late.match_state == "late"
    assert late.probe1_seq == 1
    assert engine.get_stats()["correlation"]["in_flight"] == 1


@pytest.mark.parametrize("probe_id", [1, 2])
def test_all_pending_structures_and_caches_bounded_under_flood(probe_id):
    engine = CorrelationEngine(heap_cap=8, recent_cache_size=5)
    events = []
    engine.subscribe(events.append)
    for fingerprint in range(100):
        engine.process_telemetry(
            _make_telemetry(fingerprint=fingerprint, seq=fingerprint, probe_id=probe_id)
        )
    structures = engine.get_stats()["structures"]
    assert structures["hash_entries"] == 8
    assert structures["heap_entries"] <= 16
    assert structures["expired_cache_entries"] <= 5
    assert structures["recent_match_entries"] <= 5
    assert len(events) == 92
    assert all(event.flags & CorrelationFlags.CAPACITY_EVICTED for event in events)


def test_heap_stays_bounded_during_successful_match_flood():
    engine = CorrelationEngine(heap_cap=8, recent_cache_size=5)
    for fingerprint in range(100):
        for probe_id in (1, 2):
            engine.process_telemetry(
                _make_telemetry(
                    fingerprint=fingerprint, seq=fingerprint, probe_id=probe_id
                )
            )
    assert engine.matched_total == 100
    assert engine.get_stats()["structures"]["heap_entries"] == 0


def test_reverse_arrival_uses_full_configured_window():
    now = [1_000_000_000]
    engine = CorrelationEngine(clock_ns=lambda: now[0])
    engine.process_telemetry(_make_telemetry(timestamp_ns=now[0], probe_id=2))
    now[0] += 200_000_000  # beyond the draft's hard-coded 100 ms grace
    result = engine.process_telemetry(_make_telemetry(timestamp_ns=1_000_000_000))
    assert result.match_state == "matched"
    assert engine.probe2_only_total == 0


def test_skew_samples_excluded_and_subscriber_failure_observable():
    engine = CorrelationEngine()
    events = []

    def broken(_record):
        raise RuntimeError("storage unavailable")

    engine.subscribe(broken)
    engine.subscribe(events.append)
    engine.process_telemetry(_make_telemetry(timestamp_ns=2000))
    engine.process_telemetry(_make_telemetry(timestamp_ns=1000, probe_id=2))
    assert len(events) == 1
    assert engine.subscriber_errors == 1
    assert engine.get_stats()["latency"]["count"] == 0


@pytest.mark.parametrize(
    "options",
    [
        {"heap_cap": 0},
        {"timeout_ms": 0},
        {"recent_cache_size": 0},
        {"probe1_id": 2},
        {"probe1_id": 0},
    ],
)
def test_invalid_configuration_rejected(options):
    with pytest.raises(ValueError):
        CorrelationEngine(**options)
