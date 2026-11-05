"""Bounded, single-event-loop two-probe correlation with FIFO matching."""

from __future__ import annotations

import heapq
import logging
import time
from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from backend.models import (
    CorrelationFlags,
    CorrelationRecord,
    MatchState,
    ProbeTelemetry,
)

DEFAULT_MATCH_TIMEOUT_MS = 500
DEFAULT_HEAP_CAP = 200_000
DEFAULT_CLOCK_SKEW_THRESHOLD_NS = 10_000_000_000
DEFAULT_RECENT_CACHE_SIZE = 50_000
Key = tuple[int, int]
logger = logging.getLogger(__name__)


@dataclass
class _Entry:
    token: int
    record: ProbeTelemetry
    deadline_ns: int
    flags: int = 0

    @property
    def key(self) -> Key:
        return self.record.fingerprint, self.record.captured_len


class CorrelationEngine:
    """FIFO per (fingerprint, captured length); bounded observation retention.

    Probe sequence numbers identify duplicates locally, never across probes.
    All methods must be called on the same thread/event loop. ``clock_ns`` can
    be supplied for deterministic replay. Expiration is inclusive (now >= T1
    + timeout), including when a record beats the periodic expiration task.
    """

    def __init__(
        self,
        timeout_ms: int = DEFAULT_MATCH_TIMEOUT_MS,
        heap_cap: int = DEFAULT_HEAP_CAP,
        clock_skew_threshold_ns: int = DEFAULT_CLOCK_SKEW_THRESHOLD_NS,
        probe1_id: int = 1,
        probe2_id: int = 2,
        *,
        recent_cache_size: int = DEFAULT_RECENT_CACHE_SIZE,
        clock_ns: Callable[[], int] = time.time_ns,
        probe2_grace_ms: int | None = None,
    ) -> None:
        if min(timeout_ms, heap_cap, recent_cache_size, clock_skew_threshold_ns) <= 0:
            raise ValueError("timeouts and capacities must be positive")
        if not (1 <= probe1_id <= 255 and 1 <= probe2_id <= 255):
            raise ValueError("probe IDs must be in 1..255")
        if probe1_id == probe2_id:
            raise ValueError("probe IDs must differ")
        self.timeout_ns = timeout_ms * 1_000_000
        self.probe2_grace_ns = (
            timeout_ms if probe2_grace_ms is None else probe2_grace_ms
        ) * 1_000_000
        if self.probe2_grace_ns <= 0:
            raise ValueError("probe2 grace must be positive")
        self.heap_cap = heap_cap
        self.clock_skew_threshold_ns = clock_skew_threshold_ns
        self.probe1_id, self.probe2_id = probe1_id, probe2_id
        self.recent_cache_size = recent_cache_size
        self._clock_ns = clock_ns
        self._token = 0
        self._table: dict[Key, dict[int, _Entry]] = {}
        self._pending_p2: dict[Key, dict[int, _Entry]] = {}
        self._active: dict[int, _Entry] = {}
        self._deadline_heap: list[tuple[int, int]] = []
        self._expired_cache: OrderedDict[int, _Entry] = OrderedDict()
        self._expired_keys: dict[Key, dict[int, _Entry]] = {}
        self._seen: OrderedDict[ProbeTelemetry, None] = OrderedDict()
        self._subscribers: list[Callable[[CorrelationRecord], None]] = []
        self._delay_samples: deque[float] = deque(maxlen=10_000)
        self.matched_total = 0
        self.unmatched_total = 0  # cumulative timeout events, including corrections
        self.late_total = 0
        self.late_recoveries = 0
        self.duplicates_ignored = 0
        self.probe2_only_total = 0
        self.clock_suspect_flags = 0
        self.heap_cap_hits = 0
        self.version_mismatches = 0
        self.subscriber_errors = 0

    def subscribe(self, callback: Callable[[CorrelationRecord], None]) -> None:
        if callback not in self._subscribers:
            self._subscribers.append(callback)

    def probe_status(self) -> dict[str, Any]:
        """Compatibility probe status for CorrelationEngine."""
        return {
            "probe1_connected": False,
            "probe1_ip": None,
            "probe2_connected": False,
            "probe2_ip": None,
            "active_clients": [],
            "total_connected": 0,
        }

    def unsubscribe(self, callback: Callable[[CorrelationRecord], None]) -> None:
        if callback in self._subscribers:
            self._subscribers.remove(callback)

    def _emit(self, record: CorrelationRecord) -> CorrelationRecord:
        for callback in tuple(self._subscribers):
            try:
                callback(record)
            except Exception:
                self.subscriber_errors += 1
                logger.exception("Correlation subscriber failed")
        return record

    def process_telemetry(
        self, record: ProbeTelemetry, *, flags: int = 0
    ) -> CorrelationRecord | None:
        """Process one observation, expiring overdue observations first."""
        if record.type_flags >> 4 != 1:
            self.version_mismatches += 1
            return None
        if record.type_flags & 15 != 1:
            return None
        if record.probe_id not in (self.probe1_id, self.probe2_id):
            return None
        now = self._clock_ns()
        self.expire_deadlines(now)
        if record in self._seen:
            self.duplicates_ignored += 1
            return None
        self._seen[record] = None
        if len(self._seen) > self.recent_cache_size:
            self._seen.popitem(last=False)
        key = record.fingerprint, record.captured_len
        if record.probe_id == self.probe1_id:
            counterpart = self._take(self._pending_p2, key)
            if counterpart:
                return self._match(
                    record, counterpart.record, now, flags | counterpart.flags
                )
        else:
            # Oldest unclaimed observation wins, including expired observations.
            expired = self._take(self._expired_keys, key)
            if expired:
                self._expired_cache.pop(expired.token)
                return self._match(
                    expired.record, record, now, flags | expired.flags, late=True
                )
            counterpart = self._take(self._table, key)
            if counterpart:
                return self._match(
                    counterpart.record, record, now, flags | counterpart.flags
                )
        self._insert(record, flags, now)
        return None

    def _take(self, buckets: dict[Key, dict[int, _Entry]], key: Key) -> _Entry | None:
        bucket = buckets.get(key)
        if not bucket:
            return None
        token = next(iter(bucket))
        entry = bucket.pop(token)
        if bucket:
            entry.flags |= CorrelationFlags.COLLISION_DISAMBIGUATED
        else:
            del buckets[key]
        self._active.pop(token, None)
        self._compact_heap()
        return entry

    def _insert(self, record: ProbeTelemetry, flags: int, now: int) -> None:
        if len(self._active) >= self.heap_cap:
            self.heap_cap_hits += 1
            self._expire_one(now, capacity=True)
        self._token += 1
        source = record.probe_id == self.probe1_id
        deadline = (
            record.timestamp_ns + self.timeout_ns
            if source
            else now + self.probe2_grace_ns
        )
        entry = _Entry(self._token, record, deadline, flags)
        buckets = self._table if source else self._pending_p2
        buckets.setdefault(entry.key, {})[entry.token] = entry
        self._active[entry.token] = entry
        heapq.heappush(self._deadline_heap, (deadline, entry.token))
        self._compact_heap()
        # Historical/replayed T1 can already be overdue on first receipt.
        self.expire_deadlines(now)

    def _compact_heap(self) -> None:
        # Lazy removal is amortized; at most 2*cap nodes survive any operation.
        if not self._active:
            self._deadline_heap.clear()
        elif len(self._deadline_heap) > 2 * len(self._active):
            self._deadline_heap = [
                (entry.deadline_ns, token) for token, entry in self._active.items()
            ]
            heapq.heapify(self._deadline_heap)

    def _match(
        self,
        first: ProbeTelemetry,
        second: ProbeTelemetry,
        now: int,
        flags: int,
        *,
        late: bool = False,
    ) -> CorrelationRecord:
        deadline = first.timestamp_ns + self.timeout_ns
        delay = second.timestamp_ns - first.timestamp_ns
        if delay < 0 or delay > self.clock_skew_threshold_ns:
            flags |= CorrelationFlags.CLOCK_SKEW_SUSPECT
        if flags & CorrelationFlags.CLOCK_SKEW_SUSPECT:
            self.clock_suspect_flags += 1
        else:
            self._delay_samples.append(delay / 1_000_000)
        if late:
            self.late_recoveries += 1
        late = late or now >= deadline
        if late:
            self.late_total += 1
        else:
            self.matched_total += 1
        return self._emit(
            CorrelationRecord(
                fingerprint=first.fingerprint,
                probe1_observed=True,
                probe2_observed=True,
                t1_ns=first.timestamp_ns,
                t2_ns=second.timestamp_ns,
                delay_ns=delay,
                match_state=MatchState.LATE.value if late else MatchState.MATCHED.value,
                deadline_ns=deadline,
                flags=int(flags),
                probe1_seq=first.seq,
                probe2_seq=second.seq,
                created_at_ns=now,
            )
        )

    def _expire_one(self, now: int, *, capacity: bool = False) -> CorrelationRecord:
        while True:
            _, token = heapq.heappop(self._deadline_heap)
            entry = self._active.pop(token, None)
            if entry is not None:
                break
        source = entry.record.probe_id == self.probe1_id
        buckets = self._table if source else self._pending_p2
        bucket = buckets[entry.key]
        del bucket[token]
        if not bucket:
            del buckets[entry.key]
        if capacity:
            entry.flags |= CorrelationFlags.CAPACITY_EVICTED
        if source:
            self.unmatched_total += 1
            self._expired_cache[token] = entry
            self._expired_keys.setdefault(entry.key, {})[token] = entry
            if len(self._expired_cache) > self.recent_cache_size:
                old_token, old = self._expired_cache.popitem(last=False)
                old_bucket = self._expired_keys[old.key]
                del old_bucket[old_token]
                if not old_bucket:
                    del self._expired_keys[old.key]
        else:
            self.probe2_only_total += 1
        return self._emit(
            CorrelationRecord(
                fingerprint=entry.record.fingerprint,
                probe1_observed=source,
                probe2_observed=not source,
                t1_ns=entry.record.timestamp_ns if source else None,
                t2_ns=None if source else entry.record.timestamp_ns,
                match_state=(
                    MatchState.UNMATCHED.value
                    if source
                    else MatchState.PROBE2_ONLY.value
                ),
                deadline_ns=entry.deadline_ns,
                flags=int(entry.flags),
                probe1_seq=entry.record.seq if source else None,
                probe2_seq=None if source else entry.record.seq,
                created_at_ns=now,
            )
        )

    def expire_deadlines(
        self, current_time_ns: int | None = None
    ) -> list[CorrelationRecord]:
        """Emit expirations at the inclusive boundary; also reclaim heap nodes."""
        now = self._clock_ns() if current_time_ns is None else current_time_ns
        events = []
        while self._deadline_heap and self._deadline_heap[0][0] <= now:
            if self._deadline_heap[0][1] not in self._active:
                heapq.heappop(self._deadline_heap)
                continue
            events.append(self._expire_one(now))
        self._compact_heap()
        return events

    def get_stats(self) -> dict[str, Any]:
        samples = sorted(self._delay_samples)
        latency: dict[str, Any] = {"count": len(samples)}
        for label, quantile in (("p50_ms", 0.50), ("p95_ms", 0.95), ("p99_ms", 0.99)):
            latency[label] = (
                round(samples[min(int(len(samples) * quantile), len(samples) - 1)], 3)
                if samples
                else None
            )
        latency["min_ms"] = round(samples[0], 3) if samples else None
        latency["max_ms"] = round(samples[-1], 3) if samples else None
        return {
            "correlation": {
                "in_flight": sum(map(len, self._table.values())),
                "matched_total": self.matched_total,
                "unmatched_total": self.unmatched_total,
                "late_total": self.late_total,
                "late_recoveries": self.late_recoveries,
                "uncorrected_unmatched_total": self.unmatched_total
                - self.late_recoveries,
                "duplicates_ignored": self.duplicates_ignored,
                "probe2_only_total": self.probe2_only_total,
                "clock_suspect_flags": self.clock_suspect_flags,
                "heap_cap_hits": self.heap_cap_hits,
                "version_mismatches": self.version_mismatches,
                "subscriber_errors": self.subscriber_errors,
            },
            "structures": {
                "hash_entries": len(self._active),
                "heap_entries": len(self._deadline_heap),
                "heap_cap": self.heap_cap,
                "pending_probe2_entries": sum(map(len, self._pending_p2.values())),
                "expired_cache_entries": len(self._expired_cache),
                "recent_match_entries": len(self._seen),
                "recent_cache_size": self.recent_cache_size,
            },
            "latency": latency,
        }
