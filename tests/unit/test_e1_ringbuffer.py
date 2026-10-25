"""Unit tests for Engine E1 Bounded Circular Ring Buffer."""

import threading
import time
import pytest

from backend.e1_capture.ring_buffer import BoundedRingBuffer
from backend.models import CapturedPacket


def _make_dummy_packet(seq: int) -> CapturedPacket:
    return CapturedPacket(
        probe_id=1,
        seq=seq,
        timestamp_ns=1_000_000_000 + seq,
        captured_len=64,
        original_len=64,
        data=b"\x00" * 64,
        interface="eth0",
    )


def test_ring_buffer_fifo_ordering():
    """Items popped from the ring buffer must strictly follow FIFO insertion order."""
    buf = BoundedRingBuffer[int](capacity=5)
    assert buf.is_empty()
    assert not buf.is_full()

    for i in range(5):
        assert buf.push(i)

    assert buf.is_full()
    assert buf.size() == 5

    results = []
    for _ in range(5):
        results.append(buf.pop(timeout=0.1))

    assert results == [0, 1, 2, 3, 4]
    assert buf.is_empty()
    assert buf.pushed_count == 5
    assert buf.popped_count == 5
    assert buf.dropped_count == 0


def test_ring_buffer_wrap_around():
    """Buffer should smoothly wrap around head and tail pointers across multiple cycles."""
    buf = BoundedRingBuffer[int](capacity=3)

    # Cycle 1
    buf.push(10)
    buf.push(20)
    assert buf.pop() == 10

    # Cycle 2 (causes tail to wrap around)
    buf.push(30)
    buf.push(40)
    assert buf.pop() == 20
    assert buf.pop() == 30
    assert buf.pop() == 40
    assert buf.is_empty()


def test_ring_buffer_non_blocking_saturation_drop():
    """In non-blocking mode (default), pushing into a full buffer must drop the packet."""
    capacity = 4
    buf = BoundedRingBuffer[int](capacity=capacity)

    for i in range(capacity):
        assert buf.push(i, block=False) is True

    # Buffer is now saturated. Further pushes must be dropped.
    assert buf.push(999, block=False) is False
    assert buf.push(1000, block=False) is False

    assert buf.dropped_count == 2
    assert buf.pushed_count == 4

    # Draining one slot allows a new item
    assert buf.pop() == 0
    assert buf.push(500, block=False) is True
    assert buf.pushed_count == 5


def test_ring_buffer_blocking_push_with_timeout():
    """Blocking push should wait until space is available or timeout."""
    buf = BoundedRingBuffer[int](capacity=2)
    buf.push(1)
    buf.push(2)

    # Attempt to push with small timeout on saturated buffer
    start = time.perf_counter()
    success = buf.push(3, block=True, timeout=0.05)
    elapsed = time.perf_counter() - start

    assert not success
    assert elapsed >= 0.04
    assert buf.dropped_count == 1


def test_ring_buffer_close_drains_and_unblocks():
    """Closing the buffer unblocks waiting consumers and lets them drain existing items."""
    buf = BoundedRingBuffer[int](capacity=5)
    buf.push(100)
    buf.push(200)

    buf.close()
    assert buf.is_closed

    # Further pushes must be rejected
    assert buf.push(300) is False

    # Existing items can still be retrieved
    assert buf.pop(timeout=0.1) == 100
    assert buf.pop(timeout=0.1) == 200
    # Once empty, pop returns None immediately
    assert buf.pop(timeout=0.1) is None


def test_ring_buffer_concurrent_producers_and_consumers():
    """Multi-threaded stress test with concurrent producer and consumer threads."""
    capacity = 100
    total_items = 2_000
    buf = BoundedRingBuffer[int](capacity=capacity)

    def producer():
        for i in range(total_items):
            # Use blocking push so all items get in
            buf.push(i, block=True, timeout=2.0)
        buf.close()

    received: list[int] = []
    received_lock = threading.Lock()

    def consumer():
        while True:
            item = buf.pop(timeout=0.1)
            if item is None:
                if buf.is_closed and buf.is_empty():
                    break
                continue
            with received_lock:
                received.append(item)

    prod_thread = threading.Thread(target=producer)
    cons_threads = [threading.Thread(target=consumer) for _ in range(3)]

    for t in cons_threads:
        t.start()
    prod_thread.start()

    prod_thread.join(timeout=5.0)
    for t in cons_threads:
        t.join(timeout=5.0)

    assert not prod_thread.is_alive()
    assert len(received) == total_items
    assert sorted(received) == list(range(total_items))
    assert buf.dropped_count == 0
