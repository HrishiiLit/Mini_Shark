"""Bounded Circular Ring Buffer for Engine E1 (Packet Capture).

Implements the classic Operating Systems Producer-Consumer pattern using
mutex synchronization (threading.Lock) and condition variables (threading.Condition).

Design characteristics:
- Bounded memory footprint (pre-allocated fixed-capacity slots).
- Non-blocking push for the capture producer thread to absorb bursts without
  blocking the network interface / raw socket.
- Monotonic drop counter tracking saturated buffer events (tail-drop).
- Blocking pop with configurable timeout and graceful shutdown signaling.
"""

from __future__ import annotations

import threading
from typing import Generic, TypeVar

from backend.models import CapturedPacket

T = TypeVar("T")


class BoundedRingBuffer(Generic[T]):
    """Thread-safe bounded circular ring buffer with condition variables.

    Attributes:
        capacity: Maximum number of elements the buffer can hold simultaneously.
    """

    def __init__(self, capacity: int = 10_000) -> None:
        if capacity <= 0:
            raise ValueError(f"Ring buffer capacity must be positive, got {capacity}")

        self.capacity: int = capacity
        self._slots: list[T | None] = [None] * capacity
        self._head: int = 0  # Read pointer (consumer)
        self._tail: int = 0  # Write pointer (producer)
        self._count: int = 0  # Current occupied slots

        self._lock = threading.Lock()
        self._not_empty = threading.Condition(self._lock)
        self._not_full = threading.Condition(self._lock)

        self._closed: bool = False
        self._pushed_count: int = 0
        self._popped_count: int = 0
        self._dropped_count: int = 0

    @property
    def pushed_count(self) -> int:
        """Total items successfully accepted into the ring buffer."""
        with self._lock:
            return self._pushed_count

    @property
    def popped_count(self) -> int:
        """Total items retrieved by consumers."""
        with self._lock:
            return self._popped_count

    @property
    def dropped_count(self) -> int:
        """Total items dropped due to buffer saturation."""
        with self._lock:
            return self._dropped_count

    @property
    def is_closed(self) -> bool:
        """Whether the buffer is closed for new writes."""
        with self._lock:
            return self._closed

    def is_empty(self) -> bool:
        """Return True if no items are currently queued."""
        with self._lock:
            return self._count == 0

    def is_full(self) -> bool:
        """Return True if buffer is at full capacity."""
        with self._lock:
            return self._count == self.capacity

    def size(self) -> int:
        """Return the current number of queued items."""
        with self._lock:
            return self._count

    def push(
        self,
        item: T,
        block: bool = False,
        timeout: float | None = None,
    ) -> bool:
        """Push an item into the circular buffer.

        Args:
            item: The element to store (e.g. CapturedPacket).
            block: If True, blocks until space becomes available.
                   If False (default for real-time capture), drops the packet
                   on saturation to prevent blocking the network socket.
            timeout: Maximum seconds to wait when block=True.

        Returns:
            True if the item was queued; False if dropped due to saturation
            or if the buffer is closed.
        """
        with self._lock:
            if self._closed:
                return False

            if self._count == self.capacity:
                if not block:
                    self._dropped_count += 1
                    return False

                # Blocking mode: wait until consumer drains a slot
                wait_success = self._not_full.wait_for(
                    lambda: self._count < self.capacity or self._closed,
                    timeout=timeout,
                )
                if self._closed or not wait_success or self._count == self.capacity:
                    self._dropped_count += 1
                    return False

            # Insert at tail and advance circular pointer
            self._slots[self._tail] = item
            self._tail = (self._tail + 1) % self.capacity
            self._count += 1
            self._pushed_count += 1

            # Notify waiting consumers
            self._not_empty.notify()
            return True

    def pop(self, timeout: float | None = None) -> T | None:
        """Pop the oldest item from the buffer (FIFO).

        Blocks until an item is available, timeout expires, or the buffer
        is closed and completely drained.

        Args:
            timeout: Maximum seconds to wait. None means block indefinitely.

        Returns:
            The queued item, or None if timed out or closed and empty.
        """
        with self._lock:
            # Wait while buffer is empty and not closed
            if self._count == 0:
                if self._closed:
                    return None
                wait_success = self._not_empty.wait_for(
                    lambda: self._count > 0 or self._closed,
                    timeout=timeout,
                )
                if not wait_success or self._count == 0:
                    return None

            # Retrieve from head and advance circular pointer
            item = self._slots[self._head]
            self._slots[self._head] = None  # Release reference for GC
            self._head = (self._head + 1) % self.capacity
            self._count -= 1
            self._popped_count += 1

            # Notify any waiting producer in blocking mode
            self._not_full.notify()
            return item

    def close(self) -> None:
        """Close the ring buffer, waking all waiting producers and consumers.

        Any remaining items can still be popped until empty.
        """
        with self._lock:
            self._closed = True
            self._not_empty.notify_all()
            self._not_full.notify_all()

    def clear(self) -> None:
        """Reset the buffer state and discard all currently queued items."""
        with self._lock:
            self._slots = [None] * self.capacity
            self._head = 0
            self._tail = 0
            self._count = 0
            self._not_full.notify_all()
