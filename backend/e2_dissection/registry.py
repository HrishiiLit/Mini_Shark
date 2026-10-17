"""Dissector registry for Engine E2.

A dissector consumes the bytes of one layer and returns::

    (layer, payload, next_dispatch)

- ``layer``      the decoded :class:`~backend.models.Layer`
- ``payload``    bytes handed to the next layer (``None`` stops the walk)
- ``next_dispatch`` a ``(namespace, candidates)`` pair telling the walker
  which handler to try next; ``None`` also stops the walk.

Dispatch namespaces used by the default registry:

===========  =========================================================
``link``     data-link type (DLT) of the frame, e.g. ``1`` = Ethernet
``ethertype`` Ethernet II type field, e.g. ``0x0800`` = IPv4
``ipproto``  IP protocol number, e.g. ``6`` = TCP
``port``     transport ports, tried in order (destination first)
===========  =========================================================

Handlers are looked up by id, so adding a protocol is a registration call
and never a change to the walker.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import TypeAlias

from backend.models import Layer

Dispatch: TypeAlias = tuple[str, tuple[int, ...]]
Dissector: TypeAlias = Callable[[bytes], tuple[Layer, bytes | None, Dispatch | None]]


class DissectorRegistry:
    """Maps ``(namespace, id)`` pairs to named dissector functions."""

    def __init__(self) -> None:
        self._namespaces: dict[str, dict[int, tuple[str, Dissector]]] = {}

    def register(
        self, namespace: str, identifier: int, name: str, handler: Dissector
    ) -> None:
        """Register ``handler`` under ``namespace``/``identifier``."""
        self._namespaces.setdefault(namespace, {})[identifier] = (name, handler)

    def lookup(
        self, namespace: str, candidates: Sequence[int]
    ) -> tuple[str, Dissector] | None:
        """Return the first registered handler for any candidate id."""
        table = self._namespaces.get(namespace, {})
        for identifier in candidates:
            entry = table.get(identifier)
            if entry is not None:
                return entry
        return None
