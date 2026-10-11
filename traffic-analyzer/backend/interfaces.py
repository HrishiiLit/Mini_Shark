"""Engine interface stubs for Mini Shark.

Each engine provides a callable class or function following a simple protocol.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable, List

from .models import Packet, DecodedPacket, Flow


class EngineE1(ABC):
    """Engine E1 – Packet & Frame Processing.

    Subclass must implement ``load_capture(path: str) -> List[Packet]``.
    """

    @abstractmethod
    def load_capture(self, path: str) -> List[Packet]:
        ...


class EngineE2(ABC):
    """Engine E2 – Protocol Dissection.

    Subclass must implement ``dissect(packets: Iterable[Packet]) -> List[DecodedPacket]``.
    """

    @abstractmethod
    def dissect(self, packets: Iterable[Packet]) -> List[DecodedPacket]:
        ...


class EngineE3(ABC):
    """Engine E3 – Flow & Traffic Analysis.

    Subclass must implement ``group(decoded: Iterable[DecodedPacket]) -> List[Flow]``.
    """

    @abstractmethod
    def group(self, decoded: Iterable[DecodedPacket]) -> List[Flow]:
        ...


class EngineE4(ABC):
    """Engine E4 – Traffic Query & Reporting.

    Subclass must implement a storage and query interface. For now we define a stub.
    """

    @abstractmethod
    def store(self, flows: List[Flow], packets: List[Packet]) -> None:
        ...

    @abstractmethod
    def query(self, sql_like: str) -> List[Flow]:
        ...
