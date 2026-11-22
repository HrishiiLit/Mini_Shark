"""Engine interface stubs for Mini Shark.

Each engine provides a callable class or function following a simple protocol.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable

from .models import DecodedPacket, Flow, Packet


class EngineE1(ABC):
    """Engine E1 - Packet & Frame Processing.

    Subclass must implement ``load_capture(path: str) -> List[Packet]``.
    """

    @abstractmethod
    def load_capture(self, path: str) -> list[Packet]: ...


class EngineE2(ABC):
    """Engine E2 - Protocol Dissection.

    Subclass must implement ``dissect(packets) -> list[DecodedPacket]``.
    """

    @abstractmethod
    def dissect(self, packets: Iterable[Packet]) -> list[DecodedPacket]: ...


class EngineE3(ABC):
    """Engine E3 - Flow & Traffic Analysis.

    Subclass must implement ``group(decoded: Iterable[DecodedPacket]) -> List[Flow]``.
    """

    @abstractmethod
    def group(self, decoded: Iterable[DecodedPacket]) -> list[Flow]: ...


class EngineE4(ABC):
    """Engine E4 - Traffic Query & Reporting.

    Subclass must implement a storage and query interface. For now we define a stub.
    """

    @abstractmethod
    def store(self, flows: list[Flow], packets: list[Packet]) -> None: ...

    @abstractmethod
    def query(self, sql_like: str) -> list[Flow]: ...
