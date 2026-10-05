from enum import Enum, auto
from dataclasses import dataclass
from typing import Any, Callable, TypeVar, Generic

from PySide6.QtWidgets import QPushButton
from PySide6.QtCore import Signal, QObject

class ReturnType(Enum):
    SAVING = auto()
    REMOVING = auto()
    SELECTED = auto()
    SAVE_ALL = auto()
    PROCESSING = auto()
    PROCESS_ALL = auto()

@dataclass
class DataPacket:
    data: Any
    rt_type: ReturnType

class Receive(QObject):
    incoming = Signal(object)

    def __init__(self):
        super().__init__()

        self.data: DataPacket | None = None
        self.incoming.connect(self._receive)

    def _receive(self, data: DataPacket):
        self.data = data

    def eject(self) -> DataPacket | None:
        packet: DataPacket = self.data

        self.data = None
        return packet

class Send():
    def send(self, data: DataPacket, destination: Receive):
        destination.incoming.emit(data)

@dataclass
class Node:
    source: Send
    terminal: Receive

@dataclass
class Event:
    method: Callable[[], DataPacket | Any] | None = None

@dataclass
class Connection:
    A: Node
    B: Node 
    name: str

class NetworkManager:
    def transmit(self, connection: Connection, payload: Event | DataPacket):
        if isinstance(payload, Event):
            receive = payload.method()

            if isinstance(receive, DataPacket):
                payload: DataPacket = receive

            if isinstance(receive, int):
                payload = DataPacket(data = receive)

        if payload:
            connection.A.source.send(payload, connection.B.terminal)

    def produce_connection(self, _from: Node, _to: Node, name: str) -> Connection:
        return Connection(A = _from, B = _to, name = name)

class ButtonType(Enum):
    SAVE = auto()
    REMOVE = auto()
    PROCESS = auto()

@dataclass
class Button:
    event: Event
    instance: QPushButton
    bt_type: ButtonType | None = None

T = TypeVar("T")

class Component(Generic[T]):
    def __init__(self, component: T):
        self.node = Node(
            source = Send(),
            terminal = Receive()
        )

        self.component = component