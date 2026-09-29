from dataclasses import dataclass

@dataclass
class ApacheEvent:
    timestamp: str
    level: str
    message: str

@dataclass
class SysLogEvent:
    timestamp: str
    host: str
    component: str
    pid: int | None
    message: str