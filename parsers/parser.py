import re
from parsers.event import *
from abc import ABC, abstractmethod

class IParser(ABC):
    def __init__(self, data, source: str):
        self.data = data
        self.source = source

    @abstractmethod
    def parse(self) -> list:
        raise NotImplementedError

class Apache(IParser):
    def __init__(self, data: str):
        super().__init__(data, "apache")

        self.regex = (
            r"^\[(?P<timestamp>[^\]]+)\]\s+"
            r"\[(?P<level>[^\]]+)\]\s+"
            r"(?P<message>.*)$"
        )

    def parse(self):
        events = []

        for line in self.data.splitlines():
            match = re.match(self.regex, line)

            if match:
                event = ApacheEvent(
                    timestamp = match.group("timestamp"),
                    level = match.group("level"),
                    message = match.group("message")
                )

                events.append(event)

        return events

class SysLog(IParser):
    def __init__(self, data: str):
        super().__init__(data, "syslog")

        self.regex = (
            r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+"
            r"\d{2}:\d{2}:\d{2})\s+"
            r"(?P<host>\S+)\s+"
            r"(?P<component>[^\[:]+)"
            r"(?:\[(?P<pid>\d+)\])?:\s+"
            r"(?P<message>.*)$"
        )

    def parse(self):
        events = []

        for line in self.data.splitlines():
            match = re.match(self.regex, line)

            if match:
                event = SysLogEvent(
                    timestamp = match.group("timestamp"),
                    host = match.group("host"),
                    component = match.group("component"),
                    pid = int(match.group("pid")) if match.group("pid") else None,
                    message = match.group("message")
                )

                events.append(event)

        return events

class GenParser:
    def __init__(self, data: str, source: str):
        self.data = data
        self.source = source

    def get_parser(self) -> IParser:
        if self.source == "apache":
            return Apache(self.data)

        if self.source == "syslog":
            return SysLog(self.data)

        raise ValueError(f"Unsupported Parser source : {self.source}")