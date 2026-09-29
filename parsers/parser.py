import re
from abc import ABC, abstractmethod

from parsers.event import *
from process.file_read import read_pattern

def to_int(val) -> int | None:
    if val is None:
        return None

    try:
        return int(val)
    except ValueError:
        return None


class IParser(ABC):
    def __init__(self, data, source: str):
        self.data = data
        self.source = source
        self.patterns = read_pattern(self.source)

    @abstractmethod
    def parse(self) -> list:
        raise NotImplementedError

    @abstractmethod
    def normalize(self, event) -> UniversalEvent:
        raise NotImplementedError

class Apache(IParser):
    def __init__(self, data: str):
        super().__init__(data, "apache")

    def parse(self):
        events = []

        for line in self.data.splitlines():

            for pattern in self.patterns:
                match = re.match(pattern["regex"], line)

                if match:
                    event = ApacheEvent(
                        raw = line,
                        timestamp = match.group("timestamp"),
                        level = match.group("level"),
                        message = match.group("message")
                    )
                    events.append(event)
                    break
        return events

    def normalize(self, event: ApacheEvent):
        return UniversalEvent(
            raw = event.raw,
            source_type = self.source,
            timestamp = event.timestamp,
            product = "Apache",
            severity = event.level
        )

class SysLog(IParser):
    def __init__(self, data: str):
        super().__init__(data, "syslog")

    def parse(self):
        events = []

        for line in self.data.splitlines():

            for pattern in self.patterns:
                match = re.match(pattern["regex"], line)

                if match:
                    event = SysLogEvent(
                        raw = line,
                        timestamp = match.group("timestamp"),
                        host = match.group("host"),
                        component = match.group("component"),
                        pid = int(match.group("pid")) if match.group("pid") else None,
                        message = match.group("message")
                    )
                    events.append(event)
                    break
        return events

    def extract_fields(self, message: str) -> dict:
        fields = {}

        for match in re.finditer(r'(\w+)=([^\s]*)', message):
            fields[match.group(1)] = match.group(2)
        return fields

    def normalize(self, event: SysLogEvent):
        fields = self.extract_fields(event.message)

        return UniversalEvent(
            raw = event.raw,
            source_type = self.source,
            timestamp = event.timestamp,
            host = event.host,
            component = event.component,
            pid = event.pid,

            event_category = "authentication"
                if "authentication failure" in event.message
                else None,

            action = "failure"
                if "authentication failure" in event.message
                else None,

            source_ip = fields.get("rhost"),
            username = fields.get("user"),
        )

class CEF(IParser):
    def __init__(self, data):
        super().__init__(data, "cef")

    def parse(self):
        events = []

        for line in self.data.splitlines():

            for pattern in self.patterns:
                match = re.match(pattern["regex"], line)

                if match:
                    event = CEFEvent(
                        raw = line,
                        version = int(match.group("version")),
                        vendor = match.group("vendor"),
                        product = match.group("product"),
                        device_version = match.group("device_version"),
                        signature_id = match.group("signature_id"),
                        name = match.group("name"),
                        severity = match.group("severity"),
                        extension = match.group("extension")
                    )
                    events.append(event)
                    break
        return events

    def extract_fields(self, extension: str) -> dict:
        fields = {}

        for match in re.finditer(r'(\w+)=(".*?"|\S+)', extension):
            value = match.group(2)

            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]

            fields[match.group(1)] = value
        return fields

    def normalize(self, event: CEFEvent):
        fields = self.extract_fields(event.extension)

        return UniversalEvent(
            raw = event.raw,
            source_type = self.source,
            timestamp = fields.get("rt"),
            vendor = event.vendor,
            product = event.product,
            host = fields.get("dhost"),
            event_type = event.name,
            action = fields.get("act"),
            severity = event.severity,
            source_ip = fields.get("src"),
            source_port = to_int(fields.get("spt")),
            protocol = fields.get("proto"),
            username = fields.get("suser")
        )

class Fortinet(IParser):
    def __init__(self, data):
        super().__init__(data, "fortinet")

    def parse(self):
        events = []

        for line in self.data.splitlines():
            fields = {}

            for pattern in self.patterns:
                for match in re.finditer(pattern["regex"], line):
                    value = (
                        match.group("quoted")
                        if match.group("quoted") is not None
                        else match.group("unquoted")
                    )

                    fields[match.group("key")] = value

                if fields:
                    event = FortinetEvent(
                        raw = line,
                        fields = fields,
                        date = fields.get("date"),
                        time = fields.get("time"),
                        devname = fields.get("devname"),
                        devid = fields.get("devid"),
                        logid = fields.get("logid"),
                        type = fields.get("type"),
                        subtype = fields.get("subtype"),
                        level = fields.get("level")
                    )
                    events.append(event)
                    break
        return events

    def normalize(self, event: FortinetEvent):
        fields = event.fields

        timestamp = None
        if fields.get("date") and fields.get("time"):
            timestamp = f"{fields['date']} {fields['time']}"

        return UniversalEvent(
            raw = event.raw,
            source_type = self.source,
            timestamp = timestamp,
            vendor = "Fortinet",
            product = "FortiGate",
            host = fields.get("devname"),
            event_category = fields.get("type"),
            event_type = fields.get("subtype"),
            action = fields.get("action"),
            severity = fields.get("level"),
            source_ip = fields.get("srcip"),
            source_port = to_int(fields.get("srcport")),
            destination_ip = fields.get("dstip"),
            destination_port = to_int(fields.get("dstport")),
            protocol = fields.get("proto"),
            username = fields.get("user")
        )

class GenParser:
    def __init__(self, data: str, source: str):
        self.data = data
        self.source = source

    def get_parser(self) -> IParser:
        if self.source == "apache":
            return Apache(self.data)

        if self.source == "syslog":
            return SysLog(self.data)

        if self.source == "cef":
            return CEF(self.data)

        if self.source == "fortinet":
            return Fortinet(self.data)

        raise ValueError(f"Unsupported Parser source : {self.source}")