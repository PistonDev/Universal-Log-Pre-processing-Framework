from dataclasses import dataclass

@dataclass
class ApacheEvent:
    raw:        str
    timestamp:  str | None = None
    level:      str | None = None
    message:    str | None = None

@dataclass
class SysLogEvent:
    raw:        str
    timestamp:  str | None = None
    host:       str | None = None
    component:  str | None = None
    pid:        int | None = None
    message:    str | None = None

@dataclass
class CEFEvent:
    raw:            str
    version:        int | None = None
    vendor:         str | None = None
    product:        str | None = None
    device_version: str | None = None
    signature_id:   str | None = None
    name:           str | None = None
    severity:       str | None = None
    extension:      str | None = None

@dataclass
class FortinetEvent:
    raw:        str
    fields:     dict
    date:       str | None = None
    time:       str | None = None
    devname:    str | None = None
    devid:      str | None = None
    logid:      str | None = None
    type:       str | None = None
    subtype:    str | None = None
    level:      str | None = None

@dataclass
class UniversalEvent:
    raw:                str
    source_type:        str
    timestamp:          str | None = None
    vendor:             str | None = None
    product:            str | None = None
    host:               str | None = None
    component:          str | None = None
    pid:                int | None = None
    event_category:     str | None = None
    event_type:         str | None = None
    action:             str | None = None
    severity:           str | None = None
    source_ip:          str | None = None
    source_port:        int | None = None
    destination_ip:     str | None = None
    destination_port:   int | None = None
    protocol:           str | None = None
    username:           str | None = None