from dataclasses import dataclass

@dataclass
class ApacheEvent:
    timestamp:  str
    level:      str
    message:    str
    raw:        str

@dataclass
class SysLogEvent:
    timestamp:  str
    host:       str
    component:  str
    pid:        int | None
    message:    str
    raw:        str

@dataclass
class CEFEvent:
    version:        int
    vendor:         str
    product:        str
    device_version: str
    signature_id:   str
    name:           str
    severity:       str
    extension:      str
    raw:            str

@dataclass
class FortinetEvent:
    date:       str | None
    time:       str | None
    devname:    str | None
    devid:      str | None
    logid:      str | None
    type:       str | None
    subtype:    str | None
    level:      str | None
    fields:     dict
    raw:        str

@dataclass
class UniversalEvent:
    timestamp:          str | None = None
    source_type:        str | None = None
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
    raw:                str | None = None