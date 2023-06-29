from dataclasses import dataclass
from typing import Self

@dataclass(frozen=True)
class Alert:
    action:     str
    alert_id:   int
    alert_link: str
    cmdline:    str
    dest_host:  str
    dest_ip:    str
    dest_port:  int
    process:    str
    signature:  str
    src_host:   str
    src_ip:     str
    src_port:   int
    url:        str


@dataclass(frozen=True)
class Alerts:
    alerts: list[Alert]
    count: int
