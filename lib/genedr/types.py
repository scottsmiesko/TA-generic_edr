import json
from typing import List, Literal, Optional
from dataclasses import dataclass, field, asdict
from dataclass_wizard import JSONWizard
from datetime import datetime, timedelta


@dataclass(frozen=True, kw_only=True)
class BaseImmutableDataclass:
    def json(self):
        return json.dumps(asdict(self))


@dataclass(kw_only=True)
class BaseMutableDataclass:
    def json(self):
        return json.dumps(asdict(self))


@dataclass(kw_only=True)
class ProxyConfig(BaseMutableDataclass):
    http_proxy: str = None
    https_proxy: str = None


@dataclass(kw_only=True)
class Credentials(BaseMutableDataclass):
    username: str
    password: str


@dataclass(kw_only=True)
class Query(BaseMutableDataclass):
    skip: int = 0
    take: int = 50
    sort: str = "insertion_date"
    order: str = "desc"
    since: datetime = (datetime.utcnow() - timedelta(minutes=15))
    since_cmp: str = "gte"
    before: datetime = datetime.utcnow()
    before_cmp: str = "lte"


@dataclass(frozen=True, kw_only=True)
class Alert(BaseImmutableDataclass, JSONWizard):
    """
    This should always map 1:1 with the response type Alert from Generic EDR
    """
    action: Literal["allowed", "blocked", "unknown"]
    alert_id: int
    alert_link: str
    cmdline: str
    dest_host: str
    dest_ip: str
    dest_port: int
    process: str
    signature: str
    src_host: str
    src_ip: str
    src_port: int
    url: Optional[str]


@dataclass(frozen=True)
class Alerts:
    entries: List[Alert] = field(default_factory=list)
    count: int = 0
