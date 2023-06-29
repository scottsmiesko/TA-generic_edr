from typing import List, Literal, Optional
from datetime import datetime, timedelta
from pydantic import BaseModel, Field


class HashableBaseModel(BaseModel):
    def __hash__(self):  # make hashable BaseModel subclass
        return hash((type(self),) + tuple(self.__dict__.values()))


class BaseImmutableDataclass(HashableBaseModel):
    pass


class BaseMutableDataclass(HashableBaseModel):
    pass


class ProxyConfig(BaseMutableDataclass):
    http_proxy: str = None
    https_proxy: str = None


class Credentials(BaseMutableDataclass):
    username: str
    password: str


class Query(BaseMutableDataclass):
    skip: Optional[int] = 0
    take: Optional[int] = 50
    sort: Optional[str] = "insertion_date"
    order: Optional[str] = "desc"
    since: Optional[datetime] = (datetime.utcnow() - timedelta(minutes=15))
    since_cmp: Optional[str] = "gte"
    before: Optional[datetime] = datetime.utcnow()
    before_cmp: Optional[str] = "lte"


class Alert(BaseImmutableDataclass):
    """
    This should always map 1:1 with the response type Alert from Generic EDR
    """
    action: Literal["allowed", "blocked", "unknown"]
    alert_id: int = None
    alert_link: str = None
    cmdline: Optional[str] = None
    dest_host: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    parent_process: Optional[str] = None
    process: Optional[str] = None
    signature: Optional[str] = None
    src_host: Optional[str] = None
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    url: Optional[str] = None


class Alerts(BaseMutableDataclass):
    entries: List[Alert] = Field(default_factory=list)
    count: int = 0
