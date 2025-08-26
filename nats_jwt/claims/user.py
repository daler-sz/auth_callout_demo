from dataclasses import dataclass, field

from typing_extensions import Literal

from nats_jwt.claims.base import BaseNats, BaseClaims


@dataclass(kw_only=True)
class PubSubPermissions:
    allow: list[str] | None = field(default_factory=list)
    deny: list[str] | None = field(default_factory=list)


@dataclass(kw_only=True)
class Resp:
    max: int
    ttl: int


@dataclass(kw_only=True)
class TimeRange:
    start: str | None = None
    end: str | None = None


@dataclass(kw_only=True)
class UserData(BaseNats):
    type: Literal["user"] = "user"
    pub: PubSubPermissions | None = None
    sub: PubSubPermissions | None = None
    resp: Resp | None = None
    src: list[str] | None = None
    times: list[TimeRange] | None = None
    times_location: str | None = None
    subs: int | None = None
    data: int | None = None
    payload: int | None = None
    bearer_token: bool | None = None
    allowed_connection_types: list[str] | None = None
    issuer_account: str | None = None


@dataclass(kw_only=True)
class UserClaims(BaseClaims[UserData]):
    pass
