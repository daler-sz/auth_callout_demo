from dataclasses import dataclass, field
from typing import List, Optional, Literal

from nats_jwt.claims.base import BaseClaims, BaseNats


@dataclass(kw_only=True)
class ServerID:
    name: str
    host: str
    id: str
    version: str | None = None
    cluster: str | None = None
    tags: list[str] | None = field(default_factory=list)
    xkey: list[str] | None = None


@dataclass(kw_only=True)
class ClientInfo:
    host: str | None = None
    id: int | None = None
    user: str | None = None
    name: str | None = None
    tags: list[str] | None = field(default_factory=list)
    name_tag: str | None = None
    kind: str | None = None
    type: str | None = None
    mqtt_id: str | None = None
    nonce: str | None = None


@dataclass(kw_only=True)
class ConnectOpts:
    protocol: int
    jwt: str | None = None
    nkey: str | None = None
    sig: str | None = None
    auth_token: str | None = None
    user: str | None = None
    pass_: str | None = None
    name: str | None = None
    lang: str | None = None
    version: str | None = None


@dataclass(kw_only=True)
class ClientTLS:
    version: str | None = None
    cipher: str | None = None
    certs: list[str] | None = field(default_factory=list)
    verified_chains: list[list[str]] | None = field(default_factory=list)


@dataclass(kw_only=True)
class AuthorizationRequestData(BaseNats):
    type: Literal["authorization_request"] = "authorization_request"
    server_id: ServerID
    user_nkey: str
    client_info: ClientInfo
    connect_opts: ConnectOpts
    client_tls: ClientTLS | None = None
    request_nonce: str | None = None


@dataclass(kw_only=True)
class AuthorizationRequestClaims(BaseClaims[AuthorizationRequestData]):
    pass
