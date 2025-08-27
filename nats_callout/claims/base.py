from dataclasses import dataclass, field
from typing import Literal


@dataclass(kw_only=True)
class BaseJwtClaims:
    aud: str | None = None
    exp: int | None = None
    jti: str | None = None
    iat: int | None = None
    iss: str | None = None
    name: str | None = None
    nbf: int | None = None
    sub: str | None = None


@dataclass(kw_only=True)
class BaseNats:
    type: Literal["user", "authorization_request", "authorization_response"]
    version: int = 2
    tags: list[str] = field(default_factory=list)


@dataclass(kw_only=True)
class BaseClaims[T](BaseJwtClaims):
    nats: T
