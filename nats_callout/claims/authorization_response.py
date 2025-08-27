from dataclasses import dataclass
from typing import Literal

from nats_callout.claims.base import BaseClaims, BaseNats


@dataclass(kw_only=True)
class AuthResponseData(BaseNats):
    type: Literal["authorization_response"] = "authorization_response"
    jwt: str | None = None
    error: str | None = None
    issuer_account: str | None = None


@dataclass(kw_only=True)
class AuthResponseClaims(BaseClaims[AuthResponseData]):
    pass
