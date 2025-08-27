from datetime import datetime
from functools import wraps
from typing import Callable, Awaitable

import nkeys
from adaptix import Retort

from nats_callout.claims.authorization_request import AuthRequestClaims, AuthRequestData
from nats_callout.claims.authorization_response import AuthResponseClaims, AuthResponseData
from nats_callout.claims.user import UserData, UserClaims
from nats_callout.jwt_tools import decode_auth_request, encode

type InputFunc = Callable[[AuthRequestData, ...], Awaitable[UserData]]
type OutputFunc = Callable[[str | bytes, ...], Awaitable[str]]
retort = Retort()


def callout(
    nkey_seed: str | bytes,
    account: str = "$G",  # default account
    exp: int = 3600,
    nbf: int | None = None,
) -> Callable[[InputFunc], OutputFunc]:
    nkey_seed = nkey_seed if isinstance(nkey_seed, bytes) else nkey_seed.encode()
    kp = nkeys.from_seed(nkey_seed)
    public_key_str = kp.public_key.decode()

    def _decorator(func: InputFunc) -> OutputFunc:
        @wraps(func)
        async def _inner(body: str | bytes, *args, **kwargs) -> str:
            if isinstance(body, bytes):
                body = body.decode()
            auth_request = decode_auth_request(body, retort)
            auth_request_data = auth_request.nats
            now = datetime.now()
            iat = int(now.timestamp())
            try:
                user_data = await func(auth_request_data, *args, **kwargs)
            except AuthError as e:
                auth_response = AuthResponseClaims(
                    iss=public_key_str,
                    sub=auth_request.nats.user_nkey,
                    aud=auth_request.nats.server_id.id,
                    iat=iat,
                    nats=AuthResponseData(
                        version=auth_request.nats.version,
                        tags=auth_request.nats.tags,
                        error=e.message,
                    ),
                )
                auth_response_jwt = encode(retort.dump(auth_response), kp)
                return auth_response_jwt

            user_claims = UserClaims(
                aud=account,
                sub=auth_request_data.user_nkey,
                iss=public_key_str,
                iat=iat,
                exp=iat + exp,
                nbf=iat + nbf if nbf else None,
                name=auth_request_data.user_nkey,
                nats=user_data,
            )
            user_jwt = encode(
                retort.dump(user_claims),
                kp,
            )

            auth_response = AuthResponseClaims(
                iss=public_key_str,
                sub=auth_request.nats.user_nkey,
                aud=auth_request.nats.server_id.id,
                iat=iat,
                nats=AuthResponseData(
                    jwt=user_jwt,
                    type="authorization_response",
                    version=auth_request.nats.version,
                    tags=auth_request.nats.tags,
                )
            )
            auth_response_jwt = encode(retort.dump(auth_response), kp)
            return auth_response_jwt
        return _inner
    return _decorator


class AuthError(Exception):
    def __init__(self, message: str):
        self.message = message
