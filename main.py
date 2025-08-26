import asyncio
import datetime

from adaptix import Retort, name_mapping
from faststream.annotations import FastStream
from faststream.nats import NatsBroker
import nkeys
from faststream.security import SASLPlaintext

from nats_jwt.claims.authorization_request import AuthorizationRequestClaims
from nats_jwt.claims.authorization_response import AuthorizationResponseClaims, AuthorizationResponseData
from nats_jwt.claims.user import UserClaims, UserData, PubSubPermissions
from nats_jwt.tools import encode, decode_auth_request

broker = NatsBroker(
    security=SASLPlaintext(username="auth", password="auth"),
)
app = FastStream(broker=broker)
retort = Retort(
    recipe=[
        name_mapping(omit_default=False)
    ]
)
NKEY_SEED = "SAAEJZZ3B3Y5655RH7O6SQJCVZG6WPYFMJWYOI2CRMSL5W4YQZ2XSWFCUQ".encode()

@broker.subscriber("$SYS.REQ.USER.AUTH")
async def auth_request_handler(
    body: str,
) -> str:
    kp = nkeys.from_seed(NKEY_SEED)
    public_key = kp.public_key.decode()
    payload = decode_auth_request(body)
    auth_request = retort.load(payload, AuthorizationRequestClaims)
    connect_opts = auth_request.nats.connect_opts

    # any checks here
    if connect_opts.user != "demo" or connect_opts.pass_ != "demo":
        auth_response = AuthorizationResponseClaims(
            iss=public_key,
            sub=auth_request.nats.user_nkey,
            aud=auth_request.nats.server_id.id,
            iat=int(datetime.datetime.now().timestamp()),
            exp=int((datetime.datetime.now() + datetime.timedelta(minutes=5)).timestamp()),
            nats=AuthorizationResponseData(
                version=auth_request.nats.version,
                tags=auth_request.nats.tags,
                error="invalid credentials",
            )
        )
        auth_jwt = encode(retort.dump(auth_response), kp)
        return auth_jwt

    user_claims = UserClaims(
        aud="DEMO",
        sub=auth_request.nats.user_nkey,
        iss=public_key,
        iat=int(datetime.datetime.now().timestamp()),
        name="demo",
        exp=int((datetime.datetime.now() + datetime.timedelta(hours=1)).timestamp()),
        nats=UserData(
            allowed_connection_types=["STANDARD"],
            pub=PubSubPermissions(allow=["foo"], deny=[]),
            sub=PubSubPermissions(allow=["bar"], deny=[]),
            type="user",
            version=auth_request.nats.version,
            tags=auth_request.nats.tags,
        )
    )

    user_jwt = encode(
        retort.dump(user_claims),
        kp,
    )

    auth_response = AuthorizationResponseClaims(
        iss=public_key,
        sub=auth_request.nats.user_nkey,
        aud=auth_request.nats.server_id.id,
        iat=int(datetime.datetime.now().timestamp()),
        exp=int((datetime.datetime.now() + datetime.timedelta(hours=1)).timestamp()),
        nats=AuthorizationResponseData(
            jwt=user_jwt,
            type="authorization_response",
            version=auth_request.nats.version,
            tags=auth_request.nats.tags,
        )
    )
    auth_jwt = encode(retort.dump(auth_response), kp)
    return auth_jwt

async def main():
    await app.run()


if __name__ == "__main__":
    asyncio.run(main())
