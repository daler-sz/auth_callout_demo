import asyncio
import datetime

from adaptix import Retort, name_mapping
from faststream.annotations import FastStream
from faststream.nats import NatsBroker
from faststream.security import SASLPlaintext

from nats_callout import callout, AuthRequestData, UserData, PubSubPermissions, AuthError

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
    return await check_auth(body)


@callout(NKEY_SEED, account="DEMO")
async def check_auth(
    auth_request_data: AuthRequestData,
) -> UserData:
    connect_opts = auth_request_data.connect_opts

    # any checks here
    if connect_opts.user != "demo" or connect_opts.pass_ != "demo":
        raise AuthError("invalid credentials")

    user_data = UserData(
        allowed_connection_types=["STANDARD"],
        pub=PubSubPermissions(allow=["foo"], deny=[]),
        sub=PubSubPermissions(allow=["bar"], deny=[]),
        version=auth_request_data.version,
        tags=auth_request_data.tags,
    )
    return user_data


@app.after_startup
async def after_startup():
    valid_creds = SASLPlaintext(username="demo", password="demo")
    broker = NatsBroker(security=valid_creds)
    await broker.connect()  # successfully connects

    invalid_creds = SASLPlaintext(username="demo", password="wrong")
    broker = NatsBroker(security=invalid_creds)
    await broker.connect() # raises an authentication error


async def main():
    await app.run()


if __name__ == "__main__":
    asyncio.run(main())
