import asyncio
from faststream.nats import NatsBroker
from faststream.security import SASLPlaintext


async def main():
    valid_creds = SASLPlaintext(username="demo", password="demo")
    broker = NatsBroker(security=valid_creds)
    await broker.connect() # successfully connects

    invalid_creds = SASLPlaintext(username="demo", password="wrong")
    broker = NatsBroker(security=invalid_creds)
    await broker.connect() # raises an authentication error


if __name__ == "__main__":
    asyncio.run(main())
