# NATS Auth Callout Demo in Python 

This repository contains a simple demo of how to implement an [Auth Callout](https://docs.nats.io/running-a-nats-service/configuration/securing_nats/auth_callout) mechanism in NATS using Python.

Although [FastStream](https://faststream.ag2.ai/latest/) framework is used here, the core logic (`nats_callout/` directory) can be used with any NATS client library.

## What is Auth Callout?

Auth callout is a mechanism in NATS that delegates authentication and authorization to an external service, instead of relying only on static configuration. This allows you to integrate existing identity and access systems like databases, OAuth providers, LDAP, or even simple local checks.

It’s especially valuable in dynamic environments (e.g., browser WebSocket clients) where you need to grant fine-grained and time-sensitive permissions to specific subjects, streams, or key-value stores, rather than relying on preconfigured user definitions.

### How it works:

1. A client connects to the NATS server using basic credentials (e.g., token, password).
2. The NATS server issues an authentication request by publishing a message on the system subject: `$SYS.REQ.USER.AUTH`
3. An external **auth consumer** subscribes to this subject, receives the request, and decides if the client is allowed.
4. The consumer replies with an authorization response, including permissions and limitations that will be enforced for that client session.

![](https://docs.nats.io/~gitbook/image?url=https%3A%2F%2F1487470910-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F-LqMYcZML1bsXrN3Ezg0%252Fuploads%252FZqnH9925NhQ1StzwPi5R%252Fauth-callout-light.png%3Falt%3Dmedia%26token%3D77e72613-ab63-483e-93e3-dfd4a865fb5e&width=768&dpr=4&quality=100&sign=bf2c8a00&sv=2)

The **auth consumer** is the thing that we implemented in this demo

An instruction of how to set up NATS server with auth callout can be found in the [NATS documentation](https://docs.nats.io/running-a-nats-service/configuration/securing_nats/auth_callout) or in [this video](https://youtu.be/VvGxrT-jv64).


## How to use
Just vendor the `nats_callout/` directory into your project (maybe later we distribute it as a package) and use `nats_callout.callout` decorator.
The decorated function should receive a `nats_callout.AuthRequestData` object and return a `nats_callout.UserData` object or raise `nats_callout.AuthError`.
Basically, it should be compatible with type `Callable[[AuthRequestData, ...], Awaitable[UserData]]`.

```python
from nats_callout import callout, AuthRequestData, UserData, PubSubPermissions, AuthError

NKEY_SEED = "SU..."

@callout(NKEY_SEED, account="DEMO")
async def check_auth(
    auth_request_data: AuthRequestData,
    db: DbContext,
) -> UserData:
    connect_opts = auth_request_data.connect_opts

    # any checks here
    token = connect_opts.auth_token
    if not token:
        raise AuthError("no token provided")
    
    user = await db.get_user_by_token(token)
    
    if not user:
        raise AuthError("invalid token")
    
    user_data = UserData(
        pub=PubSubPermissions(allow=["foo"], deny=[]),
        sub=PubSubPermissions(allow=["bar"], deny=[]),
        version=auth_request_data.version,
        tags=auth_request_data.tags,
    )
    return user_data
```

Now, basically, `check_auth` function is a function that receives input JWT token (auth request) from server as the first argument
and returns the output JWT token (auth response) and you can use it with whatever NATS client lib.