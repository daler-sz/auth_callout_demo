import hashlib
import base64
import json

import jwt
from nkeys import KeyPair


def encode(data: dict, kp: KeyPair):
    header = {
        "alg": "ed25519-nkey",
        "typ": "JWT"
    }

    if not data.get("jti"):
        data['jti'] = ""
        jti = _calculate_jti(json.dumps(data))
        data['jti'] = jti

    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode()
    payload_b64 = base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b'=').decode()
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = kp.sign(signing_input)
    assert kp.verify(signing_input, signature)
    signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()
    jwt_token = f"{header_b64}.{payload_b64}.{signature_b64}"
    return jwt_token


def decode_auth_request(token: str) -> dict:
    return jwt.decode(
        token,
        verify=False,
        algorithms=["ed25519-nkey"],
        options={"verify_signature": False}
    )


def _calculate_jti(claim: str) -> str:
    sha256_hash = hashlib.sha256(claim.encode()).digest()

    encoded = base64.b32encode(sha256_hash).decode()
    return encoded.rstrip("=")
