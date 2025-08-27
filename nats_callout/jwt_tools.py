import binascii
import hashlib
import base64
import json

import jwt
from adaptix import Retort
from nacl.signing import VerifyKey
from nkeys import KeyPair, ErrInvalidSeed, PREFIX_BYTE_SERVER

from nats_callout.claims import AuthRequestClaims

jwt_header = {
    "alg": "ed25519-nkey",
    "typ": "JWT"
}

def encode(data: dict, kp: KeyPair):
    if not data.get("jti"):
        data['jti'] = ""
        jti = _calculate_jti(json.dumps(data))
        data['jti'] = jti

    header_b64 = _b64_encode_dict(jwt_header)
    payload_b64 = _b64_encode_dict(data)
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = kp.sign(signing_input)
    assert kp.verify(signing_input, signature)
    signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()
    jwt_token = f"{header_b64}.{payload_b64}.{signature_b64}"
    return jwt_token


def decode_auth_request(token: str, retort: Retort) -> AuthRequestClaims:
    token_data = jwt.decode_complete(token, options={"verify_signature": False})  # verify claims
    header_json = token_data["header"]
    if header_json != jwt_header:
        raise ValueError("Invalid JWT header")
    payload_json = token_data["payload"]

    # verify signature
    header_b64, payload_b64, signature_b64 = token.split('.')
    data = retort.load(payload_json, AuthRequestClaims)
    iss = data.iss
    _, raw_public = _decode_server_public_key(iss.encode())
    key = VerifyKey(raw_public)
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = base64.urlsafe_b64decode(signature_b64 + '==')
    key.verify(signing_input, signature)
    return data


def _b64_encode_dict(data: dict) -> str:
    json_str = json.dumps(data)
    b64_bytes = base64.urlsafe_b64encode(json_str.encode())
    return b64_bytes.rstrip(b'=').decode()


def _b64_decode_dict(b64_str: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(b64_str + '==').decode())


def _calculate_jti(claim: str) -> str:
    sha256_hash = hashlib.sha256(claim.encode()).digest()

    encoded = base64.b32encode(sha256_hash).decode()
    return encoded.rstrip("=")


def _decode_server_public_key(src):
    # Add missing padding if required.
    padding = bytearray()
    padding += b'=' * (-len(src) % 8)

    try:
        base32_decoded = base64.b32decode(src + padding)
        raw = base32_decoded[:(len(base32_decoded) - 2)]
    except binascii.Error:
        raise ErrInvalidSeed()

    if len(raw) < 32:
        raise ErrInvalidSeed()

    # 248 = 11111000
    b1 = raw[0] & 248

    # 7 = 00000111
    b2 = (raw[0] & 7) << 5 | ((raw[1] & 248) >> 3)

    if b1 != PREFIX_BYTE_SERVER:
        raise ErrInvalidSeed()

    prefix = b2
    result = raw[1:(len(raw))]
    return prefix, result
