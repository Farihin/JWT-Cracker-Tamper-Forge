"""
jwt_utils.py - Core JWT (JWS) parsing, encoding and signing helpers.

Implements just enough of RFC 7515 to support the cracker and tamper
modules without an external JWT library, so the whole signing/verify
path is auditable from this one file (useful for your technical
report's "attack lifecycle mapping" section).
"""

import base64
import hashlib
import hmac
import json
from typing import Optional, Tuple

SUPPORTED_HMAC_ALGS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


def b64url_decode(segment: str) -> bytes:
    """Decode a base64url segment, restoring any stripped '=' padding."""
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def b64url_encode(data: bytes) -> str:
    """Encode bytes as base64url with padding stripped, per RFC 7515."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def split_token(token: str) -> Tuple[str, str, str]:
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError(
            f"Expected a 3-part JWT (header.payload.signature), got {len(parts)} part(s)."
        )
    return parts[0], parts[1], parts[2]


def decode_token(token: str) -> dict:
    """Decode header + payload (NO signature verification) for inspection."""
    header_b64, payload_b64, signature_b64 = split_token(token)
    header = json.loads(b64url_decode(header_b64))
    payload = json.loads(b64url_decode(payload_b64))
    return {
        "header": header,
        "payload": payload,
        "signature_b64": signature_b64,
        "header_b64": header_b64,
        "payload_b64": payload_b64,
    }


def sign_hs(header_b64: str, payload_b64: str, secret: bytes, alg: str) -> str:
    if alg not in SUPPORTED_HMAC_ALGS:
        raise ValueError(f"Unsupported HMAC alg: {alg}")
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    digestmod = SUPPORTED_HMAC_ALGS[alg]
    sig = hmac.new(secret, signing_input, digestmod).digest()
    return b64url_encode(sig)


def verify_hs(token: str, secret: bytes) -> bool:
    """Check whether `secret` reproduces the token's existing signature."""
    header_b64, payload_b64, signature_b64 = split_token(token)
    header = json.loads(b64url_decode(header_b64))
    alg = header.get("alg", "").upper()
    if alg not in SUPPORTED_HMAC_ALGS:
        return False
    expected = sign_hs(header_b64, payload_b64, secret, alg)
    return hmac.compare_digest(expected, signature_b64)  # constant-time compare


def build_token(header: dict, payload: dict, secret: Optional[bytes], alg: str) -> str:
    """Rebuild a token from (possibly tampered) header/payload dicts."""
    header = dict(header)
    header["alg"] = alg
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())

    if alg.upper() == "NONE":
        return f"{header_b64}.{payload_b64}."  # empty signature: the "alg:none" bug class

    if alg.upper() not in SUPPORTED_HMAC_ALGS:
        raise ValueError(f"build_token only supports HMAC algs or 'none', got {alg}")
    if secret is None:
        raise ValueError("A secret is required to sign with an HMAC alg.")
    sig_b64 = sign_hs(header_b64, payload_b64, secret, alg.upper())
    return f"{header_b64}.{payload_b64}.{sig_b64}"
