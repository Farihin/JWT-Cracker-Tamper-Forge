"""
cracker.py - Dictionary attack against HMAC-signed (HS256/384/512) JWTs.

Tests whether a *known, locally supplied* wordlist of candidate secrets
reproduces the token's signature. It never contacts the network and
never attempts anything beyond the wordlist you provide -- widen
coverage by extending the wordlist, not by adding a network-facing
brute-force mode.
"""

import time
from typing import Iterator, Optional

from . import jwt_utils
from .safety import KillSwitch


def iter_candidates(wordlist_path: str) -> Iterator[bytes]:
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            candidate = line.rstrip("\n\r")
            if candidate:
                yield candidate.encode("utf-8")


def crack(
    token: str,
    wordlist_path: str,
    kill_switch: KillSwitch,
    progress_every: int = 2000,
) -> Optional[str]:
    """
    Try each candidate secret in `wordlist_path` against `token`.
    Returns the matching secret (str) or None if exhausted / interrupted.
    """
    decoded = jwt_utils.decode_token(token)
    alg = decoded["header"].get("alg", "").upper()
    if alg not in jwt_utils.SUPPORTED_HMAC_ALGS:
        raise ValueError(
            f"Token uses alg={alg!r}; the cracker only targets HMAC algs "
            f"{list(jwt_utils.SUPPORTED_HMAC_ALGS)}. RS/ES/PS tokens need the "
            f"private signing key, not a guessed shared secret -- this tool "
            f"will not attempt that."
        )

    start = time.time()
    tried = 0
    for candidate in iter_candidates(wordlist_path):
        if kill_switch.triggered:
            print("\n[killswitch] Stop requested -- halting crack attempt.")
            break
        tried += 1
        if jwt_utils.verify_hs(token, candidate):
            elapsed = time.time() - start
            print(f"\n[+] Secret found after {tried} attempt(s) in {elapsed:.2f}s")
            return candidate.decode("utf-8", errors="replace")
        if tried % progress_every == 0:
            print(f"    ... {tried} candidates tried", end="\r")

    print(f"\n[-] Exhausted {tried} candidate(s); no match in supplied wordlist.")
    return None
