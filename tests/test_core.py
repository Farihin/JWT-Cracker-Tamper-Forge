"""
Unit tests for jwt_utils, cracker and tamper.
Run with: pytest -q
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core import jwt_utils, tamper, cracker
from core.safety import KillSwitch


def make_token(payload, secret="secret", alg="HS256"):
    header = {"alg": alg, "typ": "JWT"}
    return jwt_utils.build_token(header, payload, secret.encode(), alg)


def test_roundtrip_decode():
    token = make_token({"sub": "1234", "role": "user"})
    decoded = jwt_utils.decode_token(token)
    assert decoded["payload"]["sub"] == "1234"
    assert decoded["header"]["alg"] == "HS256"


def test_verify_correct_secret():
    token = make_token({"sub": "1234"}, secret="hunter2")
    assert jwt_utils.verify_hs(token, b"hunter2") is True


def test_verify_wrong_secret():
    token = make_token({"sub": "1234"}, secret="hunter2")
    assert jwt_utils.verify_hs(token, b"wrongguess") is False


def test_cracker_finds_weak_secret(tmp_path):
    token = make_token({"sub": "1234"}, secret="password")
    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("notit\npassword\nalsoeverything\n")
    found = cracker.crack(token, str(wordlist), KillSwitch())
    assert found == "password"


def test_cracker_exhausts_without_match(tmp_path):
    token = make_token({"sub": "1234"}, secret="unguessable-xyz")
    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("secret\npassword\n123456\n")
    found = cracker.crack(token, str(wordlist), KillSwitch())
    assert found is None


def test_alg_none_strips_signature():
    token = make_token({"sub": "1234", "role": "user"})
    tampered = tamper.alg_none_attack(token)
    header_b64, payload_b64, sig_b64 = tampered.split(".")
    assert sig_b64 == ""
    header = json.loads(jwt_utils.b64url_decode(header_b64))
    assert header["alg"].lower() == "none"


def test_tamper_claims_resigns_correctly():
    token = make_token({"sub": "1234", "role": "user"}, secret="knownsecret")
    tampered = tamper.tamper_claims(token, {"role": "admin"}, secret="knownsecret")
    assert jwt_utils.verify_hs(tampered, b"knownsecret") is True
    decoded = jwt_utils.decode_token(tampered)
    assert decoded["payload"]["role"] == "admin"
