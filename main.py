#!/usr/bin/env python3
"""
JWT-Cracker & Tamper Forge
IKB31603 Ethical Hacking -- Category 1: Web Application Attack
(JSON Web Token Auditor)

Usage:
  python main.py inspect --token <jwt>
  python main.py crack   --token <jwt> --wordlist wordlists/common_jwt_secrets.txt
  python main.py tamper  --token <jwt> --none-alg
  python main.py tamper  --token <jwt> --set role=admin --secret mysecret
  python main.py tamper  --token <jwt> --rs-to-hs-confusion --public-key pub.pem

Every subcommand runs the startup disclaimer + scope check first.
Pass --target to tell the tool which host/issuer this token belongs to
(defaults to "localhost"); anything outside the safe-default ranges
needs --allow-host or an explicit --force-unsafe-scope.
"""

import argparse
import sys

from core import cracker, tamper
from core.safety import (
    AuthorizationError,
    KillSwitch,
    enforce_scope,
    show_disclaimer_and_confirm,
)


def parse_claim_updates(pairs):
    updates = {}
    for pair in pairs or []:
        if "=" not in pair:
            raise ValueError(f"--set expects key=value, got {pair!r}")
        key, value = pair.split("=", 1)
        # best-effort type coercion so --set active=true / id=0 behave sanely
        if value.lower() in ("true", "false"):
            value = value.lower() == "true"
        else:
            try:
                value = int(value)
            except ValueError:
                pass
        updates[key] = value
    return updates


def build_parser():
    parser = argparse.ArgumentParser(description="JWT-Cracker & Tamper Forge")
    parser.add_argument(
        "--i-accept-responsibility",
        action="store_true",
        help="Skip the interactive confirmation prompt (disclaimer is still printed).",
    )
    parser.add_argument(
        "--target",
        default="localhost",
        help="Host/issuer this token belongs to, for scope enforcement. Default: localhost",
    )
    parser.add_argument(
        "--allow-host",
        action="append",
        default=[],
        help="Additional host/suffix to treat as in-scope. Repeatable.",
    )
    parser.add_argument(
        "--force-unsafe-scope",
        action="store_true",
        help="Override scope checks. Only use with documented authorization.",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    p_inspect = sub.add_parser("inspect", help="Decode and print a token's header/payload.")
    p_inspect.add_argument("--token", required=True)

    p_crack = sub.add_parser("crack", help="Dictionary-attack an HS256/384/512 token's secret.")
    p_crack.add_argument("--token", required=True)
    p_crack.add_argument("--wordlist", required=True)
    p_crack.add_argument(
        "--output",
        default=None,
        help="Optional local file to append the result to (never sent over the network).",
    )

    p_tamper = sub.add_parser("tamper", help="Build a tampered token for testing.")
    p_tamper.add_argument("--token", required=True)
    p_tamper.add_argument("--none-alg", action="store_true", help="Classic alg:none bypass test.")
    p_tamper.add_argument("--set", action="append", help="Claim to overwrite, e.g. role=admin. Repeatable.")
    p_tamper.add_argument("--secret", default=None, help="Secret to re-sign the tampered token with.")
    p_tamper.add_argument("--alg", default=None, help="Override signing alg (HS256/HS384/HS512).")
    p_tamper.add_argument(
        "--rs-to-hs-confusion",
        action="store_true",
        help="RS256->HS256 key-confusion test (needs --public-key).",
    )
    p_tamper.add_argument("--public-key", default=None, help="Path to the RSA public key PEM.")

    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)

    try:
        show_disclaimer_and_confirm(args.i_accept_responsibility)
        enforce_scope(args.target, args.allow_host, args.force_unsafe_scope)
    except AuthorizationError as exc:
        print(f"[!] {exc}")
        return 1

    kill_switch = KillSwitch()
    kill_switch.arm()

    if args.command == "inspect":
        print(tamper.dump_token(args.token))
        return 0

    if args.command == "crack":
        try:
            found = cracker.crack(args.token, args.wordlist, kill_switch)
        except ValueError as exc:
            print(f"[!] {exc}")
            return 1
        if found and args.output:
            with open(args.output, "a", encoding="utf-8") as fh:
                fh.write(f"token_prefix={args.token[:16]}... secret={found}\n")
            print(f"[+] Result appended locally to {args.output}")
        return 0 if found else 2

    if args.command == "tamper":
        if args.none_alg:
            print(tamper.alg_none_attack(args.token))
            return 0
        if args.rs_to_hs_confusion:
            if not args.public_key:
                print("[!] --rs-to-hs-confusion requires --public-key <path>")
                return 1
            with open(args.public_key, "r", encoding="utf-8") as fh:
                pub_pem = fh.read()
            print(tamper.alg_confusion_rs_to_hs(args.token, pub_pem))
            return 0
        updates = parse_claim_updates(args.set)
        if not updates:
            print("[!] Nothing to do -- pass --none-alg, --set key=value, or --rs-to-hs-confusion.")
            return 1
        print(tamper.tamper_claims(args.token, updates, args.secret, args.alg))
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
