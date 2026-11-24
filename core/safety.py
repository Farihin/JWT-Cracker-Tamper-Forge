"""
safety.py - Startup legal disclaimer, authorization-scope gate, and a
cooperative kill switch.

These three controls are what the assignment brief calls "enforce
authorization scope, safe defaults, a startup legal disclaimer ... and
a clean kill switch." They are deliberately not bypassable with a
single silent flag: --i-accept-responsibility still prints and logs
the disclaimer, and --force-unsafe-scope still prints a loud warning
naming the target, rather than failing silently.
"""

import ipaddress
import signal
from dataclasses import dataclass, field
from typing import List

DISCLAIMER = """
==============================================================================
 JWT-Cracker & Tamper Forge -- AUTHORIZED SECURITY TESTING TOOL ONLY
==============================================================================
This tool inspects, dictionary-attacks (wordlist only, no live brute force
against a server) and tampers with JSON Web Tokens for the SOLE purpose of
authorized security testing and academic coursework (IKB31603 - Ethical
Hacking).

Under Malaysia's Computer Crimes Act 1997 (and equivalent legislation
elsewhere), accessing, modifying, or attempting to bypass authentication on
a system or account you do not own or do not hold written permission to
test is a criminal offence, regardless of intent.

By continuing you confirm, on the record, that:
  1. You own the system/application that issued this token, OR you hold
     written authorization (a signed Rules of Engagement) to test it.
  2. You will only test tokens/targets within the agreed scope.
  3. All output stays on this machine -- this tool makes no network calls
     and will not transmit tokens, secrets, or results anywhere.

Scope is restricted by default to localhost / private / test ranges.
==============================================================================
"""

CONFIRMATION_PHRASE = "I AM AUTHORIZED TO TEST THIS TOKEN"

DEFAULT_ALLOWED_HOST_PATTERNS = (
    "localhost",
    "127.0.0.1",
    "::1",
    ".test",
    ".local",
    "example.com",  # RFC 2606: reserved for documentation/testing
)


class AuthorizationError(RuntimeError):
    pass


def show_disclaimer_and_confirm(auto_accept: bool) -> None:
    print(DISCLAIMER)
    if auto_accept:
        print("[safety] --i-accept-responsibility passed; treating as confirmed.\n")
        return
    typed = input(f'Type exactly "{CONFIRMATION_PHRASE}" to continue: ')
    if typed.strip() != CONFIRMATION_PHRASE:
        raise AuthorizationError("Confirmation phrase not matched. Exiting.")


def _host_in_allowlist(host: str, extra_allowed: List[str]) -> bool:
    host = host.lower().strip()
    patterns = list(DEFAULT_ALLOWED_HOST_PATTERNS) + [p.lower() for p in extra_allowed]
    if any(host == p or host.endswith(p) for p in patterns):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False


def enforce_scope(claimed_target: str, extra_allowed: List[str], force_unsafe: bool) -> None:
    """
    `claimed_target` is whatever host/issuer the user says this token
    belongs to (e.g. the JWT's `iss` claim, or a --target flag). Refuses
    to proceed unless it's a safe default range, in the user-supplied
    allowlist, or --force-unsafe-scope was explicitly set (which still
    gets logged loudly rather than silently passing).
    """
    if _host_in_allowlist(claimed_target, extra_allowed):
        return
    if force_unsafe:
        print(
            f"[safety][WARNING] '{claimed_target}' is outside the safe default "
            f"scope and --force-unsafe-scope was set. Proceeding because you "
            f"asserted explicit authorization -- that assertion belongs on your "
            f"signed Rules of Engagement, not on this tool."
        )
        return
    raise AuthorizationError(
        f"Target '{claimed_target}' is not in the safe-default scope "
        f"(localhost/private/test ranges) and not in --allow-host. "
        f"Add it explicitly with --allow-host, or re-run with "
        f"--force-unsafe-scope only if you hold documented authorization."
    )


@dataclass
class KillSwitch:
    """Cooperative stop flag checked inside long-running loops (the
    cracker's candidate loop), backed by a real SIGINT/SIGTERM handler
    so Ctrl+C always exits cleanly instead of leaving work half-done."""

    triggered: bool = field(default=False)

    def arm(self) -> None:
        signal.signal(signal.SIGINT, self._handle)
        signal.signal(signal.SIGTERM, self._handle)

    def _handle(self, signum, frame):
        print(f"\n[killswitch] Signal {signum} received -- stopping at next safe point.")
        self.triggered = True
