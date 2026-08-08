"""CSRF state and PKCE, without server-side storage.

An OAuth callback arrives as a bare GET from the provider, so the server has
to prove it started the login itself. The usual fix is a random value stored
server-side and echoed through the provider. This module does the same job
with a signed cookie instead, so nothing needs a session store, a database, or
sticky routing.

Two things are worth knowing about the design:

* The cookie is **signed, not encrypted**. Its contents (a random string, an
  expiry, the provider name, and whatever ``return_to`` was passed) are
  readable by anyone holding the cookie, and unforgeable without the secret.
  Nothing secret is put in it — see below.

* The PKCE verifier is **derived, never stored**. Writing it into the cookie
  would put a secret somewhere readable; keeping it server-side would
  reintroduce the state store this module exists to avoid. Instead it is
  recomputed at exchange time as ``HMAC(secret, state)``. The provider only
  ever sees its SHA-256 challenge, and an attacker who intercepts the
  authorization code still cannot redeem it without the application secret.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass

from sillo.helpers.crypto import BadSignature, sign_value, unsign_value

from .errors import StateExpired, StateMismatch

__all__ = [
    "StatePayload",
    "derive_verifier",
    "issue_state",
    "pkce_challenge",
    "verify_state",
]

#: Domain separator for the verifier HMAC. Prefixing the input keeps the
#: derived verifier from colliding with any other value the same application
#: secret is used to sign elsewhere in sillo.
_PKCE_INFO = "sillo-oauth/pkce/v1:"

#: Bytes of entropy in the state value. 32 bytes is well past the point where
#: guessing is the weak link.
_STATE_BYTES = 32


def _b64(raw: bytes) -> str:
    """Base64url-encode without padding.

    Args:
        raw: Bytes to encode.

    Returns:
        The unpadded base64url text. Both PKCE fields are defined this way, so
        the padding has to go.
    """
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


@dataclass(frozen=True)
class StatePayload:
    """What a verified state cookie was carrying.

    Attributes:
        state: The random value the provider echoed back.
        provider: Name of the provider the redirect was issued for.
        expires_at: Unix timestamp after which the value stops being accepted.
        return_to: Application-supplied value carried through the round trip.
    """

    state: str
    provider: str
    expires_at: float
    return_to: str | None = None


def issue_state(
    provider: str,
    secret: str,
    *,
    ttl: int = 600,
    return_to: str | None = None,
    now: float | None = None,
) -> tuple[str, str]:
    """Mint a fresh state value and the signed cookie that vouches for it.

    Args:
        provider: Provider name, bound into the payload so a cookie minted for
            one provider cannot satisfy another's callback.
        secret: Application signing secret.
        ttl: Seconds the value stays valid. The default of ten minutes is long
            enough to read a consent screen and short enough that a leaked
            cookie is not useful for long.
        return_to: Opaque value to carry through the provider round trip,
            typically the page the person was heading for.
        now: Current time, injectable for tests.

    Returns:
        ``(state, cookie_value)`` — the first goes to the provider as the
        ``state`` query parameter, the second to the browser as a cookie.
    """
    state = _b64(secrets.token_bytes(_STATE_BYTES))
    issued = time.time() if now is None else now
    payload = json.dumps(
        {
            "s": state,
            "p": provider,
            "e": issued + ttl,
            "r": return_to,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    return state, sign_value(payload, secret)


def verify_state(
    cookie_value: str | None,
    state_param: str | None,
    provider: str,
    secret: str,
    *,
    now: float | None = None,
) -> StatePayload:
    """Check that a callback belongs to a redirect this server issued.

    Every failure mode except expiry collapses to
    :class:`~sillo_oauth.errors.StateMismatch`, deliberately: a missing
    cookie, a forged one, and one minted for a different provider are all
    "this callback is not ours", and distinguishing them in an error code
    would only tell an attacker which half of the check they cleared.

    Args:
        cookie_value: The signed value that came back with the callback, or
            ``None`` if the browser sent no cookie.
        state_param: The ``state`` query parameter the provider echoed.
        provider: Name of the provider whose callback this claims to be.
        secret: Application signing secret, the same one passed to
            :func:`issue_state`.
        now: Current time, injectable for tests.

    Returns:
        The verified payload.

    Raises:
        StateMismatch: The two values do not agree, or the cookie is absent,
            malformed, unsigned, or for another provider.
        StateExpired: The cookie is genuine but past its expiry.
    """
    if not cookie_value or not state_param:
        raise StateMismatch(
            "Missing OAuth state cookie or state parameter", provider=provider
        )

    try:
        payload = json.loads(unsign_value(cookie_value, secret))
    except (BadSignature, ValueError, TypeError) as exc:
        raise StateMismatch(
            "OAuth state cookie is not valid", provider=provider
        ) from exc

    if not isinstance(payload, dict):
        raise StateMismatch("OAuth state cookie is not valid", provider=provider)

    stored = payload.get("s")
    # Compared in constant time even though a forged value cannot be signed
    # anyway — the cost is nil and it keeps the comparison from becoming a
    # timing oracle if the signing step is ever relaxed.
    if not isinstance(stored, str) or not hmac.compare_digest(stored, state_param):
        raise StateMismatch("OAuth state does not match", provider=provider)

    if payload.get("p") != provider:
        raise StateMismatch(
            "OAuth state was issued for a different provider", provider=provider
        )

    expires_at = payload.get("e")
    if not isinstance(expires_at, (int, float)):
        raise StateMismatch("OAuth state cookie is not valid", provider=provider)

    current = time.time() if now is None else now
    if current > expires_at:
        raise StateExpired("OAuth state has expired", provider=provider)

    return_to = payload.get("r")
    return StatePayload(
        state=stored,
        provider=provider,
        expires_at=float(expires_at),
        return_to=return_to if isinstance(return_to, str) else None,
    )


def derive_verifier(state: str, secret: str) -> str:
    """Recompute the PKCE verifier bound to a state value.

    Deterministic, so the redirect step and the exchange step arrive at the
    same verifier without either storing it. Since ``state`` is unguessable
    and ``secret`` never leaves the server, so is the result.

    Args:
        state: The state value the verifier is bound to.
        secret: Application signing secret.

    Returns:
        A 43-character verifier, which is what base64url of a SHA-256 digest
        comes to and sits at the bottom of the 43–128 range RFC 7636 allows.
    """
    digest = hmac.new(
        secret.encode(), (_PKCE_INFO + state).encode(), hashlib.sha256
    ).digest()
    return _b64(digest)


def pkce_challenge(verifier: str) -> str:
    """The ``S256`` challenge for a verifier.

    Args:
        verifier: The value from :func:`derive_verifier`.

    Returns:
        Base64url of the verifier's SHA-256 digest, unpadded.
    """
    return _b64(hashlib.sha256(verifier.encode("ascii")).digest())
