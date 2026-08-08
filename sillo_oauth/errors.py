"""Failures the OAuth flow can end in.

Every error carries a stable ``code``. Handlers branch on the code rather than
the class, so a caller can pass it straight into a redirect
(``/login?error=state_mismatch``) without leaking exception names, and adding a
new subclass never breaks an existing ``except OAuthError``.
"""

from __future__ import annotations

__all__ = [
    "OAuthDenied",
    "OAuthError",
    "ProfileFetchFailed",
    "ProviderMisconfigured",
    "ProviderRejected",
    "StateExpired",
    "StateMismatch",
    "TokenExchangeFailed",
]


class OAuthError(Exception):
    """Base class for every failure raised by this package.

    Attributes:
        code: Stable, URL-safe identifier for the failure kind.
        provider: Name of the provider the flow was running against, when
            known. ``None`` for failures raised before a provider is involved.
        detail: Whatever the provider said, verbatim, for logging. Never
            assume it is safe to show a user — providers put arbitrary text
            here.
    """

    code = "oauth_error"

    def __init__(
        self,
        message: str | None = None,
        *,
        provider: str | None = None,
        detail: str | None = None,
    ) -> None:
        super().__init__(message or self.code)
        self.provider = provider
        self.detail = detail

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(code={self.code!r}, provider={self.provider!r}, "
            f"detail={self.detail!r})"
        )


class OAuthDenied(OAuthError):
    """The person declined consent at the provider.

    This is a normal outcome, not a fault: the provider redirects back with
    ``?error=access_denied``. Treat it as "go back to the login page", not as
    an error worth alerting on.
    """

    code = "denied"


class ProviderRejected(OAuthError):
    """The provider redirected back with an ``error`` other than a refusal.

    Covers everything from ``invalid_scope`` to a misconfigured redirect URI.
    The provider's own code is in :attr:`OAuthError.detail`; it is kept out of
    :attr:`code` because it is provider-defined and unbounded, and would turn
    a caller's ``if`` into an open set.
    """

    code = "provider_error"


class StateMismatch(OAuthError):
    """The callback could not be tied back to a redirect this server started.

    Covers every way that link can break — no state cookie, no ``state``
    query parameter, a forged or tampered cookie, or a cookie belonging to a
    different provider. They are deliberately one code: each is either a CSRF
    attempt or an unusable callback, and telling them apart in a redirect URL
    only helps an attacker probe.
    """

    code = "state_mismatch"


class StateExpired(OAuthError):
    """The state cookie was valid but issued too long ago.

    Separate from :class:`StateMismatch` because it has an obvious, blameless
    cause — the person left the consent screen open — and deserves "that took
    too long, try again" rather than a security-flavoured message.
    """

    code = "state_expired"


class TokenExchangeFailed(OAuthError):
    """The provider refused to trade the authorization code for a token.

    Usually a stale or replayed ``code``, a ``redirect_uri`` that does not
    match the one sent to the authorize endpoint, or bad client credentials.
    """

    code = "exchange_failed"


class ProfileFetchFailed(OAuthError):
    """A token was obtained but the provider would not describe its owner.

    Either the userinfo endpoint rejected the token, returned something that
    was not JSON, or omitted the subject claim the profile is keyed on.
    """

    code = "profile_failed"


class ProviderMisconfigured(OAuthError):
    """The provider object itself cannot support the requested step.

    Raised at call time, not at construction, because a provider is legitimate
    with no ``userinfo_endpoint`` right up until something asks it for a
    profile. This is a programming error — it should never reach a redirect.
    """

    code = "provider_misconfigured"
