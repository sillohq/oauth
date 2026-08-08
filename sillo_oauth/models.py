"""The data the flow hands back.

Three frozen records, no behaviour beyond formatting. Nothing here touches a
``Response``: :class:`AuthorizeURL` describes what needs to be sent and stored,
and the caller decides how.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

__all__ = ["AuthorizeURL", "OAuthProfile", "OAuthTokens"]


@dataclass(frozen=True)
class AuthorizeURL:
    """Everything the redirect step produces.

    The flow is stateless, so the one thing that must survive the round trip
    to the provider — proof that *this* server started *this* login — is
    handed back as a cookie to set rather than written anywhere. Storing it
    somewhere other than a cookie (the session, say) is fine: only
    ``cookie_value`` matters, and :func:`sillo_oauth.exchange` will read it
    from wherever you pass it.

    Attributes:
        url: Where to send the person. A plain string — build the redirect
            yourself.
        state: The opaque value echoed back by the provider. Exposed for
            logging and for callers who want to key their own storage on it;
            verification does not need it.
        cookie_name: Suggested cookie name, namespaced per provider so two
            logins started in two tabs cannot overwrite each other.
        cookie_value: The signed payload that must come back on the callback.
        max_age: Seconds the value stays valid. Past this,
            :class:`~sillo_oauth.errors.StateExpired`.
    """

    url: str
    state: str
    cookie_name: str
    cookie_value: str
    max_age: int

    def cookie_kwargs(self, **overrides: Any) -> dict[str, Any]:
        """Arguments for ``response.set_cookie``, with safe defaults.

        A convenience, never a requirement — the fields are all public and a
        caller who wants different attributes can ignore this entirely::

            return response.redirect(authorize.url).set_cookie(
                **authorize.cookie_kwargs()
            )

        Note the order: sillo's ``Responder`` has no response to attach a
        cookie to until ``redirect()``/``json()`` has been called, so setting
        the cookie first raises. Chaining, or setting it after, both work.

        Every attribute is stated rather than left to the framework's
        defaults, which differ between ``Responder.set_cookie`` (``secure``
        on) and ``BaseResponse.set_cookie`` (off) — a difference that would
        otherwise decide the security of this cookie by which object the
        caller happened to hold.

        The choices:

        * ``httponly`` — nothing in the browser needs to read this.
        * ``samesite="lax"`` — ``"strict"`` would stop the browser sending
          the cookie on the provider's cross-site redirect back, which is the
          one request that needs it.
        * ``secure`` — on, since a live OAuth redirect URI is HTTPS. Plain
          ``http://localhost`` development is the exception, and needs
          ``cookie_kwargs(secure=False)``; without it the browser accepts the
          cookie and never sends it back, and every callback fails as a state
          mismatch.

        Args:
            **overrides: Any cookie attribute to replace, e.g.
                ``secure=False`` or ``path="/auth"``.

        Returns:
            Keyword arguments for ``Response.set_cookie``.
        """
        kwargs: dict[str, Any] = {
            "key": self.cookie_name,
            "value": self.cookie_value,
            "max_age": self.max_age,
            "httponly": True,
            "samesite": "lax",
            "secure": True,
            "path": "/",
        }
        kwargs.update(overrides)
        return kwargs


@dataclass(frozen=True)
class OAuthTokens:
    """What the token endpoint returned.

    Attributes:
        access_token: The credential for calling the provider's API.
        token_type: Normally ``"Bearer"``. Kept as sent, since a few providers
            spell it ``"bearer"``.
        refresh_token: Present only when the provider was asked for offline
            access and agreed.
        expires_in: Lifetime in seconds, when stated.
        scope: Scopes actually granted, which can be narrower than requested.
        id_token: The OIDC identity token, for providers that issue one. This
            package does not verify it — treat it as opaque unless you do.
        raw: The full decoded response, so provider-specific extras are never
            lost to this dataclass's field list.
    """

    access_token: str
    token_type: str = "Bearer"
    refresh_token: str | None = None
    expires_in: int | None = None
    scope: str | None = None
    id_token: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    def authorization_header(self) -> str:
        """The ``Authorization`` value for calling the provider's API.

        Returns:
            ``"Bearer <token>"``, with the token type capitalised as HTTP
            expects regardless of how the provider spelled it.
        """
        return f"{self.token_type.capitalize()} {self.access_token}"


@dataclass(frozen=True)
class OAuthProfile:
    """A verified external identity.

    This is the flow's whole output. It is deliberately *not* a user: mapping
    it onto an account, creating one, or refusing to, is the application's
    decision and happens in the caller's handler.

    Attributes:
        provider: Which provider vouched for this identity.
        subject: The provider's stable identifier for the account. This is the
            only field safe to key a local account on — email addresses get
            reassigned and usernames get renamed, and both are mutable at most
            providers.
        email: Best-known address, if any scope granted access to one.
        email_verified: Whether the provider claims to have verified it.
            ``False`` also means "did not say", so never merge accounts on an
            unverified address.
        name: Human-readable display name.
        username: Provider-local handle, where the concept exists.
        avatar_url: Profile picture, when given.
        raw: The untouched userinfo payload.
        tokens: The credentials this profile was fetched with, kept so a
            caller can store them and call the provider's API later.
        return_to: Whatever was handed to ``authorize_url(return_to=...)``,
            carried through the provider round trip inside the signed state
            and given back here.
    """

    provider: str
    subject: str
    email: str | None = None
    email_verified: bool = False
    name: str | None = None
    username: str | None = None
    avatar_url: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)
    tokens: OAuthTokens | None = None
    return_to: str | None = None

    @property
    def key(self) -> str:
        """A globally unique handle for this identity.

        ``subject`` is only unique within one provider, so anything storing
        identities from more than one needs the pair. Handy as a lookup key
        or a generated username seed.

        Returns:
            ``"<provider>:<subject>"``.
        """
        return f"{self.provider}:{self.subject}"
