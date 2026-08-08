"""Provider definitions.

A provider is inert configuration plus two overridable hooks: how to read a
profile out of the provider's userinfo response, and — for the awkward ones —
how to fetch it at all. It registers nothing, owns no routes, and holds no
per-request state, so a single instance built at startup serves every request.

The shipped subclasses only set defaults; every one of their endpoints and
scopes can be overridden per instance, and :class:`OAuthProvider` itself
handles any provider not listed here.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from types import MappingProxyType
from typing import Any

import httpx

from .errors import ProfileFetchFailed, ProviderMisconfigured
from .models import OAuthProfile, OAuthTokens

__all__ = [
    "DiscordOAuthProvider",
    "GithubOAuthProvider",
    "GoogleOAuthProvider",
    "MicrosoftOAuthProvider",
    "OAuthProvider",
]

#: Keys that commonly hold the provider's stable account identifier, tried in
#: order when a provider has no explicit mapping. ``sub`` first because OIDC
#: standardises it; ``id`` next because almost every non-OIDC provider uses it.
_SUBJECT_KEYS = ("sub", "id", "user_id", "uid")


class OAuthProvider:
    """An OAuth 2.0 / OpenID Connect provider.

    Instantiate directly for any provider without a shipped subclass, giving
    it the three endpoints::

        gitlab = OAuthProvider(
            name="gitlab",
            client_id=...,
            client_secret=...,
            state_secret=...,
            authorize_endpoint="https://gitlab.com/oauth/authorize",
            token_endpoint="https://gitlab.com/oauth/token",
            userinfo_endpoint="https://gitlab.com/api/v4/user",
            scopes=["read_user"],
        )

    Attributes:
        name: Identifier for this provider. Appears in profiles, error
            payloads, and the default state cookie name, and is bound into the
            signed state so one provider's callback cannot consume another's.
        client_id: The application's public client identifier.
        client_secret: The application's secret. Empty for a public client.
        state_secret: Key used to sign state cookies and derive PKCE
            verifiers. Independent of ``client_secret`` — it protects this
            server's own cookies, not the provider relationship. May be left
            unset if every call passes ``secret=`` explicitly.
        redirect_uri: Callback URL registered with the provider. Optional
            here if supplied per call instead.
        scopes: Scopes to request.
        use_pkce: Whether to send a PKCE challenge and verifier.
    """

    #: Subclass defaults. Every one is overridable per instance.
    name: str = "oauth"
    authorize_endpoint: str = ""
    token_endpoint: str = ""
    userinfo_endpoint: str | None = None
    default_scopes: tuple[str, ...] = ()
    scope_separator: str = " "
    use_pkce: bool = True

    #: Sent with the token request. The ``Accept`` header is not decoration:
    #: several providers return a form-encoded body without it.
    #:
    #: Read-only, because a plain dict here is shared by every instance of the
    #: class — mutating it to add one header to one provider would silently
    #: change every other provider of that type in the process.
    token_headers: Mapping[str, str] = MappingProxyType({"Accept": "application/json"})

    #: Sent with the userinfo request, alongside ``Authorization``.
    userinfo_headers: Mapping[str, str] = MappingProxyType(
        {"Accept": "application/json"}
    )

    def __init__(
        self,
        *,
        client_id: str,
        client_secret: str = "",
        state_secret: str | None = None,
        redirect_uri: str | None = None,
        scopes: Sequence[str] | None = None,
        name: str | None = None,
        authorize_endpoint: str | None = None,
        token_endpoint: str | None = None,
        userinfo_endpoint: str | None = None,
        use_pkce: bool | None = None,
        authorize_params: Mapping[str, str] | None = None,
        token_headers: Mapping[str, str] | None = None,
        userinfo_headers: Mapping[str, str] | None = None,
        profile_mapper: Callable[[dict[str, Any]], Mapping[str, Any]] | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = 10.0,
    ) -> None:
        """Configure a provider.

        Args:
            client_id: Public client identifier from the provider.
            client_secret: Client secret. Defaults to empty, for public
                clients that authenticate with PKCE alone.
            state_secret: Signing key for state cookies and PKCE verifiers.
            redirect_uri: Callback URL. Can also be given per call, which is
                what a single provider serving several callback paths needs.
            scopes: Scopes to request, replacing the subclass defaults.
            name: Overrides the provider name.
            authorize_endpoint: Overrides the authorize URL.
            token_endpoint: Overrides the token URL.
            userinfo_endpoint: Overrides the userinfo URL.
            use_pkce: Overrides whether PKCE is used. Providers that reject
                unknown parameters need this off.
            authorize_params: Extra query parameters added to every authorize
                URL — ``{"access_type": "offline"}`` and friends.
            token_headers: Headers merged over the class defaults for the
                token request. Merged rather than replaced, so adding one
                header does not silently drop the ``Accept`` that several
                providers need to answer with JSON.
            userinfo_headers: Headers merged over the class defaults for the
                userinfo request. ``Authorization`` is always set from the
                access token and cannot be overridden here.
            profile_mapper: Replaces the subclass's field mapping. Receives
                the raw userinfo dict, returns a mapping of
                :class:`~sillo_oauth.models.OAuthProfile` field names.
            transport: An ``httpx`` transport to use instead of the default
                network one. This is the seam the test suite uses to run the
                whole flow against canned responses.
            timeout: Per-request timeout in seconds for token and userinfo
                calls.

        Raises:
            ProviderMisconfigured: If no authorize or token endpoint is known,
                which means the provider can never complete a login.
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.state_secret = state_secret
        self.redirect_uri = redirect_uri
        self.transport = transport
        self.timeout = timeout
        self.profile_mapper = profile_mapper
        self.authorize_params = dict(authorize_params or {})

        if name is not None:
            self.name = name
        if authorize_endpoint is not None:
            self.authorize_endpoint = authorize_endpoint
        if token_endpoint is not None:
            self.token_endpoint = token_endpoint
        if userinfo_endpoint is not None:
            self.userinfo_endpoint = userinfo_endpoint
        if use_pkce is not None:
            self.use_pkce = use_pkce

        self.scopes: list[str] = (
            list(scopes) if scopes is not None else list(self.default_scopes)
        )

        # Merged over the class defaults, then frozen: an instance that wants
        # one extra header should not have to restate the ones that make the
        # provider work.
        self.token_headers = MappingProxyType(
            {**type(self).token_headers, **(token_headers or {})}
        )
        self.userinfo_headers = MappingProxyType(
            {**type(self).userinfo_headers, **(userinfo_headers or {})}
        )

        # Checked here rather than at redirect time: a provider with no
        # endpoints is a startup mistake, and failing on the first login
        # attempt instead would hide it until traffic arrives.
        if not self.authorize_endpoint or not self.token_endpoint:
            raise ProviderMisconfigured(
                f"Provider {self.name!r} needs both authorize_endpoint and "
                "token_endpoint",
                provider=self.name,
            )

    def __repr__(self) -> str:
        # Deliberately omits client_secret and state_secret: providers get
        # logged and dropped into tracebacks.
        return (
            f"<{type(self).__name__} name={self.name!r} client_id={self.client_id!r}>"
        )

    # -- HTTP -------------------------------------------------------------

    def http_client(self) -> httpx.AsyncClient:
        """Build the client used for token and userinfo calls.

        Override to add proxies, retries, or connection-pool settings. The
        default honours the ``transport`` and ``timeout`` given to the
        constructor.

        Returns:
            An unopened ``httpx.AsyncClient``. The flow closes it.
        """
        return httpx.AsyncClient(transport=self.transport, timeout=self.timeout)

    # -- Token request ----------------------------------------------------

    def token_request_data(
        self,
        *,
        code: str,
        redirect_uri: str,
        verifier: str | None,
    ) -> dict[str, str]:
        """The form body for the token exchange.

        Override for a provider that spells the grant differently or wants
        credentials somewhere other than the body.

        Args:
            code: Authorization code from the callback.
            redirect_uri: Must be byte-identical to the one sent to the
                authorize endpoint, or the provider rejects the exchange.
            verifier: PKCE verifier, or ``None`` when PKCE is off.

        Returns:
            Form fields to POST to the token endpoint.
        """
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": self.client_id,
        }
        if self.client_secret:
            data["client_secret"] = self.client_secret
        if verifier:
            data["code_verifier"] = verifier
        return data

    def refresh_request_data(self, *, refresh_token: str) -> dict[str, str]:
        """The form body for a refresh.

        Args:
            refresh_token: The token issued alongside the original access
                token.

        Returns:
            Form fields to POST to the token endpoint.
        """
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.client_id,
        }
        if self.client_secret:
            data["client_secret"] = self.client_secret
        return data

    # -- Profile ----------------------------------------------------------

    async def fetch_profile(
        self, client: httpx.AsyncClient, tokens: OAuthTokens
    ) -> OAuthProfile:
        """Turn tokens into a profile.

        The default makes one authenticated GET against ``userinfo_endpoint``.
        Override when a provider needs more than that — see
        :class:`GithubOAuthProvider`, which has to make a second call to learn
        an email address.

        Args:
            client: An open client, reused so the whole flow shares one
                connection pool.
            tokens: Credentials from the token exchange.

        Returns:
            The mapped profile.

        Raises:
            ProviderMisconfigured: If the provider has no userinfo endpoint.
            ProfileFetchFailed: If the request fails or the response is not a
                JSON object.
        """
        raw = await self.fetch_userinfo(client, tokens)
        return self.build_profile(raw, tokens)

    async def fetch_userinfo(
        self, client: httpx.AsyncClient, tokens: OAuthTokens
    ) -> dict[str, Any]:
        """GET the userinfo endpoint with the access token.

        Args:
            client: An open client.
            tokens: Credentials from the token exchange.

        Returns:
            The decoded JSON object.

        Raises:
            ProviderMisconfigured: If no userinfo endpoint is configured.
            ProfileFetchFailed: On a non-2xx response, or a body that is not a
                JSON object.
        """
        if not self.userinfo_endpoint:
            raise ProviderMisconfigured(
                f"Provider {self.name!r} has no userinfo_endpoint",
                provider=self.name,
            )

        headers = {
            **self.userinfo_headers,
            "Authorization": tokens.authorization_header(),
        }
        try:
            response = await client.get(self.userinfo_endpoint, headers=headers)
        except httpx.HTTPError as exc:
            raise ProfileFetchFailed(
                "Could not reach the userinfo endpoint",
                provider=self.name,
                detail=str(exc),
            ) from exc

        if response.status_code >= 400:
            raise ProfileFetchFailed(
                "Provider rejected the userinfo request",
                provider=self.name,
                detail=response.text[:500],
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise ProfileFetchFailed(
                "Userinfo response was not JSON",
                provider=self.name,
                detail=response.text[:500],
            ) from exc

        if not isinstance(payload, dict):
            raise ProfileFetchFailed(
                "Userinfo response was not a JSON object",
                provider=self.name,
                detail=response.text[:500],
            )
        return payload

    def map_profile(self, raw: dict[str, Any]) -> Mapping[str, Any]:
        """Map a raw userinfo payload onto profile fields.

        The base implementation is a best guess for providers with no
        subclass: it looks for the subject under the keys OIDC and most
        REST APIs use, and picks up ``email``/``name`` when present. Supply
        ``profile_mapper`` or subclass for anything more specific.

        Args:
            raw: The decoded userinfo object.

        Returns:
            A mapping of :class:`~sillo_oauth.models.OAuthProfile` field names.
            ``subject`` may be missing; :meth:`build_profile` reports that.
        """
        subject = next(
            (str(raw[key]) for key in _SUBJECT_KEYS if raw.get(key) is not None),
            None,
        )
        return {
            "subject": subject,
            "email": raw.get("email"),
            "email_verified": bool(raw.get("email_verified", False)),
            "name": raw.get("name"),
            "username": raw.get("username") or raw.get("preferred_username"),
            "avatar_url": raw.get("picture") or raw.get("avatar_url"),
        }

    def build_profile(
        self, raw: dict[str, Any], tokens: OAuthTokens | None = None
    ) -> OAuthProfile:
        """Assemble the profile from a raw payload.

        Args:
            raw: The decoded userinfo object.
            tokens: Credentials to attach, when the caller has them.

        Returns:
            The profile, with ``raw`` always carrying the untouched payload so
            nothing the mapping dropped is lost.

        Raises:
            ProfileFetchFailed: If no subject could be determined. Without one
                there is nothing stable to key an account on, so this is a
                hard failure rather than a profile with a blank id.
        """
        mapper = self.profile_mapper or self.map_profile
        mapped = dict(mapper(raw))

        subject = mapped.get("subject")
        if subject is None or subject == "":
            raise ProfileFetchFailed(
                f"Provider {self.name!r} returned no account identifier",
                provider=self.name,
                detail=", ".join(sorted(raw)) or "<empty response>",
            )

        mapped["subject"] = str(subject)
        mapped.pop("provider", None)
        mapped.pop("raw", None)
        mapped.pop("tokens", None)
        return OAuthProfile(provider=self.name, raw=raw, tokens=tokens, **mapped)


class GoogleOAuthProvider(OAuthProvider):
    """Google, via OpenID Connect.

    Note that ``email_verified`` is meaningful here — Google states it — so it
    is safe to use when deciding whether to match an existing local account by
    email.
    """

    name = "google"
    authorize_endpoint = "https://accounts.google.com/o/oauth2/v2/auth"
    token_endpoint = "https://oauth2.googleapis.com/token"
    userinfo_endpoint = "https://openidconnect.googleapis.com/v1/userinfo"
    default_scopes = ("openid", "email", "profile")

    def map_profile(self, raw: dict[str, Any]) -> Mapping[str, Any]:
        """Map Google's OIDC userinfo claims.

        Args:
            raw: Decoded userinfo response.

        Returns:
            Profile fields.
        """
        return {
            "subject": raw.get("sub"),
            "email": raw.get("email"),
            "email_verified": bool(raw.get("email_verified", False)),
            "name": raw.get("name"),
            "username": raw.get("preferred_username"),
            "avatar_url": raw.get("picture"),
        }


class GithubOAuthProvider(OAuthProvider):
    """GitHub.

    Two departures from the common case, both GitHub's:

    * PKCE is off. GitHub's OAuth app flow does not implement it, and sending
      the parameters gains nothing.
    * A profile may come back with ``email: null``, because GitHub honours the
      "keep my address private" setting on ``/user``. When that happens and
      the ``user:email`` scope was granted, :meth:`fetch_profile` makes a
      second call to find the primary verified address.
    """

    name = "github"
    authorize_endpoint = "https://github.com/login/oauth/authorize"
    token_endpoint = "https://github.com/login/oauth/access_token"
    userinfo_endpoint = "https://api.github.com/user"
    default_scopes = ("read:user", "user:email")
    use_pkce = False
    userinfo_headers = MappingProxyType({"Accept": "application/vnd.github+json"})

    #: Where the address list lives, when ``/user`` withholds it. Derived from
    #: :attr:`userinfo_endpoint` rather than hardcoded, so pointing this
    #: provider at a GitHub Enterprise host moves both endpoints together.
    emails_endpoint: str

    def __init__(self, *, emails_endpoint: str | None = None, **kwargs: Any) -> None:
        """Configure the provider.

        Args:
            emails_endpoint: Where to look up addresses. Defaults to
                ``<userinfo_endpoint>/emails``, which is right for github.com
                and for any Enterprise host reached by overriding
                ``userinfo_endpoint``.
            **kwargs: Everything :class:`OAuthProvider` accepts.
        """
        super().__init__(**kwargs)
        self.emails_endpoint = emails_endpoint or f"{self.userinfo_endpoint}/emails"

    async def fetch_profile(
        self, client: httpx.AsyncClient, tokens: OAuthTokens
    ) -> OAuthProfile:
        """Fetch the account, falling back to the email list when needed.

        Args:
            client: An open client.
            tokens: Credentials from the token exchange.

        Returns:
            The profile, with ``email`` filled from ``/user/emails`` if
            ``/user`` withheld it.
        """
        raw = await self.fetch_userinfo(client, tokens)
        if not raw.get("email"):
            found = await self._fetch_primary_email(client, tokens)
            if found is not None:
                # Merged into the raw payload rather than patched onto the
                # profile afterwards, so `profile.raw` stays a faithful record
                # of what the mapping actually saw.
                raw = {**raw, **found}
        return self.build_profile(raw, tokens)

    async def _fetch_primary_email(
        self, client: httpx.AsyncClient, tokens: OAuthTokens
    ) -> dict[str, Any] | None:
        """Look up the primary verified address.

        A failure here is not fatal — the scope may simply not have been
        granted — so every problem returns ``None`` and leaves the profile
        without an email rather than failing a login that is otherwise fine.

        Args:
            client: An open client.
            tokens: Credentials from the token exchange.

        Returns:
            ``{"email": ..., "email_verified": True}`` or ``None``.
        """
        headers = {
            **self.userinfo_headers,
            "Authorization": tokens.authorization_header(),
        }
        try:
            response = await client.get(self.emails_endpoint, headers=headers)
            if response.status_code >= 400:
                return None
            entries = response.json()
        except (httpx.HTTPError, ValueError):
            return None

        if not isinstance(entries, list):
            return None

        for entry in entries:
            if (
                isinstance(entry, dict)
                and entry.get("primary")
                and entry.get("verified")
                and entry.get("email")
            ):
                return {"email": entry["email"], "email_verified": True}
        return None

    def map_profile(self, raw: dict[str, Any]) -> Mapping[str, Any]:
        """Map GitHub's user payload.

        ``email_verified`` is only ever true when the address came from the
        emails endpoint, which is the sole place GitHub states verification.

        Args:
            raw: Decoded ``/user`` response, possibly merged with an email.

        Returns:
            Profile fields.
        """
        return {
            "subject": raw.get("id"),
            "email": raw.get("email"),
            "email_verified": bool(raw.get("email_verified", False)),
            "name": raw.get("name"),
            "username": raw.get("login"),
            "avatar_url": raw.get("avatar_url"),
        }


class DiscordOAuthProvider(OAuthProvider):
    """Discord.

    Discord returns an avatar *hash* rather than a URL, so the mapping builds
    the CDN link itself.
    """

    name = "discord"
    authorize_endpoint = "https://discord.com/oauth2/authorize"
    token_endpoint = "https://discord.com/api/oauth2/token"
    userinfo_endpoint = "https://discord.com/api/users/@me"
    default_scopes = ("identify", "email")

    def map_profile(self, raw: dict[str, Any]) -> Mapping[str, Any]:
        """Map Discord's user payload.

        Args:
            raw: Decoded ``/users/@me`` response.

        Returns:
            Profile fields, with ``avatar_url`` assembled from the hash.
        """
        user_id = raw.get("id")
        avatar = raw.get("avatar")
        avatar_url = (
            f"https://cdn.discordapp.com/avatars/{user_id}/{avatar}.png"
            if user_id and avatar
            else None
        )
        return {
            "subject": user_id,
            "email": raw.get("email"),
            # Discord's `verified` is about the email address, not the account.
            "email_verified": bool(raw.get("verified", False)),
            "name": raw.get("global_name") or raw.get("username"),
            "username": raw.get("username"),
            "avatar_url": avatar_url,
        }


class MicrosoftOAuthProvider(OAuthProvider):
    """Microsoft identity platform (Entra ID).

    The endpoints are tenant-scoped. ``"common"`` accepts both work and
    personal accounts; pass a tenant id to restrict logins to one directory.
    """

    name = "microsoft"
    userinfo_endpoint = "https://graph.microsoft.com/oidc/userinfo"
    default_scopes = ("openid", "email", "profile")

    def __init__(self, *, tenant: str = "common", **kwargs: Any) -> None:
        """Configure the provider for a tenant.

        Args:
            tenant: Directory to authenticate against — a tenant id,
                ``"common"``, ``"organizations"``, or ``"consumers"``.
            **kwargs: Everything :class:`OAuthProvider` accepts. Passing
                ``authorize_endpoint`` or ``token_endpoint`` explicitly wins
                over the tenant-derived defaults.
        """
        self.tenant = tenant
        base = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0"
        kwargs.setdefault("authorize_endpoint", f"{base}/authorize")
        kwargs.setdefault("token_endpoint", f"{base}/token")
        super().__init__(**kwargs)

    def map_profile(self, raw: dict[str, Any]) -> Mapping[str, Any]:
        """Map Microsoft's OIDC userinfo claims.

        Microsoft does not return an ``email_verified`` claim from this
        endpoint, so it stays ``False`` — meaning "not stated", which is the
        safe reading when deciding whether to trust an address.

        Args:
            raw: Decoded userinfo response.

        Returns:
            Profile fields.
        """
        return {
            "subject": raw.get("sub"),
            "email": raw.get("email") or raw.get("upn"),
            "email_verified": False,
            "name": raw.get("name"),
            "username": raw.get("preferred_username"),
            "avatar_url": raw.get("picture"),
        }
