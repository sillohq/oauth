"""The two steps of an OAuth login, as plain functions.

Nothing here builds a response, sets a cookie, or registers a route.
:func:`authorize_url` returns a URL and the value that must survive the round
trip; :func:`exchange` returns a verified profile. What happens on either side
of those — which paths they live at, how the identity is persisted, where
failures redirect — stays in the handler that calls them::

    from sillo_oauth import authorize_url, exchange, OAuthError

    @app.get("/auth/google/redirect")
    async def start(request, response):
        authorize = authorize_url(google)
        response.set_cookie(**authorize.cookie_kwargs())
        return response.redirect(authorize.url)

    @app.get("/auth/google/callback")
    async def finish(request, response):
        try:
            profile = await exchange(google, request)
        except OAuthError as exc:
            return response.redirect(f"/login?error={exc.code}")
        ...

Each step also has a request-free form — :func:`complete`, :func:`exchange_code`
and :func:`fetch_profile` — for callers whose credentials do not arrive as a
sillo ``Request``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import replace
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from .errors import (
    OAuthDenied,
    ProviderMisconfigured,
    ProviderRejected,
    StateMismatch,
    TokenExchangeFailed,
)
from .models import AuthorizeURL, OAuthProfile, OAuthTokens
from .providers import OAuthProvider
from .state import derive_verifier, issue_state, pkce_challenge, verify_state

if TYPE_CHECKING:
    from sillo.core.http import Request

__all__ = [
    "authorize_url",
    "complete",
    "exchange",
    "exchange_code",
    "fetch_profile",
    "state_cookie_name",
]

#: Provider error codes that mean "the person said no". Both spellings are in
#: the wild: the first is RFC 6749, the second is what a few providers send.
#: Deliberately excludes OIDC's ``consent_required``, which comes back from a
#: ``prompt=none`` request and means "ask them properly", not "they refused".
_DENIAL_CODES = frozenset({"access_denied", "user_denied"})


def state_cookie_name(provider: OAuthProvider) -> str:
    """The default cookie name for a provider's state.

    Namespaced per provider so a login started with one and a login started
    with another — two tabs, two buttons — do not overwrite each other.

    Args:
        provider: The provider the redirect is for.

    Returns:
        e.g. ``"oauth_state_google"``.
    """
    return f"oauth_state_{provider.name}"


def _require_secret(provider: OAuthProvider, secret: str | None) -> str:
    """Resolve the signing secret, preferring the per-call override.

    Args:
        provider: The provider in play.
        secret: Per-call override, or ``None`` to use the provider's.

    Returns:
        The secret to sign or verify state with.

    Raises:
        ProviderMisconfigured: If neither is set. Continuing would mean an
            unsigned state cookie, i.e. no CSRF protection at all, so this
            fails instead of degrading quietly.
    """
    resolved = secret or provider.state_secret
    if not resolved:
        raise ProviderMisconfigured(
            f"Provider {provider.name!r} has no state_secret; set one on the "
            "provider or pass secret= to this call",
            provider=provider.name,
        )
    return resolved


def _require_redirect_uri(provider: OAuthProvider, redirect_uri: str | None) -> str:
    """Resolve the callback URL, preferring the per-call override.

    Args:
        provider: The provider in play.
        redirect_uri: Per-call override, or ``None`` to use the provider's.

    Returns:
        The callback URL.

    Raises:
        ProviderMisconfigured: If neither is set.
    """
    resolved = redirect_uri or provider.redirect_uri
    if not resolved:
        raise ProviderMisconfigured(
            f"Provider {provider.name!r} has no redirect_uri; set one on the "
            "provider or pass redirect_uri= to this call",
            provider=provider.name,
        )
    return resolved


def _merge_query(url: str, params: dict[str, str]) -> str:
    """Add query parameters to a URL that may already have some.

    Args:
        url: Base URL, possibly carrying its own query string.
        params: Parameters to append.

    Returns:
        The combined URL, with existing parameters preserved.
    """
    parts = urlsplit(url)
    existing = parse_qsl(parts.query, keep_blank_values=True)
    query = urlencode([*existing, *params.items()])
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


def authorize_url(
    provider: OAuthProvider,
    *,
    redirect_uri: str | None = None,
    scopes: Sequence[str] | None = None,
    return_to: str | None = None,
    extra_params: Mapping[str, str] | None = None,
    ttl: int = 600,
    secret: str | None = None,
    cookie_name: str | None = None,
) -> AuthorizeURL:
    """Build the URL that starts a login.

    Pure: it reads no request, performs no I/O, and writes nothing. The value
    that has to survive the round trip comes back on the result for the caller
    to store — as a cookie, in the session, wherever.

    Args:
        provider: The provider to authenticate against.
        redirect_uri: Callback URL, overriding the provider's.
        scopes: Scopes to request, overriding the provider's.
        return_to: Opaque value carried through the provider and returned on
            :attr:`OAuthProfile.return_to`. Signed, so it cannot be tampered
            with — but still validate it before redirecting to it, since a
            caller can put anything in.
        extra_params: Extra query parameters for this call only, merged over
            the provider's own. Use for one-off prompts such as
            ``{"prompt": "consent"}`` or ``{"login_hint": email}``.
        ttl: Seconds the state stays valid.
        secret: Signing secret, overriding the provider's.
        cookie_name: Cookie name, overriding the per-provider default.

    Returns:
        The URL to send the person to, plus the state cookie to set.

    Raises:
        ProviderMisconfigured: If no signing secret or redirect URI is
            available from either the provider or this call.
    """
    signing_secret = _require_secret(provider, secret)
    callback = _require_redirect_uri(provider, redirect_uri)

    state, cookie_value = issue_state(
        provider.name, signing_secret, ttl=ttl, return_to=return_to
    )

    params: dict[str, str] = {
        "response_type": "code",
        "client_id": provider.client_id,
        "redirect_uri": callback,
        "state": state,
    }

    requested = list(scopes) if scopes is not None else provider.scopes
    if requested:
        params["scope"] = provider.scope_separator.join(requested)

    if provider.use_pkce:
        params["code_challenge"] = pkce_challenge(
            derive_verifier(state, signing_secret)
        )
        params["code_challenge_method"] = "S256"

    params.update(provider.authorize_params)
    if extra_params:
        params.update(extra_params)

    return AuthorizeURL(
        url=_merge_query(provider.authorize_endpoint, params),
        state=state,
        cookie_name=cookie_name or state_cookie_name(provider),
        cookie_value=cookie_value,
        max_age=ttl,
    )


async def exchange(
    provider: OAuthProvider,
    request: Request,
    *,
    secret: str | None = None,
    cookie_name: str | None = None,
    redirect_uri: str | None = None,
) -> OAuthProfile:
    """Complete a login from an incoming callback request.

    Reads the ``code``, ``state`` and ``error`` query parameters and the state
    cookie off *request*, then does everything :func:`complete` does. It reads
    the request and returns data — it does not touch the response.

    Args:
        provider: The provider that issued the callback.
        request: The sillo request for the callback.
        secret: Signing secret, overriding the provider's.
        cookie_name: Cookie to read the state from, overriding the default.
        redirect_uri: Callback URL for the token request. Must match the one
            used to build the authorize URL.

    Returns:
        The verified profile.

    Raises:
        OAuthError: Any failure in the flow — see :func:`complete`.
    """
    query = request.query_params
    cookies = request.cookies
    return await complete(
        provider,
        code=query.get("code"),
        state=query.get("state"),
        cookie_value=cookies.get(cookie_name or state_cookie_name(provider)),
        error=query.get("error"),
        error_description=query.get("error_description"),
        secret=secret,
        redirect_uri=redirect_uri,
    )


async def complete(
    provider: OAuthProvider,
    *,
    code: str | None,
    state: str | None,
    cookie_value: str | None,
    error: str | None = None,
    error_description: str | None = None,
    secret: str | None = None,
    redirect_uri: str | None = None,
) -> OAuthProfile:
    """Complete a login from already-extracted callback values.

    The request-free form of :func:`exchange`, for callers whose callback did
    not arrive as a sillo ``Request`` — a worker consuming a queued callback,
    a CLI, a test.

    The order of checks matters and is fixed: a provider-reported error is
    handled first (there is no code to exchange anyway), then state is
    verified, and only then is anything sent to the provider. Verifying state
    last would mean a forged callback could still make this server issue a
    token request.

    Args:
        provider: The provider that issued the callback.
        code: The ``code`` query parameter.
        state: The ``state`` query parameter.
        cookie_value: The stored state value from the redirect step.
        error: The ``error`` query parameter, if the provider sent one.
        error_description: The provider's human-readable elaboration.
        secret: Signing secret, overriding the provider's.
        redirect_uri: Callback URL for the token request.

    Returns:
        The verified profile, carrying the tokens and any ``return_to``.

    Raises:
        OAuthDenied: The person refused consent.
        ProviderRejected: The provider reported some other error.
        StateMismatch: The callback does not match a redirect from this
            server, or arrived without a code.
        StateExpired: The state was genuine but too old.
        TokenExchangeFailed: The provider would not issue a token.
        ProfileFetchFailed: The token worked but the profile did not.
        ProviderMisconfigured: Required configuration is missing.
    """
    signing_secret = _require_secret(provider, secret)

    if error:
        if error in _DENIAL_CODES:
            raise OAuthDenied(
                "The user declined authorization",
                provider=provider.name,
                detail=error_description or error,
            )
        raise ProviderRejected(
            f"Provider returned {error!r}",
            provider=provider.name,
            detail=error_description or error,
        )

    payload = verify_state(cookie_value, state, provider.name, signing_secret)

    if not code:
        # State checked out but there is nothing to redeem. Reported as a
        # mismatch rather than its own code because it is the same practical
        # outcome — an unusable callback — and callers already branch on it.
        raise StateMismatch(
            "Callback carried no authorization code", provider=provider.name
        )

    verifier = (
        derive_verifier(payload.state, signing_secret) if provider.use_pkce else None
    )

    async with provider.http_client() as client:
        tokens = await _request_tokens(
            provider,
            client,
            code=code,
            redirect_uri=_require_redirect_uri(provider, redirect_uri),
            verifier=verifier,
        )
        profile = await provider.fetch_profile(client, tokens)

    # Frozen dataclass, so the carried value is attached by rebuilding rather
    # than mutating — and only here, where the state payload is in scope.
    if payload.return_to is not None:
        profile = replace(profile, return_to=payload.return_to)
    return profile


async def exchange_code(
    provider: OAuthProvider,
    *,
    code: str,
    redirect_uri: str | None = None,
    verifier: str | None = None,
) -> OAuthTokens:
    """Trade an authorization code for tokens, and nothing else.

    Skips state verification entirely, so only call it where the callback has
    already been authenticated some other way.

    Args:
        provider: The provider to call.
        code: The authorization code.
        redirect_uri: Callback URL, which must match the authorize request.
        verifier: PKCE verifier, if the authorize request sent a challenge.

    Returns:
        The tokens the provider issued.

    Raises:
        TokenExchangeFailed: The provider refused, was unreachable, or
            returned something unreadable.
        ProviderMisconfigured: No redirect URI is available.
    """
    async with provider.http_client() as client:
        return await _request_tokens(
            provider,
            client,
            code=code,
            redirect_uri=_require_redirect_uri(provider, redirect_uri),
            verifier=verifier,
        )


async def fetch_profile(provider: OAuthProvider, tokens: OAuthTokens) -> OAuthProfile:
    """Fetch a profile for tokens already in hand.

    Useful for refreshing a stored profile without repeating the login.

    Args:
        provider: The provider to call.
        tokens: Credentials to authenticate the userinfo call with.

    Returns:
        The profile.

    Raises:
        ProfileFetchFailed: The provider rejected the token or returned
            something unusable.
        ProviderMisconfigured: The provider has no userinfo endpoint.
    """
    async with provider.http_client() as client:
        return await provider.fetch_profile(client, tokens)


async def _request_tokens(
    provider: OAuthProvider,
    client: httpx.AsyncClient,
    *,
    code: str,
    redirect_uri: str,
    verifier: str | None,
) -> OAuthTokens:
    """POST the token endpoint and read the result.

    Args:
        provider: The provider to call.
        client: An open client, shared with the profile call.
        code: The authorization code.
        redirect_uri: Callback URL, echoed for the provider to compare.
        verifier: PKCE verifier, or ``None``.

    Returns:
        The parsed tokens.

    Raises:
        TokenExchangeFailed: On transport failure, a non-2xx status, an
            unreadable body, an ``error`` field, or a missing access token.
    """
    data = provider.token_request_data(
        code=code, redirect_uri=redirect_uri, verifier=verifier
    )

    try:
        response = await client.post(
            provider.token_endpoint,
            data=data,
            headers=dict(provider.token_headers),
        )
    except httpx.HTTPError as exc:
        raise TokenExchangeFailed(
            "Could not reach the token endpoint",
            provider=provider.name,
            detail=str(exc),
        ) from exc

    payload = _decode_token_response(response, provider.name)

    if payload.get("error"):
        raise TokenExchangeFailed(
            "Provider refused the authorization code",
            provider=provider.name,
            detail=str(payload.get("error_description") or payload["error"]),
        )

    if response.status_code >= 400:
        raise TokenExchangeFailed(
            "Provider refused the authorization code",
            provider=provider.name,
            detail=response.text[:500],
        )

    access_token = payload.get("access_token")
    if not access_token:
        raise TokenExchangeFailed(
            "Token response carried no access_token",
            provider=provider.name,
            detail=", ".join(sorted(payload)) or "<empty response>",
        )

    return OAuthTokens(
        access_token=str(access_token),
        token_type=str(payload.get("token_type") or "Bearer"),
        refresh_token=payload.get("refresh_token"),
        expires_in=_parse_expires_in(payload.get("expires_in")),
        scope=payload.get("scope"),
        id_token=payload.get("id_token"),
        raw=payload,
    )


def _parse_expires_in(value: Any) -> int | None:
    """Read a token lifetime, whatever shape the provider sent it in.

    Providers are inconsistent here: an int, a decimal string, and a float
    are all in the wild. A lifetime is advisory — the token either works or
    it does not — so anything unreadable becomes ``None`` rather than
    failing an otherwise good login.

    Args:
        value: The raw ``expires_in`` field.

    Returns:
        The lifetime in whole seconds, or ``None`` if absent or unreadable.
        Negative values are dropped too: an already-expired token is a
        provider bug, and reporting it as a negative lifetime just moves the
        surprise into the caller's arithmetic.
    """
    if value is None or isinstance(value, bool):
        return None
    try:
        seconds = int(float(value))
    except (TypeError, ValueError):
        return None
    return seconds if seconds >= 0 else None


def _decode_token_response(response: httpx.Response, provider: str) -> dict[str, Any]:
    """Read a token response as JSON, falling back to form encoding.

    Most providers answer with JSON. A few — GitHub being the one everyone
    meets — answer with ``application/x-www-form-urlencoded`` unless asked
    otherwise, and will do so again the moment someone overrides
    ``token_headers``. Handling both means that override cannot silently
    break the exchange.

    Args:
        response: The token endpoint's response.
        provider: Provider name, for the error.

    Returns:
        The decoded body as a flat dict.

    Raises:
        TokenExchangeFailed: The body is neither a JSON object nor a form.
    """
    content_type = response.headers.get("content-type", "")

    if "json" in content_type:
        try:
            payload = response.json()
        except ValueError as exc:
            raise TokenExchangeFailed(
                "Token response was not valid JSON",
                provider=provider,
                detail=response.text[:500],
            ) from exc
        if not isinstance(payload, dict):
            raise TokenExchangeFailed(
                "Token response was not a JSON object",
                provider=provider,
                detail=response.text[:500],
            )
        return payload

    if "form-urlencoded" in content_type:
        return dict(parse_qsl(response.text, keep_blank_values=True))

    # No usable content type. Try both rather than guess, since an untyped
    # body is still readable and refusing it would fail a working login.
    try:
        payload = response.json()
        if isinstance(payload, dict):
            return payload
    except ValueError:
        pass

    parsed = dict(parse_qsl(response.text, keep_blank_values=True))
    if parsed:
        return parsed

    raise TokenExchangeFailed(
        "Token response could not be decoded",
        provider=provider,
        detail=response.text[:500],
    )
