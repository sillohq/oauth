"""OAuth 2.0 / OpenID Connect login for sillo.

The whole surface is two functions and a provider object. Neither function
takes a response, builds one, or registers a route — the redirect step returns
a URL and the value to store, the callback step returns a verified profile,
and everything around them stays in the application's own handlers::

    from sillo_oauth import GoogleOAuthProvider, authorize_url, exchange, OAuthError

    google = GoogleOAuthProvider(
        client_id=...,
        client_secret=...,
        state_secret=...,
        redirect_uri="https://example.com/auth/google/callback",
    )

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
        user = await resolve_user(profile)
        login(request, user)          # or create_jwt(...), or neither
        return response.redirect(profile.return_to or "/")

What the profile becomes — a session, a JWT, a linked account, nothing — is
never decided here.
"""

from .errors import (
    OAuthDenied,
    OAuthError,
    ProfileFetchFailed,
    ProviderMisconfigured,
    ProviderRejected,
    StateExpired,
    StateMismatch,
    TokenExchangeFailed,
)
from .flow import (
    authorize_url,
    complete,
    exchange,
    exchange_code,
    fetch_profile,
    state_cookie_name,
)
from .models import AuthorizeURL, OAuthProfile, OAuthTokens
from .providers import (
    DiscordOAuthProvider,
    GithubOAuthProvider,
    GoogleOAuthProvider,
    MicrosoftOAuthProvider,
    OAuthProvider,
)
from .state import (
    StatePayload,
    derive_verifier,
    issue_state,
    pkce_challenge,
    verify_state,
)

__version__ = "0.0.1a0"

__all__ = [
    "AuthorizeURL",
    "DiscordOAuthProvider",
    "GithubOAuthProvider",
    "GoogleOAuthProvider",
    "MicrosoftOAuthProvider",
    "OAuthDenied",
    "OAuthError",
    "OAuthProfile",
    "OAuthProvider",
    "OAuthTokens",
    "ProfileFetchFailed",
    "ProviderMisconfigured",
    "ProviderRejected",
    "StateExpired",
    "StateMismatch",
    "StatePayload",
    "TokenExchangeFailed",
    "__version__",
    "authorize_url",
    "complete",
    "derive_verifier",
    "exchange",
    "exchange_code",
    "fetch_profile",
    "issue_state",
    "pkce_challenge",
    "state_cookie_name",
    "verify_state",
]
