"""The flow driven through a real sillo application.

These tests wire ``authorize_url`` and ``exchange`` into ordinary handlers and
walk a ``TestClient`` through the whole login: redirect, provider callback,
protected route. The provider is stubbed, so no test needs credentials or a
network — but everything on this side of the wire is the real thing, including
sillo's session middleware, authentication middleware, and ``useAuth`` gate.

They exist because the unit tests cannot catch integration mistakes: cookie
attributes that stop a browser returning the cookie, middleware registered in
the wrong order, a gate that lets an unauthenticated request through.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest
from conftest import (
    ACCESS_TOKEN,
    CLIENT_ID,
    CLIENT_SECRET,
    STATE_SECRET,
    ProviderStub,
)
from sillo import silloApp
from sillo.auth import AuthenticationMiddleware, useAuth
from sillo.auth.jwt_auth import JWTAuthBackend, create_jwt
from sillo.auth.session_auth import SessionAuthBackend, login, logout
from sillo.session import SessionMiddleware
from sillo.testclient import TestClient
from sillo.users import SimpleUser

from sillo_oauth import (
    GithubOAuthProvider,
    GoogleOAuthProvider,
    OAuthError,
    authorize_url,
    exchange,
)

SESSION_SECRET = "test-session-secret"
# 32+ bytes, or PyJWT warns about the HMAC key length on every call.
JWT_SECRET = "test-jwt-secret-padded-to-32-bytes-plus"
CALLBACK = "http://testserver/auth/google/callback"


def make_provider(stub: ProviderStub, cls=GoogleOAuthProvider, **overrides):
    """Build a provider wired to *stub*, with the happy path routed."""
    stub.route(cls.token_endpoint, json={"access_token": ACCESS_TOKEN})
    stub.route(
        cls.userinfo_endpoint,
        json=overrides.pop(
            "userinfo",
            {
                "sub": "google-subject-1",
                "id": 4242,
                "login": "ada",
                "email": "ada@example.com",
                "email_verified": True,
                "name": "Ada Lovelace",
            },
        ),
    )
    return cls(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        state_secret=STATE_SECRET,
        redirect_uri=CALLBACK,
        transport=stub.transport,
        **overrides,
    )


def state_from(response) -> str:
    """Pull the ``state`` parameter out of a redirect's Location header."""
    return parse_qs(urlsplit(response.headers["location"]).query)["state"][0]


def session_app() -> silloApp:
    """An app with session-cookie authentication installed.

    ``app.use`` builds the middleware chain inside-out — the last registered
    runs first — so ``SessionMiddleware`` is registered *after*
    ``AuthenticationMiddleware`` in order to run *before* it. Reversed, the
    session backend finds no session and every request is anonymous.
    """
    app = silloApp()
    app.use(
        AuthenticationMiddleware(user_model=SimpleUser, backend=[SessionAuthBackend()])
    )
    # `session_cookie_secure=False` because TestClient speaks http; a
    # deployment over https should leave it on.
    app.use(SessionMiddleware(secret_key=SESSION_SECRET, session_cookie_secure=False))
    return app


@pytest.fixture
def google(stub: ProviderStub) -> GoogleOAuthProvider:
    """A stubbed Google provider whose callback URL matches the test app."""
    return make_provider(stub)


class TestSessionLogin:
    """The common case: OAuth in, session cookie out."""

    @pytest.fixture
    def client(self, google) -> TestClient:
        app = session_app()

        async def start(request, response):
            authorize = authorize_url(google, return_to="/me")
            return response.redirect(authorize.url).set_cookie(
                **authorize.cookie_kwargs(secure=False)
            )

        async def finish(request, response):
            try:
                profile = await exchange(google, request)
            except OAuthError as exc:
                return response.json({"error": exc.code}, status_code=400)
            login(request, SimpleUser(profile.key))
            return response.redirect(profile.return_to or "/")

        async def me(request, response):
            return response.json({"identity": request.user.identity})

        async def sign_out(request, response):
            logout(request)
            return response.json({"ok": True})

        app.get("/auth/google/redirect", handler=start)
        app.get("/auth/google/callback", handler=finish)
        app.get("/me", handler=me, auth=useAuth())
        app.get("/logout", handler=sign_out)
        return TestClient(app, follow_redirects=False)

    def test_redirect_sends_the_browser_to_the_provider(self, client):
        response = client.get("/auth/google/redirect")

        assert response.status_code == 302
        assert response.headers["location"].startswith(
            GoogleOAuthProvider.authorize_endpoint
        )

    def test_redirect_sets_the_state_cookie(self, client):
        response = client.get("/auth/google/redirect")

        assert "oauth_state_google" in response.headers["set-cookie"]
        assert "HttpOnly" in response.headers["set-cookie"]

    def test_protected_route_is_closed_before_login(self, client):
        assert client.get("/me").status_code == 401

    def test_full_login(self, client, stub):
        started = client.get("/auth/google/redirect")

        finished = client.get(
            f"/auth/google/callback?code=test-code&state={state_from(started)}"
        )

        assert finished.status_code == 302
        assert finished.headers["location"] == "/me"
        assert client.get("/me").json() == {"identity": "google:google-subject-1"}

    def test_login_reaches_the_provider_exactly_once(self, client, stub):
        started = client.get("/auth/google/redirect")
        client.get(f"/auth/google/callback?code=test-code&state={state_from(started)}")

        assert len(stub.requests) == 2, "one token call, one userinfo call"

    def test_logout_closes_the_route_again(self, client):
        started = client.get("/auth/google/redirect")
        client.get(f"/auth/google/callback?code=test-code&state={state_from(started)}")
        assert client.get("/me").status_code == 200

        client.get("/logout")

        assert client.get("/me").status_code == 401

    def test_return_to_drives_the_final_redirect(self, google, stub):
        app = session_app()

        async def start(request, response):
            authorize = authorize_url(
                google, return_to=request.query_params.get("next", "/")
            )
            return response.redirect(authorize.url).set_cookie(
                **authorize.cookie_kwargs(secure=False)
            )

        async def finish(request, response):
            profile = await exchange(google, request)
            login(request, SimpleUser(profile.key))
            return response.redirect(profile.return_to or "/")

        app.get("/auth/google/redirect", handler=start)
        app.get("/auth/google/callback", handler=finish)
        client = TestClient(app, follow_redirects=False)

        started = client.get("/auth/google/redirect?next=/settings/billing")
        finished = client.get(
            f"/auth/google/callback?code=test-code&state={state_from(started)}"
        )

        assert finished.headers["location"] == "/settings/billing"


class TestCallbackRejections:
    """What a real callback endpoint does with a bad request."""

    @pytest.fixture
    def client(self, google) -> TestClient:
        app = session_app()

        async def start(request, response):
            authorize = authorize_url(google)
            return response.redirect(authorize.url).set_cookie(
                **authorize.cookie_kwargs(secure=False)
            )

        async def finish(request, response):
            try:
                profile = await exchange(google, request)
            except OAuthError as exc:
                return response.json({"error": exc.code}, status_code=400)
            login(request, SimpleUser(profile.key))
            return response.json({"identity": profile.key})

        app.get("/auth/google/redirect", handler=start)
        app.get("/auth/google/callback", handler=finish)
        app.get("/me", handler=lambda r, s: s.json({"ok": True}), auth=useAuth())
        return TestClient(app, follow_redirects=False)

    def test_callback_without_a_prior_redirect_is_rejected(self, client):
        """No state cookie was ever issued to this browser."""
        response = client.get("/auth/google/callback?code=c&state=made-up")

        assert response.status_code == 400
        assert response.json() == {"error": "state_mismatch"}

    def test_callback_with_a_stolen_code_but_no_cookie_is_rejected(self, google, stub):
        """The CSRF property, stated as an attack.

        One browser starts a login; a second browser replays the resulting
        callback URL. Without the first browser's cookie the callback is
        useless, which is the whole point of the state value.
        """
        app = session_app()

        async def start(request, response):
            authorize = authorize_url(google)
            return response.redirect(authorize.url).set_cookie(
                **authorize.cookie_kwargs(secure=False)
            )

        async def finish(request, response):
            try:
                await exchange(google, request)
            except OAuthError as exc:
                return response.json({"error": exc.code}, status_code=400)
            return response.json({"ok": True})

        app.get("/auth/google/redirect", handler=start)
        app.get("/auth/google/callback", handler=finish)

        victim = TestClient(app, follow_redirects=False)
        attacker = TestClient(app, follow_redirects=False)

        started = victim.get("/auth/google/redirect")
        replayed = attacker.get(
            f"/auth/google/callback?code=test-code&state={state_from(started)}"
        )

        assert replayed.status_code == 400
        assert replayed.json() == {"error": "state_mismatch"}

    def test_rejected_callback_never_reaches_the_provider(self, client, stub):
        client.get("/auth/google/callback?code=c&state=made-up")

        assert stub.requests == []

    def test_denied_consent_is_reported_as_denial(self, client):
        response = client.get("/auth/google/callback?error=access_denied")

        assert response.json() == {"error": "denied"}

    def test_provider_error_is_reported_separately(self, client):
        response = client.get("/auth/google/callback?error=invalid_scope")

        assert response.json() == {"error": "provider_error"}

    def test_tampered_state_cookie_is_rejected(self, client):
        started = client.get("/auth/google/redirect")
        client.cookies.set("oauth_state_google", "forged.value")

        response = client.get(
            f"/auth/google/callback?code=test-code&state={state_from(started)}"
        )

        assert response.json() == {"error": "state_mismatch"}

    def test_a_rejected_callback_leaves_the_caller_anonymous(self, client):
        client.get("/auth/google/callback?code=c&state=made-up")

        assert client.get("/me").status_code == 401

    def test_token_failure_surfaces_as_its_own_code(self, client, stub):
        started = client.get("/auth/google/redirect")
        stub.route(GoogleOAuthProvider.token_endpoint, json={"error": "invalid_grant"})

        response = client.get(
            f"/auth/google/callback?code=test-code&state={state_from(started)}"
        )

        assert response.json() == {"error": "exchange_failed"}


class TestJWTLogin:
    """The same flow, persisting a token instead of a session.

    Nothing in the OAuth step changes — only the four lines after
    ``exchange`` — which is what keeping persistence out of this package
    buys.
    """

    @pytest.fixture
    def client(self, google) -> TestClient:
        app = silloApp()
        app.use(
            AuthenticationMiddleware(
                user_model=SimpleUser,
                backend=[JWTAuthBackend(secret_key=JWT_SECRET, check_blacklist=False)],
            )
        )

        async def start(request, response):
            authorize = authorize_url(google)
            return response.redirect(authorize.url).set_cookie(
                **authorize.cookie_kwargs(secure=False)
            )

        async def finish(request, response):
            profile = await exchange(google, request)
            # No session anywhere in this app.
            token = create_jwt({"id": profile.key}, JWT_SECRET)
            return response.json({"access_token": token})

        async def me(request, response):
            return response.json({"identity": request.user.identity})

        app.get("/auth/google/redirect", handler=start)
        app.get("/auth/google/callback", handler=finish)
        app.get("/me", handler=me, auth=useAuth(schemes=["bearerAuth"]))
        return TestClient(app, follow_redirects=False)

    def test_callback_returns_a_token_instead_of_redirecting(self, client):
        started = client.get("/auth/google/redirect")

        finished = client.get(
            f"/auth/google/callback?code=test-code&state={state_from(started)}"
        )

        assert finished.status_code == 200
        assert finished.json()["access_token"]

    def test_the_token_authenticates_the_protected_route(self, client):
        started = client.get("/auth/google/redirect")
        token = client.get(
            f"/auth/google/callback?code=test-code&state={state_from(started)}"
        ).json()["access_token"]

        response = client.get("/me", headers={"Authorization": f"Bearer {token}"})

        assert response.status_code == 200
        assert response.json() == {"identity": "google:google-subject-1"}

    def test_no_token_means_no_access(self, client):
        assert client.get("/me").status_code == 401

    def test_a_forged_token_is_refused(self, client):
        forged = create_jwt({"id": "google:someone-else"}, "not-the-secret")

        response = client.get("/me", headers={"Authorization": f"Bearer {forged}"})

        assert response.status_code == 401

    def test_the_state_cookie_still_gates_the_callback(self, client):
        """PKCE and state apply regardless of how identity is persisted."""
        response = client.get("/auth/google/callback?code=c&state=made-up")

        assert response.status_code == 401 or response.status_code >= 400


class TestNoPersistence:
    """OAuth used only to verify an identity, with no login at all."""

    def test_callback_can_simply_return_the_profile(self, google, stub):
        app = silloApp()

        async def start(request, response):
            authorize = authorize_url(google)
            return response.redirect(authorize.url).set_cookie(
                **authorize.cookie_kwargs(secure=False)
            )

        async def finish(request, response):
            profile = await exchange(google, request)
            return response.json(
                {"email": profile.email, "verified": profile.email_verified}
            )

        app.get("/verify/redirect", handler=start)
        app.get("/verify/callback", handler=finish)
        client = TestClient(app, follow_redirects=False)

        started = client.get("/verify/redirect")
        finished = client.get(
            f"/verify/callback?code=test-code&state={state_from(started)}"
        )

        assert finished.json() == {"email": "ada@example.com", "verified": True}
        # No session middleware, no auth middleware, no user model.
        assert "session" not in finished.headers.get("set-cookie", "")


class TestAccountLinking:
    """Connecting a second provider to an already-authenticated user."""

    def test_linking_keeps_the_current_user(self, stub):
        github_stub = ProviderStub()
        google = make_provider(stub)
        github = make_provider(
            github_stub,
            cls=GithubOAuthProvider,
            userinfo={"id": 4242, "login": "ada", "email": "ada@example.com"},
        )
        links: dict[str, str] = {}

        app = session_app()

        async def google_start(request, response):
            authorize = authorize_url(google)
            return response.redirect(authorize.url).set_cookie(
                **authorize.cookie_kwargs(secure=False)
            )

        async def google_finish(request, response):
            profile = await exchange(google, request)
            login(request, SimpleUser(profile.key))
            return response.json({"identity": profile.key})

        async def github_start(request, response):
            authorize = authorize_url(github)
            return response.redirect(authorize.url).set_cookie(
                **authorize.cookie_kwargs(secure=False)
            )

        async def github_finish(request, response):
            profile = await exchange(github, request)
            if not request.user.is_authenticated:
                return response.json({"error": "not_logged_in"}, status_code=401)
            # Linked to the *current* user, not to a newly matched one.
            links[request.user.identity] = profile.key
            return response.json({"linked": profile.key})

        app.get("/auth/google/redirect", handler=google_start)
        app.get("/auth/google/callback", handler=google_finish)
        app.get("/settings/connect/github", handler=github_start)
        app.get("/settings/connect/github/callback", handler=github_finish)
        client = TestClient(app, follow_redirects=False)

        started = client.get("/auth/google/redirect")
        client.get(f"/auth/google/callback?code=test-code&state={state_from(started)}")

        linking = client.get("/settings/connect/github")
        result = client.get(
            "/settings/connect/github/callback"
            f"?code=test-code&state={state_from(linking)}"
        )

        assert result.json() == {"linked": "github:4242"}
        assert links == {"google:google-subject-1": "github:4242"}

    def test_linking_is_refused_when_not_logged_in(self, stub):
        github_stub = ProviderStub()
        github = make_provider(
            github_stub,
            cls=GithubOAuthProvider,
            userinfo={"id": 4242, "login": "ada", "email": "ada@example.com"},
        )
        app = session_app()

        async def start(request, response):
            authorize = authorize_url(github)
            return response.redirect(authorize.url).set_cookie(
                **authorize.cookie_kwargs(secure=False)
            )

        async def finish(request, response):
            await exchange(github, request)
            if not request.user.is_authenticated:
                return response.json({"error": "not_logged_in"}, status_code=401)
            return response.json({"linked": True})

        app.get("/connect/github", handler=start)
        app.get("/connect/github/callback", handler=finish)
        client = TestClient(app, follow_redirects=False)

        started = client.get("/connect/github")
        result = client.get(
            f"/connect/github/callback?code=test-code&state={state_from(started)}"
        )

        assert result.status_code == 401


class TestMultipleProviders:
    """Two logins in flight at once must not interfere."""

    def test_each_provider_gets_its_own_state_cookie(self, stub):
        github_stub = ProviderStub()
        google = make_provider(stub)
        github = make_provider(
            github_stub,
            cls=GithubOAuthProvider,
            userinfo={"id": 4242, "login": "ada", "email": "ada@example.com"},
        )
        app = session_app()

        async def google_start(request, response):
            authorize = authorize_url(google)
            return response.redirect(authorize.url).set_cookie(
                **authorize.cookie_kwargs(secure=False)
            )

        async def github_start(request, response):
            authorize = authorize_url(github)
            return response.redirect(authorize.url).set_cookie(
                **authorize.cookie_kwargs(secure=False)
            )

        async def google_finish(request, response):
            profile = await exchange(google, request)
            return response.json({"key": profile.key})

        async def github_finish(request, response):
            profile = await exchange(github, request)
            return response.json({"key": profile.key})

        app.get("/auth/google/redirect", handler=google_start)
        app.get("/auth/google/callback", handler=google_finish)
        app.get("/auth/github/redirect", handler=github_start)
        app.get("/auth/github/callback", handler=github_finish)
        client = TestClient(app, follow_redirects=False)

        # Both logins started before either completes, as two browser tabs.
        google_started = client.get("/auth/google/redirect")
        github_started = client.get("/auth/github/redirect")

        assert "oauth_state_google" in client.cookies
        assert "oauth_state_github" in client.cookies

        google_done = client.get(
            f"/auth/google/callback?code=c1&state={state_from(google_started)}"
        )
        github_done = client.get(
            f"/auth/github/callback?code=c2&state={state_from(github_started)}"
        )

        assert google_done.json() == {"key": "google:google-subject-1"}
        assert github_done.json() == {"key": "github:4242"}


class TestCookieMechanics:
    """Framework details that silently break the flow when got wrong."""

    def test_secure_cookie_is_not_returned_over_http(self, google):
        """Why the tests pass ``secure=False`` and localhost dev must too.

        The browser accepts a ``Secure`` cookie over http and then never
        sends it back, so the callback fails as a state mismatch with nothing
        obviously wrong at the redirect step.
        """
        app = silloApp()

        async def start(request, response):
            authorize = authorize_url(google)
            return response.redirect(authorize.url).set_cookie(
                **authorize.cookie_kwargs()  # secure=True by default
            )

        async def finish(request, response):
            try:
                await exchange(google, request)
            except OAuthError as exc:
                return response.json({"error": exc.code}, status_code=400)
            return response.json({"ok": True})

        app.get("/auth/google/redirect", handler=start)
        app.get("/auth/google/callback", handler=finish)
        client = TestClient(app, follow_redirects=False)

        started = client.get("/auth/google/redirect")
        assert "Secure" in started.headers["set-cookie"]

        result = client.get(
            f"/auth/google/callback?code=test-code&state={state_from(started)}"
        )

        assert result.json() == {"error": "state_mismatch"}

    def test_setting_the_cookie_before_the_redirect_raises(self, google):
        """``Responder`` has nothing to attach a cookie to until then.

        Pinned as a test because the natural reading order — set the cookie,
        then redirect — is the one that fails.
        """
        app = silloApp()

        async def start(request, response):
            authorize = authorize_url(google)
            response.set_cookie(**authorize.cookie_kwargs(secure=False))
            return response.redirect(authorize.url)

        app.get("/auth/google/redirect", handler=start)
        client = TestClient(app, raise_server_exceptions=False)

        assert client.get("/auth/google/redirect").status_code == 500
