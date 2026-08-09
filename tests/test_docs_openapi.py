"""Every OpenAPI claim the OAuth documentation makes, executed.

The guides under ``guides/oauth/`` describe what a sillo application publishes
under ``components.securitySchemes`` and what each route's ``security``
becomes after a login. None of that is written by hand — it is derived from
the backends and the ``useAuth`` gate — so prose describing it goes stale the
moment the builder changes, silently, in a place nobody runs.

These tests are the contract. Each asserts the exact JSON a reader would see
at ``/openapi.json``, so a change in core that contradicts the documentation
fails here rather than in someone's integration.

They need no network and no credentials: the document is generated from route
registration alone, and the one test that completes a login uses the stubbed
provider from ``conftest``.
"""

from __future__ import annotations

import pytest
from conftest import ACCESS_TOKEN, CLIENT_ID, CLIENT_SECRET, STATE_SECRET, ProviderStub
from sillo import silloApp
from sillo.auth import useAuth
from sillo.auth.jwt_auth import JWTAuthBackend
from sillo.auth.session_auth import SessionAuthBackend
from sillo.openapi.models import OAuth2, OAuthFlowAuthorizationCode, OAuthFlows
from sillo.session import SessionMiddleware
from sillo.testclient import TestClient
from sillo.users import SimpleUser

from sillo_oauth import GoogleOAuthProvider, authorize_url, exchange

JWT_SECRET = "docs-jwt-secret-padded-to-32-bytes-plus"
SESSION_SECRET = "docs-session-secret-padded-to-32-bytes"


async def ok(request, response):
    """A handler that does nothing but succeed."""
    return response.json({"ok": True})


def build_app(**kwargs) -> silloApp:
    """An app with both shipped backends declared through ``auth=``.

    This is the wiring the docs recommend: backends go to the constructor, not
    to ``app.use``, because that is what publishes their schemes.
    """
    kwargs.setdefault("title", "OAuth demo")
    kwargs.setdefault("version", "1.0.0")
    kwargs.setdefault(
        "auth",
        [
            JWTAuthBackend(
                secret_key=JWT_SECRET,
                check_blacklist=False,
                description="Issued by /auth/google/callback.",
            ),
            SessionAuthBackend(description="Set by /auth/google/callback."),
        ],
    )
    kwargs.setdefault("auth_user_model", SimpleUser)
    return silloApp(**kwargs)


def document(app: silloApp) -> dict:
    """The document a reader actually gets."""
    return TestClient(app).get("/openapi.json").json()


def security_of(doc: dict, path: str, verb: str = "get"):
    """The ``security`` a single operation declares."""
    return doc["paths"][path][verb].get("security")


class TestPublishedSchemes:
    """What ``silloApp(auth=[...])`` puts under components.securitySchemes."""

    def test_jwt_backend_publishes_http_bearer(self):
        app = build_app()

        schemes = document(app)["components"]["securitySchemes"]

        assert schemes["bearerAuth"] == {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "Issued by /auth/google/callback.",
        }

    def test_session_backend_publishes_the_cookie_it_rides_on(self):
        app = build_app()

        schemes = document(app)["components"]["securitySchemes"]

        assert schemes["sessionCookie"] == {
            "type": "apiKey",
            "in": "cookie",
            "name": "session_id",
            "description": "Set by /auth/google/callback.",
        }

    def test_schemes_are_keyed_by_backend_name(self):
        app = build_app()

        assert set(document(app)["components"]["securitySchemes"]) == {
            "bearerAuth",
            "sessionCookie",
        }

    def test_description_is_how_a_reader_learns_where_the_token_comes_from(self):
        """The docs tell people to set it; this proves it reaches the page."""
        app = build_app()

        schemes = document(app)["components"]["securitySchemes"]

        assert "/auth/google/callback" in schemes["bearerAuth"]["description"]

    def test_cookie_name_must_match_the_session_config(self):
        """The document names the cookie a caller has to send."""
        app = build_app(
            auth=[SessionAuthBackend(cookie_name="my_session")],
            auth_user_model=SimpleUser,
        )

        schemes = document(app)["components"]["securitySchemes"]

        assert schemes["sessionCookie"]["name"] == "my_session"

    def test_an_app_declaring_no_backends_still_advertises_bearer_auth(self):
        """A legacy default worth knowing about before trusting a document.

        An application that never declared a backend still publishes
        ``bearerAuth``, so an empty app's document claims a credential it has
        no basis for.
        """
        app = silloApp(title="t", version="1.0.0")
        app.get("/me", handler=ok, auth=useAuth())

        doc = document(app)

        assert set(doc["components"]["securitySchemes"]) == {"bearerAuth"}
        assert security_of(doc, "/me") == [{"bearerAuth": []}]

    def test_app_use_middleware_documents_the_wrong_credential(self):
        """Why the docs say to declare backends through ``auth=``.

        Installing the middleware by hand authenticates requests perfectly
        well, but registers no scheme — so the document falls back to the
        legacy ``bearerAuth`` default. A session-only app wired this way
        advertises a bearer token it never reads and stays silent about the
        cookie it does, which is a documentation bug no test of the app's
        behaviour would catch.
        """
        from sillo.auth import AuthenticationMiddleware

        app = silloApp(title="t", version="1.0.0")
        app.use(
            AuthenticationMiddleware(
                user_model=SimpleUser, backend=[SessionAuthBackend()]
            )
        )
        app.get("/dash", handler=ok, auth=useAuth())

        doc = document(app)
        schemes = doc["components"]["securitySchemes"]

        assert "sessionCookie" not in schemes, "the credential it actually reads"
        assert schemes["bearerAuth"]["scheme"] == "bearer", "one it never reads"
        assert security_of(doc, "/dash") == [{"bearerAuth": []}]


class TestDerivedSecurity:
    """The gate is written once; the document follows from it."""

    @pytest.fixture
    def doc(self) -> dict:
        app = build_app()
        app.get("/public", handler=ok)
        app.get("/me", handler=ok, auth=useAuth())
        app.get("/api/me", handler=ok, auth=useAuth(schemes=["bearerAuth"]))
        app.get("/dash", handler=ok, auth=useAuth(schemes=["sessionCookie"]))
        app.get(
            "/either", handler=ok, auth=useAuth(schemes=["bearerAuth", "sessionCookie"])
        )
        app.get(
            "/both",
            handler=ok,
            auth=useAuth(schemes=["bearerAuth", "sessionCookie"], all_of=True),
        )
        app.get("/optional", handler=ok, auth=useAuth(required=False))
        app.get("/perm", handler=ok, auth=useAuth(permissions=["admin"]))
        return document(app)

    def test_ungated_route_declares_no_security(self, doc):
        assert security_of(doc, "/public") is None

    def test_bare_gate_accepts_any_registered_scheme(self, doc):
        """A bare ``useAuth()`` rejects anonymous callers but names nothing.

        Documenting it as public would be the more dangerous lie: a consumer
        reads "no auth needed" and is refused.
        """
        assert security_of(doc, "/me") == [{"bearerAuth": []}, {"sessionCookie": []}]

    def test_single_scheme(self, doc):
        assert security_of(doc, "/api/me") == [{"bearerAuth": []}]
        assert security_of(doc, "/dash") == [{"sessionCookie": []}]

    def test_several_schemes_are_alternatives(self, doc):
        """Separate objects mean "any one of these"."""
        assert security_of(doc, "/either") == [
            {"bearerAuth": []},
            {"sessionCookie": []},
        ]

    def test_all_of_is_one_object_with_several_keys(self, doc):
        """One object with two keys means "both together"."""
        assert security_of(doc, "/both") == [{"bearerAuth": [], "sessionCookie": []}]

    def test_optional_auth_adds_an_empty_requirement(self, doc):
        """``{}`` is OpenAPI's spelling of "authentication is optional"."""
        assert security_of(doc, "/optional") == [
            {"bearerAuth": []},
            {"sessionCookie": []},
            {},
        ]

    def test_permissions_do_not_reach_the_document(self, doc):
        """Authorization has no OpenAPI field, so it cannot be expressed."""
        assert security_of(doc, "/perm") == [{"bearerAuth": []}, {"sessionCookie": []}]


class TestLegacyScopeLabels:
    """The trap the docs warn about, pinned in both directions."""

    def test_a_legacy_label_still_gates_correctly(self):
        """``schemes=["jwt"]`` keeps working at runtime."""
        from sillo.auth.jwt_auth import create_jwt

        app = build_app()
        app.get("/legacy", handler=ok, auth=useAuth(schemes=["jwt"]))
        client = TestClient(app)

        token = create_jwt({"id": "1"}, JWT_SECRET)
        assert client.get("/legacy").status_code == 401
        assert (
            client.get(
                "/legacy", headers={"Authorization": f"Bearer {token}"}
            ).status_code
            == 200
        )

    def test_but_it_writes_a_scheme_the_document_never_defines(self):
        """Which is why the docs say to write the scheme name instead.

        The gate accepts "jwt" as an alias, but the document has no such
        scheme, so a viewer renders an authorize box wired to nothing.
        """
        app = build_app()
        app.get("/legacy", handler=ok, auth=useAuth(schemes=["jwt"]))

        doc = document(app)
        declared = {
            name for requirement in security_of(doc, "/legacy") for name in requirement
        }
        defined = set(doc["components"]["securitySchemes"])

        assert declared == {"jwt"}
        assert declared - defined == {"jwt"}, "dangling reference"

    def test_strict_security_refuses_to_build_that_document(self):
        """The recommended setting turns the silent lie into a startup error."""
        app = build_app(strict_security=True)
        app.get("/legacy", handler=ok, auth=useAuth(schemes=["jwt"]))

        with pytest.raises(ValueError, match="not registered"):
            app.build_openapi()

    def test_the_error_names_the_route_and_the_registered_schemes(self):
        app = build_app(strict_security=True)
        app.get("/legacy", handler=ok, auth=useAuth(schemes=["jwt"]))

        with pytest.raises(ValueError) as caught:
            app.build_openapi()

        message = str(caught.value)
        assert "/legacy requires 'jwt'" in message
        assert "bearerAuth" in message

    def test_the_scheme_name_passes_strict_security(self):
        app = build_app(strict_security=True)
        app.get("/api/me", handler=ok, auth=useAuth(schemes=["bearerAuth"]))

        assert security_of(document(app), "/api/me") == [{"bearerAuth": []}]


class TestOAuthRoutesInTheDocument:
    """The redirect and callback endpoints themselves."""

    def test_excluded_routes_do_not_appear(self):
        """The docs suggest hiding them; this is what that does."""
        app = build_app()
        app.get("/auth/google/redirect", handler=ok, exclude_from_schema=True)
        app.get("/auth/google/callback", handler=ok, exclude_from_schema=True)
        app.get("/me", handler=ok, auth=useAuth())

        paths = document(app)["paths"]

        assert "/auth/google/redirect" not in paths
        assert "/auth/google/callback" not in paths
        assert "/me" in paths

    def test_included_oauth_routes_document_as_public(self):
        """They must be, or the browser could never reach them."""
        app = build_app()
        app.get("/auth/google/redirect", handler=ok)

        assert security_of(document(app), "/auth/google/redirect") is None

    def test_gating_them_would_be_a_mistake(self):
        """Stated as a test so the reasoning in the docs is checkable."""
        app = build_app()
        app.get("/auth/google/callback", handler=ok, auth=useAuth())

        assert TestClient(app).get("/auth/google/callback?code=c").status_code == 401


class TestCustomOAuth2Scheme:
    """Publishing the OAuth2 flow itself, for a Swagger authorize button."""

    AUTHORIZE = "https://accounts.google.com/o/oauth2/v2/auth"
    TOKEN = "https://oauth2.googleapis.com/token"

    def scheme(self) -> OAuth2:
        return OAuth2(
            description="Sign in with Google.",
            flows=OAuthFlows(
                authorizationCode=OAuthFlowAuthorizationCode(
                    authorizationUrl=self.AUTHORIZE,
                    tokenUrl=self.TOKEN,
                    scopes={"openid": "Sign in", "email": "Email address"},
                )
            ),
        )

    def test_a_registered_oauth2_scheme_reaches_the_document(self):
        app = build_app()
        app.openapi_config.add_security_scheme("googleOAuth", self.scheme())

        published = document(app)["components"]["securitySchemes"]["googleOAuth"]

        assert published["type"] == "oauth2"
        assert (
            published["flows"]["authorizationCode"]["authorizationUrl"]
            == self.AUTHORIZE
        )
        assert published["flows"]["authorizationCode"]["scopes"] == {
            "openid": "Sign in",
            "email": "Email address",
        }

    def test_the_mapping_form_carries_oauth2_scopes_onto_the_route(self):
        app = build_app()
        app.openapi_config.add_security_scheme("googleOAuth", self.scheme())
        app.get(
            "/scoped",
            handler=ok,
            auth=useAuth(schemes={"googleOAuth": ["openid", "email"]}),
        )

        assert security_of(document(app), "/scoped") == [
            {"googleOAuth": ["openid", "email"]}
        ]

    def test_registering_the_scheme_alone_does_not_make_the_gate_accept_it(self):
        """The trap the docs spell out.

        A scheme in the document is just prose. The gate matches on what a
        backend *reports*, and no shipped backend calls itself googleOAuth,
        so this route refuses every caller including a valid JWT.
        """
        from sillo.auth.jwt_auth import create_jwt

        app = build_app()
        app.openapi_config.add_security_scheme("googleOAuth", self.scheme())
        app.get("/scoped", handler=ok, auth=useAuth(schemes=["googleOAuth"]))

        token = create_jwt({"id": "1"}, JWT_SECRET)
        response = TestClient(app).get(
            "/scoped", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 401

    def test_naming_the_backend_makes_gate_and_document_agree(self):
        """The fix: the backend must report the name the document defines."""
        from sillo.auth.jwt_auth import create_jwt

        scheme = self.scheme()

        class GoogleTokenBackend(JWTAuthBackend):
            name = "googleOAuth"

            def describe(self):
                return scheme

        app = silloApp(
            title="t",
            version="1.0.0",
            auth=[GoogleTokenBackend(secret_key=JWT_SECRET, check_blacklist=False)],
            auth_user_model=SimpleUser,
            strict_security=True,
        )
        app.get("/scoped", handler=ok, auth=useAuth(schemes=["googleOAuth"]))
        client = TestClient(app)

        doc = client.get("/openapi.json").json()
        assert doc["components"]["securitySchemes"]["googleOAuth"]["type"] == "oauth2"
        assert security_of(doc, "/scoped") == [{"googleOAuth": []}]

        token = create_jwt({"id": "1"}, JWT_SECRET)
        assert (
            client.get(
                "/scoped", headers={"Authorization": f"Bearer {token}"}
            ).status_code
            == 200
        )


class TestTwoBackendsOneName:
    """Why the docs tell you to name a second backend of the same kind."""

    def test_conflicting_definitions_are_refused(self):
        with pytest.raises(ValueError, match="both claim the scheme"):
            silloApp(
                title="t",
                version="1.0.0",
                auth=[
                    JWTAuthBackend(secret_key="a" * 40, description="user tokens"),
                    JWTAuthBackend(secret_key="b" * 40, description="admin tokens"),
                ],
                auth_user_model=SimpleUser,
            )

    def test_giving_one_a_distinct_name_resolves_it(self):
        app = silloApp(
            title="t",
            version="1.0.0",
            auth=[
                JWTAuthBackend(secret_key="a" * 40, description="user tokens"),
                JWTAuthBackend(
                    secret_key="b" * 40, name="adminAuth", description="admin tokens"
                ),
            ],
            auth_user_model=SimpleUser,
        )

        assert set(document(app)["components"]["securitySchemes"]) == {
            "bearerAuth",
            "adminAuth",
        }


class TestDocumentedFlowEndToEnd:
    """The quickstart, run: login through OAuth, then use the documented gate.

    Proves the two halves fit — that the credential the document advertises is
    the one the OAuth callback actually issues.
    """

    def test_session_login_then_a_documented_route(self):
        from sillo.auth.session_auth import login

        stub = ProviderStub()
        stub.route(
            GoogleOAuthProvider.token_endpoint, json={"access_token": ACCESS_TOKEN}
        )
        stub.route(
            GoogleOAuthProvider.userinfo_endpoint,
            json={
                "sub": "google-1",
                "email": "ada@example.com",
                "email_verified": True,
            },
        )
        google = GoogleOAuthProvider(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            state_secret=STATE_SECRET,
            redirect_uri="http://testserver/auth/google/callback",
            transport=stub.transport,
        )

        app = build_app(strict_security=True)
        app.use(
            SessionMiddleware(secret_key=SESSION_SECRET, session_cookie_secure=False)
        )

        async def start(request, response):
            authorize = authorize_url(google)
            return response.redirect(authorize.url).set_cookie(
                **authorize.cookie_kwargs(secure=False)
            )

        async def finish(request, response):
            profile = await exchange(google, request)
            login(request, SimpleUser(profile.key))
            return response.json({"key": profile.key})

        async def me(request, response):
            return response.json({"identity": request.user.identity})

        app.get("/auth/google/redirect", handler=start, exclude_from_schema=True)
        app.get("/auth/google/callback", handler=finish, exclude_from_schema=True)
        app.get("/me", handler=me, auth=useAuth(schemes=["sessionCookie"]))

        client = TestClient(app, follow_redirects=False)

        # The document advertises exactly the credential the flow issues.
        doc = client.get("/openapi.json").json()
        assert security_of(doc, "/me") == [{"sessionCookie": []}]
        assert "/auth/google/callback" not in doc["paths"]

        assert client.get("/me").status_code == 401

        from urllib.parse import parse_qs, urlsplit

        started = client.get("/auth/google/redirect")
        state = parse_qs(urlsplit(started.headers["location"]).query)["state"][0]
        client.get(f"/auth/google/callback?code=test-code&state={state}")

        assert client.get("/me").json() == {"identity": "google:google-1"}
