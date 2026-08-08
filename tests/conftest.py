"""Shared fixtures.

Two rules hold across the whole suite:

* **No real credentials.** Every client id, secret and token below is a fixed
  literal invented for these tests. Nothing reads the environment, so the
  suite behaves identically on a laptop with OAuth apps configured and on CI
  with nothing configured.

* **No network, enforced rather than intended.** The ``no_network`` fixture is
  autouse and breaks httpx's real transport, so a test that forgets to inject
  a stub fails loudly instead of quietly reaching out to Google. Every
  provider under test gets an :class:`ProviderStub` transport.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from sillo_oauth import GoogleOAuthProvider, OAuthProvider

#: Fixed, obviously-fake credentials.
CLIENT_ID = "test-client-id"
CLIENT_SECRET = "test-client-secret"
STATE_SECRET = "test-state-secret-not-a-real-key"
REDIRECT_URI = "https://app.test/auth/callback"
ACCESS_TOKEN = "test-access-token"


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make any real outbound HTTP request fail the test.

    This is the guarantee that the suite never needs a live provider: a test
    that reaches the network has misconfigured its stub, and should say so
    rather than pass slowly or fail on a plane.
    """

    async def _refuse(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError(
            "A test tried to make a real network request. Inject a stub "
            "transport instead."
        )

    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", _refuse)


class ProviderStub:
    """A canned OAuth provider, served over an ``httpx`` mock transport.

    Routes are matched on scheme + host + path, ignoring the query string, so
    a test registers ``https://api.test/user`` once and does not care what
    parameters the code under test appends.

    Attributes:
        requests: Every request the code under test made, in order.
    """

    def __init__(self) -> None:
        self._routes: dict[str, httpx.Response] = {}
        self.requests: list[httpx.Request] = []

    @staticmethod
    def _key(url: str | httpx.URL) -> str:
        parts = urlsplit(str(url))
        return f"{parts.scheme}://{parts.netloc}{parts.path}"

    def route(
        self,
        url: str,
        *,
        json: Any = None,
        text: str | None = None,
        status: int = 200,
        content_type: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProviderStub:
        """Register the response for one endpoint.

        Args:
            url: Endpoint URL; only scheme, host and path are matched.
            json: Body to serialise as JSON. Mutually exclusive with *text*.
            text: Raw body, for testing form-encoded and malformed responses.
            status: HTTP status to return.
            content_type: Overrides the header httpx would infer, so a test
                can serve JSON with no content type, or a form-encoded body.
            headers: Extra response headers.

        Returns:
            ``self``, so routes can be chained.
        """
        response_headers = dict(headers or {})
        if content_type is not None:
            response_headers["content-type"] = content_type

        if text is not None:
            response = httpx.Response(status, text=text, headers=response_headers)
        else:
            response = httpx.Response(status, json=json, headers=response_headers)
            if content_type is not None:
                response.headers["content-type"] = content_type

        self._routes[self._key(url)] = response
        return self

    def fail(self, url: str, exc: Exception | None = None) -> ProviderStub:
        """Make an endpoint raise a transport error.

        Args:
            url: Endpoint URL to break.
            exc: Exception to raise. Defaults to a connect error, the usual
                shape of "the provider is down".

        Returns:
            ``self``.
        """
        self._routes[self._key(url)] = exc or httpx.ConnectError("connection refused")
        return self

    @property
    def transport(self) -> httpx.MockTransport:
        """An ``httpx`` transport serving the registered routes."""

        def handler(request: httpx.Request) -> httpx.Response:
            self.requests.append(request)
            match = self._routes.get(self._key(request.url))
            if match is None:
                raise AssertionError(f"No stub registered for {request.url}")
            if isinstance(match, Exception):
                raise match
            # Rebuilt per call so a route can be hit twice without the
            # response stream being consumed the second time.
            return httpx.Response(
                match.status_code, content=match.content, headers=match.headers
            )

        return httpx.MockTransport(handler)

    def request_to(self, url: str) -> httpx.Request:
        """The last request made to an endpoint.

        Args:
            url: Endpoint URL.

        Returns:
            The recorded request.

        Raises:
            AssertionError: If nothing was sent there.
        """
        key = self._key(url)
        for request in reversed(self.requests):
            if self._key(request.url) == key:
                return request
        raise AssertionError(f"No request was made to {url}")

    def form_to(self, url: str) -> dict[str, str]:
        """The form body last posted to an endpoint, flattened.

        Args:
            url: Endpoint URL.

        Returns:
            Field names mapped to their single values.
        """
        body = self.request_to(url).content.decode()
        return {key: values[0] for key, values in parse_qs(body).items()}


@pytest.fixture
def stub() -> ProviderStub:
    """An empty provider stub for a test to route as it needs."""
    return ProviderStub()


@pytest.fixture
def google(stub: ProviderStub) -> GoogleOAuthProvider:
    """A Google provider wired to the stub, with the happy path routed."""
    stub.route(
        GoogleOAuthProvider.token_endpoint,
        json={
            "access_token": ACCESS_TOKEN,
            "token_type": "Bearer",
            "expires_in": 3599,
            "scope": "openid email profile",
            "id_token": "test-id-token",
        },
    )
    stub.route(
        GoogleOAuthProvider.userinfo_endpoint,
        json={
            "sub": "google-subject-1",
            "email": "ada@example.com",
            "email_verified": True,
            "name": "Ada Lovelace",
            "picture": "https://cdn.test/ada.png",
        },
    )
    return GoogleOAuthProvider(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        state_secret=STATE_SECRET,
        redirect_uri=REDIRECT_URI,
        transport=stub.transport,
    )


@pytest.fixture
def generic(stub: ProviderStub) -> OAuthProvider:
    """A provider with no shipped subclass, exercising the base behaviour."""
    return OAuthProvider(
        name="acme",
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        state_secret=STATE_SECRET,
        redirect_uri=REDIRECT_URI,
        authorize_endpoint="https://acme.test/oauth/authorize",
        token_endpoint="https://acme.test/oauth/token",
        userinfo_endpoint="https://acme.test/api/me",
        scopes=["read"],
        transport=stub.transport,
    )
