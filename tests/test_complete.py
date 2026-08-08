"""The callback step end to end, without a request object.

``complete`` is what ``exchange`` reduces to once the query parameters and the
cookie have been read off a request. Testing it directly keeps the ordering
guarantees — especially "verify state before talking to the provider" —
provable without a web server in the way.
"""

from __future__ import annotations

import pytest
from conftest import ACCESS_TOKEN, STATE_SECRET

from sillo_oauth import (
    GoogleOAuthProvider,
    OAuthDenied,
    OAuthError,
    ProviderMisconfigured,
    ProviderRejected,
    StateExpired,
    StateMismatch,
    TokenExchangeFailed,
    authorize_url,
    complete,
    derive_verifier,
    issue_state,
)

TOKEN_URL = GoogleOAuthProvider.token_endpoint
USERINFO_URL = GoogleOAuthProvider.userinfo_endpoint


async def run(provider, *, code="test-code", **kwargs):
    """Start a login and complete it, threading the state through."""
    started = authorize_url(provider, return_to=kwargs.pop("return_to", None))
    return await complete(
        provider,
        code=code,
        state=kwargs.pop("state", started.state),
        cookie_value=kwargs.pop("cookie_value", started.cookie_value),
        **kwargs,
    )


class TestHappyPath:
    """A login that works."""

    async def test_returns_a_profile(self, google):
        profile = await run(google)

        assert profile.provider == "google"
        assert profile.subject == "google-subject-1"
        assert profile.email == "ada@example.com"

    async def test_attaches_the_tokens(self, google):
        profile = await run(google)

        assert profile.tokens is not None
        assert profile.tokens.access_token == ACCESS_TOKEN

    async def test_carries_return_to_back(self, google):
        profile = await run(google, return_to="/dashboard")

        assert profile.return_to == "/dashboard"

    async def test_return_to_is_none_when_not_set(self, google):
        assert (await run(google)).return_to is None

    async def test_calls_both_endpoints_in_order(self, google, stub):
        await run(google)

        called = [str(request.url).split("?")[0] for request in stub.requests]
        assert called == [TOKEN_URL, USERINFO_URL]

    async def test_sends_the_derived_pkce_verifier(self, google, stub):
        """The verifier must match the challenge sent at the redirect step."""
        started = authorize_url(google)

        await complete(
            google,
            code="test-code",
            state=started.state,
            cookie_value=started.cookie_value,
        )

        expected = derive_verifier(started.state, STATE_SECRET)
        assert stub.form_to(TOKEN_URL)["code_verifier"] == expected


class TestProviderReportedErrors:
    """The provider redirected back with an ``error`` instead of a code."""

    async def test_access_denied_is_a_refusal_not_a_fault(self, google):
        with pytest.raises(OAuthDenied) as caught:
            await complete(
                google,
                code=None,
                state=None,
                cookie_value=None,
                error="access_denied",
            )

        assert caught.value.code == "denied"

    async def test_user_denied_is_also_a_refusal(self, google):
        with pytest.raises(OAuthDenied):
            await complete(
                google, code=None, state=None, cookie_value=None, error="user_denied"
            )

    async def test_other_errors_are_reported_separately(self, google):
        with pytest.raises(ProviderRejected) as caught:
            await complete(
                google,
                code=None,
                state=None,
                cookie_value=None,
                error="invalid_scope",
                error_description="Unknown scope 'drive'",
            )

        assert caught.value.code == "provider_error"
        assert caught.value.detail == "Unknown scope 'drive'"

    async def test_provider_error_code_is_kept_in_detail(self, google):
        with pytest.raises(ProviderRejected) as caught:
            await complete(
                google, code=None, state=None, cookie_value=None, error="server_error"
            )

        assert caught.value.detail == "server_error"

    async def test_no_request_is_made_when_the_provider_reported_an_error(
        self, google, stub
    ):
        with pytest.raises(OAuthError):
            await complete(
                google, code=None, state=None, cookie_value=None, error="access_denied"
            )

        assert stub.requests == []


class TestStateEnforcement:
    """Nothing reaches the provider until the callback is proven ours."""

    async def test_forged_callback_is_rejected(self, google):
        with pytest.raises(StateMismatch):
            await complete(
                google,
                code="attacker-code",
                state="attacker-state",
                cookie_value="attacker-cookie",
            )

    async def test_forged_callback_makes_no_token_request(self, google, stub):
        """The point of checking state first.

        If state were verified after the exchange, an attacker could make this
        server burn a code — or redeem one they planted — before the check.
        """
        with pytest.raises(StateMismatch):
            await complete(
                google,
                code="attacker-code",
                state="attacker-state",
                cookie_value="attacker-cookie",
            )

        assert stub.requests == []

    async def test_missing_cookie_is_rejected(self, google):
        started = authorize_url(google)

        with pytest.raises(StateMismatch):
            await complete(google, code="c", state=started.state, cookie_value=None)

    async def test_missing_state_parameter_is_rejected(self, google):
        started = authorize_url(google)

        with pytest.raises(StateMismatch):
            await complete(
                google, code="c", state=None, cookie_value=started.cookie_value
            )

    async def test_state_from_a_different_login_is_rejected(self, google):
        first = authorize_url(google)
        second = authorize_url(google)

        with pytest.raises(StateMismatch):
            await complete(
                google,
                code="c",
                state=second.state,
                cookie_value=first.cookie_value,
            )

    async def test_state_from_another_provider_is_rejected(self, google):
        """A cookie minted for GitHub cannot complete a Google callback."""
        state, cookie = issue_state("github", STATE_SECRET)

        with pytest.raises(StateMismatch):
            await complete(google, code="c", state=state, cookie_value=cookie)

    async def test_expired_state_is_rejected(self, google):
        state, cookie = issue_state("google", STATE_SECRET, ttl=0, now=0.0)

        with pytest.raises(StateExpired):
            await complete(google, code="c", state=state, cookie_value=cookie)

    async def test_valid_state_with_no_code_is_rejected(self, google, stub):
        started = authorize_url(google)

        with pytest.raises(StateMismatch, match="no authorization code"):
            await complete(
                google,
                code=None,
                state=started.state,
                cookie_value=started.cookie_value,
            )

        assert stub.requests == []


class TestFailurePropagation:
    """Downstream failures surface with their own codes."""

    async def test_token_failure_propagates(self, google, stub):
        stub.route(TOKEN_URL, json={"error": "invalid_grant"})

        with pytest.raises(TokenExchangeFailed):
            await run(google)

    async def test_profile_failure_propagates(self, google, stub):
        stub.route(USERINFO_URL, json={"no": "subject"})

        with pytest.raises(OAuthError) as caught:
            await run(google)

        assert caught.value.code == "profile_failed"

    async def test_every_failure_is_catchable_as_oauth_error(self, google, stub):
        """One ``except`` clause is enough for a handler."""
        stub.route(TOKEN_URL, json={"error": "invalid_grant"})

        with pytest.raises(OAuthError):
            await run(google)

    async def test_missing_secret_is_refused_before_anything_else(self, stub):
        stub.route(TOKEN_URL, json={"access_token": ACCESS_TOKEN})
        provider = GoogleOAuthProvider(
            client_id="cid",
            redirect_uri="https://app.test/cb",
            transport=stub.transport,
        )

        with pytest.raises(ProviderMisconfigured, match="state_secret"):
            await complete(provider, code="c", state="s", cookie_value="v")

        assert stub.requests == []


class TestErrorCodes:
    """The stable identifiers handlers branch on."""

    def test_codes_are_url_safe_and_distinct(self):
        codes = {
            OAuthError.code,
            OAuthDenied.code,
            ProviderRejected.code,
            StateMismatch.code,
            StateExpired.code,
            TokenExchangeFailed.code,
            ProviderMisconfigured.code,
        }

        assert len(codes) == 7, "each failure kind needs its own code"
        assert all(code.replace("_", "").isalnum() for code in codes)

    def test_every_error_subclasses_oauth_error(self):
        for cls in (
            OAuthDenied,
            ProviderRejected,
            StateMismatch,
            StateExpired,
            TokenExchangeFailed,
            ProviderMisconfigured,
        ):
            assert issubclass(cls, OAuthError)

    def test_repr_shows_the_code_and_provider(self):
        error = StateMismatch("nope", provider="google", detail="d")

        assert "state_mismatch" in repr(error)
        assert "google" in repr(error)
