"""The token request: what gets sent, and how responses are read.

Every response here is canned. No test needs a client secret that exists, an
authorization code that was ever issued, or a network.
"""

from __future__ import annotations

import httpx
import pytest
from conftest import (
    ACCESS_TOKEN,
    CLIENT_ID,
    CLIENT_SECRET,
    REDIRECT_URI,
    STATE_SECRET,
    ProviderStub,
)

from sillo_oauth import (
    GithubOAuthProvider,
    GoogleOAuthProvider,
    OAuthProvider,
    ProviderMisconfigured,
    TokenExchangeFailed,
    derive_verifier,
    exchange_code,
)

TOKEN_URL = GoogleOAuthProvider.token_endpoint


class TestRequestShape:
    """What the provider receives."""

    async def test_posts_to_the_token_endpoint(self, google, stub):
        await exchange_code(google, code="test-code")

        request = stub.request_to(TOKEN_URL)
        assert request.method == "POST"

    async def test_sends_the_authorization_code_grant(self, google, stub):
        await exchange_code(google, code="test-code")

        form = stub.form_to(TOKEN_URL)
        assert form["grant_type"] == "authorization_code"
        assert form["code"] == "test-code"

    async def test_sends_client_credentials(self, google, stub):
        await exchange_code(google, code="test-code")

        form = stub.form_to(TOKEN_URL)
        assert form["client_id"] == CLIENT_ID
        assert form["client_secret"] == CLIENT_SECRET

    async def test_echoes_the_redirect_uri(self, google, stub):
        """Providers compare this against the authorize request."""
        await exchange_code(google, code="test-code")

        assert stub.form_to(TOKEN_URL)["redirect_uri"] == REDIRECT_URI

    async def test_redirect_uri_can_be_overridden_per_call(self, google, stub):
        await exchange_code(
            google, code="test-code", redirect_uri="https://other.test/cb"
        )

        assert stub.form_to(TOKEN_URL)["redirect_uri"] == "https://other.test/cb"

    async def test_sends_the_pkce_verifier_when_given(self, google, stub):
        verifier = derive_verifier("some-state", STATE_SECRET)

        await exchange_code(google, code="test-code", verifier=verifier)

        assert stub.form_to(TOKEN_URL)["code_verifier"] == verifier

    async def test_omits_the_verifier_when_not_given(self, google, stub):
        await exchange_code(google, code="test-code")

        assert "code_verifier" not in stub.form_to(TOKEN_URL)

    async def test_public_client_omits_the_secret(self, stub):
        """An empty secret means a public client, not an empty credential."""
        stub.route(TOKEN_URL, json={"access_token": ACCESS_TOKEN})
        provider = GoogleOAuthProvider(
            client_id=CLIENT_ID,
            client_secret="",
            state_secret=STATE_SECRET,
            redirect_uri=REDIRECT_URI,
            transport=stub.transport,
        )

        await exchange_code(provider, code="test-code")

        assert "client_secret" not in stub.form_to(TOKEN_URL)

    async def test_asks_for_json(self, google, stub):
        """Several providers answer with a form body without this header."""
        await exchange_code(google, code="test-code")

        assert stub.request_to(TOKEN_URL).headers["accept"] == "application/json"

    async def test_missing_redirect_uri_is_refused(self, stub):
        stub.route(TOKEN_URL, json={"access_token": ACCESS_TOKEN})
        provider = GoogleOAuthProvider(
            client_id=CLIENT_ID, state_secret=STATE_SECRET, transport=stub.transport
        )

        with pytest.raises(ProviderMisconfigured, match="redirect_uri"):
            await exchange_code(provider, code="test-code")


class TestSuccessfulResponses:
    """Reading a token out of what came back."""

    async def test_parses_a_full_json_response(self, google):
        tokens = await exchange_code(google, code="test-code")

        assert tokens.access_token == ACCESS_TOKEN
        assert tokens.token_type == "Bearer"
        assert tokens.expires_in == 3599
        assert tokens.scope == "openid email profile"
        assert tokens.id_token == "test-id-token"

    async def test_keeps_the_raw_payload(self, stub, google):
        stub.route(
            TOKEN_URL,
            json={"access_token": ACCESS_TOKEN, "x_provider_extra": "kept"},
        )

        tokens = await exchange_code(google, code="test-code")

        assert tokens.raw["x_provider_extra"] == "kept"

    async def test_defaults_the_token_type(self, stub, google):
        stub.route(TOKEN_URL, json={"access_token": ACCESS_TOKEN})

        assert (await exchange_code(google, code="c")).token_type == "Bearer"

    async def test_captures_a_refresh_token(self, stub, google):
        stub.route(
            TOKEN_URL,
            json={"access_token": ACCESS_TOKEN, "refresh_token": "test-refresh"},
        )

        assert (await exchange_code(google, code="c")).refresh_token == "test-refresh"

    async def test_non_numeric_expiry_becomes_none(self, stub, google):
        """Rather than raising on a provider that sends something odd."""
        stub.route(TOKEN_URL, json={"access_token": ACCESS_TOKEN, "expires_in": "soon"})

        assert (await exchange_code(google, code="c")).expires_in is None

    async def test_string_expiry_is_parsed(self, stub, google):
        stub.route(TOKEN_URL, json={"access_token": ACCESS_TOKEN, "expires_in": "3600"})

        assert (await exchange_code(google, code="c")).expires_in == 3600

    async def test_authorization_header_is_built_from_the_token(self, google):
        tokens = await exchange_code(google, code="test-code")

        assert tokens.authorization_header() == f"Bearer {ACCESS_TOKEN}"

    async def test_lowercase_token_type_is_normalised_in_the_header(self, stub, google):
        """GitHub answers ``"bearer"``; HTTP wants it capitalised."""
        stub.route(
            TOKEN_URL, json={"access_token": ACCESS_TOKEN, "token_type": "bearer"}
        )

        tokens = await exchange_code(google, code="c")

        assert tokens.token_type == "bearer"
        assert tokens.authorization_header() == f"Bearer {ACCESS_TOKEN}"


class TestFormEncodedResponses:
    """GitHub's default, and anyone who overrides the Accept header."""

    async def test_form_encoded_body_is_parsed(self, stub):
        stub.route(
            GithubOAuthProvider.token_endpoint,
            text=f"access_token={ACCESS_TOKEN}&scope=read%3Auser&token_type=bearer",
            content_type="application/x-www-form-urlencoded; charset=utf-8",
        )
        github = GithubOAuthProvider(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            state_secret=STATE_SECRET,
            redirect_uri=REDIRECT_URI,
            transport=stub.transport,
        )

        tokens = await exchange_code(github, code="test-code")

        assert tokens.access_token == ACCESS_TOKEN
        assert tokens.scope == "read:user"

    async def test_form_encoded_error_is_reported(self, stub):
        stub.route(
            GithubOAuthProvider.token_endpoint,
            text="error=bad_verification_code&error_description=The+code+expired",
            content_type="application/x-www-form-urlencoded",
        )
        github = GithubOAuthProvider(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            state_secret=STATE_SECRET,
            redirect_uri=REDIRECT_URI,
            transport=stub.transport,
        )

        with pytest.raises(TokenExchangeFailed) as caught:
            await exchange_code(github, code="test-code")

        assert caught.value.detail == "The code expired"

    async def test_body_with_no_content_type_is_still_read(self, stub, google):
        """Both encodings are tried rather than guessed at."""
        stub.route(TOKEN_URL, text=f"access_token={ACCESS_TOKEN}", content_type="")

        assert (await exchange_code(google, code="c")).access_token == ACCESS_TOKEN

    async def test_untyped_json_body_is_still_read(self, stub, google):
        stub.route(
            TOKEN_URL, text=f'{{"access_token": "{ACCESS_TOKEN}"}}', content_type=""
        )

        assert (await exchange_code(google, code="c")).access_token == ACCESS_TOKEN


class TestFailures:
    """Every way the exchange can go wrong."""

    async def test_error_field_in_a_200_response(self, stub, google):
        """Some providers answer 200 with an error body."""
        stub.route(
            TOKEN_URL,
            json={"error": "invalid_grant", "error_description": "Code was used"},
        )

        with pytest.raises(TokenExchangeFailed) as caught:
            await exchange_code(google, code="test-code")

        assert caught.value.code == "exchange_failed"
        assert caught.value.detail == "Code was used"

    async def test_error_field_falls_back_to_the_code(self, stub, google):
        stub.route(TOKEN_URL, json={"error": "invalid_grant"})

        with pytest.raises(TokenExchangeFailed) as caught:
            await exchange_code(google, code="test-code")

        assert caught.value.detail == "invalid_grant"

    async def test_http_400(self, stub, google):
        stub.route(TOKEN_URL, json={"whatever": True}, status=400)

        with pytest.raises(TokenExchangeFailed):
            await exchange_code(google, code="test-code")

    async def test_http_500(self, stub, google):
        stub.route(TOKEN_URL, json={}, status=500)

        with pytest.raises(TokenExchangeFailed):
            await exchange_code(google, code="test-code")

    async def test_missing_access_token(self, stub, google):
        stub.route(TOKEN_URL, json={"token_type": "Bearer"})

        with pytest.raises(TokenExchangeFailed, match="no access_token"):
            await exchange_code(google, code="test-code")

    async def test_empty_access_token(self, stub, google):
        stub.route(TOKEN_URL, json={"access_token": ""})

        with pytest.raises(TokenExchangeFailed, match="no access_token"):
            await exchange_code(google, code="test-code")

    async def test_json_array_instead_of_an_object(self, stub, google):
        stub.route(TOKEN_URL, json=["nope"])

        with pytest.raises(TokenExchangeFailed, match="not a JSON object"):
            await exchange_code(google, code="test-code")

    async def test_malformed_json(self, stub, google):
        stub.route(TOKEN_URL, text="{not json", content_type="application/json")

        with pytest.raises(TokenExchangeFailed, match="not valid JSON"):
            await exchange_code(google, code="test-code")

    async def test_undecodable_body(self, stub, google):
        stub.route(TOKEN_URL, text="", content_type="text/html")

        with pytest.raises(TokenExchangeFailed, match="could not be decoded"):
            await exchange_code(google, code="test-code")

    async def test_provider_unreachable(self, stub, google):
        stub.fail(TOKEN_URL)

        with pytest.raises(TokenExchangeFailed, match="Could not reach"):
            await exchange_code(google, code="test-code")

    async def test_provider_timeout(self, stub, google):
        stub.fail(TOKEN_URL, httpx.ReadTimeout("too slow"))

        with pytest.raises(TokenExchangeFailed, match="Could not reach"):
            await exchange_code(google, code="test-code")

    async def test_failure_names_the_provider(self, stub, google):
        stub.route(TOKEN_URL, json={"error": "invalid_grant"})

        with pytest.raises(TokenExchangeFailed) as caught:
            await exchange_code(google, code="test-code")

        assert caught.value.provider == "google"


class TestTokenRequestCustomisation:
    """The provider hook for providers that want a different body."""

    async def test_token_request_data_can_be_overridden(self, stub):
        class BasicAuthProvider(OAuthProvider):
            name = "basic"
            authorize_endpoint = "https://basic.test/authorize"
            token_endpoint = "https://basic.test/token"

            def token_request_data(self, *, code, redirect_uri, verifier):
                data = super().token_request_data(
                    code=code, redirect_uri=redirect_uri, verifier=verifier
                )
                # Credentials go in the header instead of the body.
                data.pop("client_secret", None)
                data["custom_field"] = "present"
                return data

        stub.route("https://basic.test/token", json={"access_token": ACCESS_TOKEN})
        provider = BasicAuthProvider(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            state_secret=STATE_SECRET,
            redirect_uri=REDIRECT_URI,
            transport=stub.transport,
        )

        await exchange_code(provider, code="test-code")

        form = stub.form_to("https://basic.test/token")
        assert form["custom_field"] == "present"
        assert "client_secret" not in form


class TestNetworkGuard:
    """The suite's own safety net."""

    async def test_a_provider_without_a_stub_cannot_reach_the_network(self):
        """Proves the autouse guard actually bites."""
        provider = GoogleOAuthProvider(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            state_secret=STATE_SECRET,
            redirect_uri=REDIRECT_URI,
        )

        with pytest.raises(AssertionError, match="real network request"):
            await exchange_code(provider, code="test-code")
