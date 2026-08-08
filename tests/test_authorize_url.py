"""Building the redirect URL.

``authorize_url`` is pure — no request, no response, no I/O — so these tests
read the URL it produced and the cookie it asked to be set, and nothing else.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest
from conftest import CLIENT_ID, REDIRECT_URI, STATE_SECRET

from sillo_oauth import (
    GithubOAuthProvider,
    GoogleOAuthProvider,
    MicrosoftOAuthProvider,
    OAuthProvider,
    ProviderMisconfigured,
    authorize_url,
    derive_verifier,
    pkce_challenge,
    state_cookie_name,
    verify_state,
)


def query_of(url: str) -> dict[str, str]:
    """Flatten a URL's query string to single values."""
    return {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}


class TestRequiredParameters:
    """The parameters every authorize request must carry."""

    def test_targets_the_provider_authorize_endpoint(self, google):
        url = authorize_url(google).url

        assert url.startswith(GoogleOAuthProvider.authorize_endpoint)

    def test_sends_response_type_code(self, google):
        assert query_of(authorize_url(google).url)["response_type"] == "code"

    def test_sends_client_id(self, google):
        assert query_of(authorize_url(google).url)["client_id"] == CLIENT_ID

    def test_sends_redirect_uri(self, google):
        assert query_of(authorize_url(google).url)["redirect_uri"] == REDIRECT_URI

    def test_sends_the_state(self, google):
        result = authorize_url(google)

        assert query_of(result.url)["state"] == result.state

    def test_never_sends_the_client_secret(self, google):
        """The authorize URL is visible to the browser and to the user."""
        assert "client_secret" not in authorize_url(google).url

    def test_never_sends_the_state_secret(self, google):
        assert STATE_SECRET not in authorize_url(google).url

    def test_never_sends_the_pkce_verifier(self, google):
        """Only the challenge may leave the server."""
        result = authorize_url(google)
        verifier = derive_verifier(result.state, STATE_SECRET)

        assert verifier not in result.url


class TestScopes:
    """Scope selection and encoding."""

    def test_uses_the_provider_defaults(self, google):
        assert query_of(authorize_url(google).url)["scope"] == "openid email profile"

    def test_per_call_scopes_override_the_provider(self, google):
        url = authorize_url(google, scopes=["openid", "drive.readonly"]).url

        assert query_of(url)["scope"] == "openid drive.readonly"

    def test_empty_scope_list_omits_the_parameter(self, google):
        assert "scope" not in query_of(authorize_url(google, scopes=[]).url)

    def test_provider_without_scopes_omits_the_parameter(self, stub):
        provider = OAuthProvider(
            name="acme",
            client_id=CLIENT_ID,
            state_secret=STATE_SECRET,
            redirect_uri=REDIRECT_URI,
            authorize_endpoint="https://acme.test/authorize",
            token_endpoint="https://acme.test/token",
            transport=stub.transport,
        )

        assert "scope" not in query_of(authorize_url(provider).url)

    def test_custom_separator_is_honoured(self, stub):
        """Some providers want commas, not spaces."""

        class CommaProvider(OAuthProvider):
            name = "comma"
            authorize_endpoint = "https://comma.test/authorize"
            token_endpoint = "https://comma.test/token"
            scope_separator = ","

        provider = CommaProvider(
            client_id=CLIENT_ID,
            state_secret=STATE_SECRET,
            redirect_uri=REDIRECT_URI,
            scopes=["read", "write"],
            transport=stub.transport,
        )

        assert query_of(authorize_url(provider).url)["scope"] == "read,write"


class TestPKCEParameters:
    """The challenge, when the provider supports one."""

    def test_challenge_is_sent_and_matches_the_derived_verifier(self, google):
        result = authorize_url(google)
        params = query_of(result.url)
        expected = pkce_challenge(derive_verifier(result.state, STATE_SECRET))

        assert params["code_challenge"] == expected
        assert params["code_challenge_method"] == "S256"

    def test_omitted_for_providers_that_do_not_support_pkce(self, stub):
        github = GithubOAuthProvider(
            client_id=CLIENT_ID,
            client_secret="s",
            state_secret=STATE_SECRET,
            redirect_uri=REDIRECT_URI,
            transport=stub.transport,
        )
        params = query_of(authorize_url(github).url)

        assert "code_challenge" not in params
        assert "code_challenge_method" not in params

    def test_can_be_disabled_per_instance(self, stub):
        provider = GoogleOAuthProvider(
            client_id=CLIENT_ID,
            state_secret=STATE_SECRET,
            redirect_uri=REDIRECT_URI,
            use_pkce=False,
            transport=stub.transport,
        )

        assert "code_challenge" not in query_of(authorize_url(provider).url)

    def test_challenge_differs_between_logins(self, google):
        first = query_of(authorize_url(google).url)["code_challenge"]
        second = query_of(authorize_url(google).url)["code_challenge"]

        assert first != second


class TestExtraParameters:
    """Provider-level and per-call additions."""

    def test_provider_level_parameters_are_included(self, stub):
        provider = GoogleOAuthProvider(
            client_id=CLIENT_ID,
            state_secret=STATE_SECRET,
            redirect_uri=REDIRECT_URI,
            authorize_params={"access_type": "offline"},
            transport=stub.transport,
        )

        assert query_of(authorize_url(provider).url)["access_type"] == "offline"

    def test_per_call_parameters_are_included(self, google):
        url = authorize_url(google, extra_params={"prompt": "consent"}).url

        assert query_of(url)["prompt"] == "consent"

    def test_per_call_parameters_win_over_provider_level(self, stub):
        provider = GoogleOAuthProvider(
            client_id=CLIENT_ID,
            state_secret=STATE_SECRET,
            redirect_uri=REDIRECT_URI,
            authorize_params={"prompt": "none"},
            transport=stub.transport,
        )
        url = authorize_url(provider, extra_params={"prompt": "consent"}).url

        assert query_of(url)["prompt"] == "consent"

    def test_reserved_parameters_are_refused(self, google):
        """Overriding the state would silently disarm CSRF protection.

        The cookie is signed against the generated value, so a supplied one
        either breaks every login or, if an attacker chose it, removes the
        guarantee entirely. Either way it must not be ignorable.
        """
        with pytest.raises(ProviderMisconfigured, match="state"):
            authorize_url(google, extra_params={"state": "attacker-chosen"})

    def test_reserved_pkce_parameters_are_refused(self, google):
        with pytest.raises(ProviderMisconfigured, match="code_challenge"):
            authorize_url(google, extra_params={"code_challenge": "not-derived"})

    @pytest.mark.parametrize(
        "name",
        [
            "state",
            "code_challenge",
            "code_challenge_method",
            "response_type",
            "client_id",
            "redirect_uri",
            "scope",
        ],
    )
    def test_every_managed_parameter_is_refused(self, google, name):
        with pytest.raises(ProviderMisconfigured):
            authorize_url(google, extra_params={name: "x"})

    def test_reserved_parameters_are_refused_at_provider_level_too(self, stub):
        """The provider-level dict is merged into the same place."""
        provider = GoogleOAuthProvider(
            client_id=CLIENT_ID,
            state_secret=STATE_SECRET,
            redirect_uri=REDIRECT_URI,
            authorize_params={"state": "fixed"},
            transport=stub.transport,
        )

        with pytest.raises(ProviderMisconfigured, match="state"):
            authorize_url(provider)

    def test_the_error_says_what_to_do_instead(self, google):
        with pytest.raises(ProviderMisconfigured, match="pass scopes= instead"):
            authorize_url(google, extra_params={"scope": "openid"})

    def test_unreserved_parameters_still_pass_through(self, google):
        url = authorize_url(
            google, extra_params={"prompt": "consent", "login_hint": "ada@example.com"}
        ).url

        assert query_of(url)["prompt"] == "consent"
        assert query_of(url)["login_hint"] == "ada@example.com"

    def test_existing_query_on_the_endpoint_is_preserved(self, stub):
        provider = OAuthProvider(
            name="acme",
            client_id=CLIENT_ID,
            state_secret=STATE_SECRET,
            redirect_uri=REDIRECT_URI,
            authorize_endpoint="https://acme.test/authorize?tenant=acme-inc",
            token_endpoint="https://acme.test/token",
            transport=stub.transport,
        )
        params = query_of(authorize_url(provider).url)

        assert params["tenant"] == "acme-inc"
        assert params["response_type"] == "code"

    def test_endpoint_query_never_duplicates_a_managed_parameter(self, stub):
        """Two ``state`` values would leave the provider to pick one.

        A misconfigured endpoint with its own ``state=`` is the caller's
        mistake, but appending ours after it produces a URL that works only
        if the provider happens to read the second occurrence.
        """
        provider = OAuthProvider(
            name="acme",
            client_id=CLIENT_ID,
            state_secret=STATE_SECRET,
            redirect_uri=REDIRECT_URI,
            authorize_endpoint=(
                "https://acme.test/authorize?state=stale&client_id=wrong&keep=yes"
            ),
            token_endpoint="https://acme.test/token",
            transport=stub.transport,
        )

        result = authorize_url(provider)
        query = urlsplit(result.url).query
        params = parse_qs(query)

        assert params["state"] == [result.state]
        assert params["client_id"] == [CLIENT_ID]
        assert params["keep"] == ["yes"], "unrelated endpoint query survives"
        assert query.count("state=") == 1


class TestOverrides:
    """Per-call overrides of provider configuration."""

    def test_redirect_uri_can_be_overridden(self, google):
        url = authorize_url(google, redirect_uri="https://other.test/cb").url

        assert query_of(url)["redirect_uri"] == "https://other.test/cb"

    def test_secret_can_be_overridden(self, stub):
        provider = GoogleOAuthProvider(
            client_id=CLIENT_ID,
            state_secret=None,
            redirect_uri=REDIRECT_URI,
            transport=stub.transport,
        )
        result = authorize_url(provider, secret="per-call-secret")

        assert verify_state(
            result.cookie_value, result.state, "google", "per-call-secret"
        )

    def test_cookie_name_can_be_overridden(self, google):
        result = authorize_url(google, cookie_name="my_state")

        assert result.cookie_name == "my_state"

    def test_ttl_is_reflected_in_max_age(self, google):
        assert authorize_url(google, ttl=90).max_age == 90


class TestStateCookie:
    """What comes back for the caller to store."""

    def test_cookie_name_is_namespaced_per_provider(self, google):
        assert authorize_url(google).cookie_name == "oauth_state_google"
        assert state_cookie_name(google) == "oauth_state_google"

    def test_cookie_value_verifies_against_the_state(self, google):
        result = authorize_url(google)

        payload = verify_state(
            result.cookie_value, result.state, "google", STATE_SECRET
        )

        assert payload.state == result.state

    def test_return_to_survives_the_round_trip(self, google):
        result = authorize_url(google, return_to="/dashboard")

        payload = verify_state(
            result.cookie_value, result.state, "google", STATE_SECRET
        )

        assert payload.return_to == "/dashboard"

    def test_return_to_is_not_sent_to_the_provider(self, google):
        """It travels in the signed cookie, not the query string."""
        result = authorize_url(google, return_to="/dashboard")

        assert "/dashboard" not in result.url
        assert "return_to" not in query_of(result.url)

    def test_cookie_kwargs_are_safe_by_default(self, google):
        kwargs = authorize_url(google).cookie_kwargs()

        assert kwargs["httponly"] is True
        assert kwargs["secure"] is True
        # "strict" would stop the browser sending the cookie on the
        # provider's cross-site redirect back, which is the one request that
        # needs it.
        assert kwargs["samesite"] == "lax"
        assert kwargs["path"] == "/"

    def test_cookie_kwargs_state_every_attribute(self):
        """None may be left to the framework's default.

        ``Responder.set_cookie`` defaults ``secure`` on and
        ``BaseResponse.set_cookie`` defaults it off, so an unstated attribute
        would make this cookie's security depend on which object the caller
        happened to be holding.
        """
        from sillo_oauth import AuthorizeURL

        kwargs = AuthorizeURL("u", "s", "n", "v", 60).cookie_kwargs()

        assert set(kwargs) == {
            "key",
            "value",
            "max_age",
            "httponly",
            "samesite",
            "secure",
            "path",
        }

    def test_cookie_kwargs_carry_the_value_and_lifetime(self, google):
        result = authorize_url(google, ttl=120)
        kwargs = result.cookie_kwargs()

        assert kwargs["key"] == result.cookie_name
        assert kwargs["value"] == result.cookie_value
        assert kwargs["max_age"] == 120

    def test_cookie_kwargs_accept_overrides(self, google):
        kwargs = authorize_url(google).cookie_kwargs(secure=True, samesite="none")

        assert kwargs["secure"] is True
        assert kwargs["samesite"] == "none"

    def test_overrides_do_not_leak_into_the_next_call(self, google):
        result = authorize_url(google)
        result.cookie_kwargs(secure=False, path="/auth")

        second = result.cookie_kwargs()

        assert second["secure"] is True
        assert second["path"] == "/"


class TestMisconfiguration:
    """Failures that are the application's mistake, not the provider's."""

    def test_missing_state_secret_is_refused(self, stub):
        provider = GoogleOAuthProvider(
            client_id=CLIENT_ID, redirect_uri=REDIRECT_URI, transport=stub.transport
        )

        with pytest.raises(ProviderMisconfigured, match="state_secret"):
            authorize_url(provider)

    def test_missing_redirect_uri_is_refused(self, stub):
        provider = GoogleOAuthProvider(
            client_id=CLIENT_ID, state_secret=STATE_SECRET, transport=stub.transport
        )

        with pytest.raises(ProviderMisconfigured, match="redirect_uri"):
            authorize_url(provider)

    def test_provider_without_endpoints_is_refused_at_construction(self):
        """A provider with no endpoints can never work, so it fails early."""
        with pytest.raises(ProviderMisconfigured, match="authorize_endpoint"):
            OAuthProvider(name="broken", client_id=CLIENT_ID, state_secret=STATE_SECRET)


class TestMicrosoftTenant:
    """Endpoints derived from the tenant."""

    def test_default_tenant_is_common(self, stub):
        provider = MicrosoftOAuthProvider(
            client_id=CLIENT_ID,
            state_secret=STATE_SECRET,
            redirect_uri=REDIRECT_URI,
            transport=stub.transport,
        )

        assert "/common/" in provider.authorize_endpoint
        assert "/common/" in provider.token_endpoint

    def test_tenant_is_substituted_into_both_endpoints(self, stub):
        provider = MicrosoftOAuthProvider(
            tenant="contoso-tenant-id",
            client_id=CLIENT_ID,
            state_secret=STATE_SECRET,
            redirect_uri=REDIRECT_URI,
            transport=stub.transport,
        )

        assert "/contoso-tenant-id/" in provider.authorize_endpoint
        assert "/contoso-tenant-id/" in provider.token_endpoint

    def test_explicit_endpoints_win_over_the_tenant(self, stub):
        provider = MicrosoftOAuthProvider(
            tenant="contoso",
            client_id=CLIENT_ID,
            state_secret=STATE_SECRET,
            redirect_uri=REDIRECT_URI,
            authorize_endpoint="https://custom.test/authorize",
            transport=stub.transport,
        )

        assert provider.authorize_endpoint == "https://custom.test/authorize"
        assert "/contoso/" in provider.token_endpoint
