"""Output the OAuth documentation quotes verbatim.

The guides under ``guides/oauth/`` print exact reprs, exact error messages and
exact tables. A reader compares what they see against what the page says, so
those are a contract in a way that prose is not: if the rendering changes, the
documentation is wrong on screen, and nothing else in the suite would notice.

Behaviour that the docs merely *describe* is covered by the rest of the suite.
This file pins only what they reproduce word for word.
"""

from __future__ import annotations

import pytest
from conftest import CLIENT_ID, REDIRECT_URI, STATE_SECRET

from sillo_oauth import (
    DiscordOAuthProvider,
    GithubOAuthProvider,
    GoogleOAuthProvider,
    MicrosoftOAuthProvider,
    OAuthDenied,
    OAuthError,
    OAuthProfile,
    OAuthTokens,
    ProfileFetchFailed,
    ProviderMisconfigured,
    ProviderRejected,
    StateExpired,
    StateMismatch,
    TokenExchangeFailed,
    authorize_url,
    state_cookie_name,
)


@pytest.fixture
def google(stub):
    return GoogleOAuthProvider(
        client_id=CLIENT_ID,
        client_secret="SECRET-CLIENT",
        state_secret=STATE_SECRET,
        redirect_uri=REDIRECT_URI,
        transport=stub.transport,
    )


class TestQuotedReprs:
    """`guides/oauth/security/` prints these."""

    def test_tokens_repr_renders_exactly_as_documented(self):
        tokens = OAuthTokens(
            access_token="ya29.LIVE",
            refresh_token="r",
            expires_in=3600,
            scope="openid email",
        )

        assert repr(tokens) == (
            "OAuthTokens(access_token=<redacted>, token_type='Bearer', "
            "expires_in=3600, scope='openid email', also_holds=['refresh_token'])"
        )

    def test_provider_repr_hides_both_secrets(self):
        """The docs promise a provider repr leaks neither secret."""
        provider = GoogleOAuthProvider(
            client_id="cid",
            client_secret="SECRET-CLIENT",
            state_secret="SECRET-STATE",
            redirect_uri=REDIRECT_URI,
        )

        printed = repr(provider)

        assert printed == "<GoogleOAuthProvider name='google' client_id='cid'>"
        assert "SECRET-CLIENT" not in printed
        assert "SECRET-STATE" not in printed


class TestQuotedErrorMessages:
    """`guides/oauth/security/` reproduces this one in full."""

    def test_reserved_parameter_message(self, google):
        with pytest.raises(ProviderMisconfigured) as caught:
            authorize_url(google, extra_params={"state": "chosen"})

        assert str(caught.value) == (
            "These authorize parameters are managed by sillo-oauth and cannot "
            "be overridden: state (it is generated and signed into the state "
            "cookie)"
        )

    def test_redirect_uri_and_scope_point_at_their_arguments(self, google):
        """The docs say the error names the proper knob."""
        with pytest.raises(ProviderMisconfigured) as caught:
            authorize_url(google, extra_params={"redirect_uri": "x", "scope": "y"})

        message = str(caught.value)
        assert "pass redirect_uri= instead" in message
        assert "pass scopes= instead" in message


class TestDocumentedErrorCodes:
    """The `.code` table in `guides/oauth/`."""

    @pytest.mark.parametrize(
        ("cls", "code"),
        [
            (OAuthDenied, "denied"),
            (ProviderRejected, "provider_error"),
            (StateMismatch, "state_mismatch"),
            (StateExpired, "state_expired"),
            (TokenExchangeFailed, "exchange_failed"),
            (ProfileFetchFailed, "profile_failed"),
            (ProviderMisconfigured, "provider_misconfigured"),
        ],
    )
    def test_each_documented_code_is_what_the_class_reports(self, cls, code):
        assert cls.code == code
        assert issubclass(cls, OAuthError)

    def test_the_table_is_complete(self):
        """No error kind exists that the documentation does not list."""
        documented = {
            "denied",
            "provider_error",
            "state_mismatch",
            "state_expired",
            "exchange_failed",
            "profile_failed",
            "provider_misconfigured",
        }

        def subclasses(cls):
            for sub in cls.__subclasses__():
                yield sub
                yield from subclasses(sub)

        assert {sub.code for sub in subclasses(OAuthError)} == documented


class TestDocumentedCookieAttributes:
    """The cookie-attribute table in `guides/oauth/security/`."""

    def test_every_documented_attribute_is_stated(self, google):
        kwargs = authorize_url(google).cookie_kwargs()

        assert set(kwargs) == {
            "key",
            "value",
            "max_age",
            "httponly",
            "samesite",
            "secure",
            "path",
        }

    def test_the_documented_values(self, google):
        kwargs = authorize_url(google, ttl=600).cookie_kwargs()

        assert kwargs["httponly"] is True
        assert kwargs["samesite"] == "lax"
        assert kwargs["secure"] is True
        assert kwargs["path"] == "/"
        assert kwargs["max_age"] == 600

    def test_the_documented_default_ttl_is_ten_minutes(self, google):
        """`guides/oauth/security/` says "default 10 minutes"."""
        assert authorize_url(google).max_age == 600

    def test_the_documented_cookie_name(self, google):
        assert state_cookie_name(google) == "oauth_state_google"
        assert authorize_url(google).cookie_name == "oauth_state_google"


class TestDocumentedProviderTable:
    """The provider table in `guides/oauth/providers/`."""

    @pytest.mark.parametrize(
        ("cls", "scopes"),
        [
            (GoogleOAuthProvider, ("openid", "email", "profile")),
            (GithubOAuthProvider, ("read:user", "user:email")),
            (DiscordOAuthProvider, ("identify", "email")),
            (MicrosoftOAuthProvider, ("openid", "email", "profile")),
        ],
    )
    def test_documented_default_scopes(self, cls, scopes):
        assert cls.default_scopes == scopes

    def test_github_has_pkce_off_as_documented(self):
        assert GithubOAuthProvider.use_pkce is False

    def test_the_others_have_pkce_on(self):
        for cls in (
            GoogleOAuthProvider,
            DiscordOAuthProvider,
            MicrosoftOAuthProvider,
        ):
            assert cls.use_pkce is True

    def test_documented_subject_key_order(self):
        """The docs name the order the generic mapping tries."""
        from sillo_oauth.providers import _SUBJECT_KEYS

        assert _SUBJECT_KEYS == ("sub", "id", "user_id", "uid")


class TestDocumentedProfileFields:
    """The field list in `guides/oauth/`."""

    def test_every_documented_field_exists(self):
        profile = OAuthProfile(provider="google", subject="112233")

        for field in (
            "provider",
            "subject",
            "email",
            "email_verified",
            "name",
            "username",
            "avatar_url",
            "raw",
            "tokens",
            "return_to",
        ):
            assert hasattr(profile, field), field

    def test_key_renders_as_documented(self):
        profile = OAuthProfile(provider="google", subject="112233")

        assert profile.key == "google:112233"
