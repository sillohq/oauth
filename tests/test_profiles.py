"""Turning a provider's userinfo payload into an ``OAuthProfile``.

The payloads below are trimmed copies of the real response shapes, filled with
invented values. Nothing here calls a provider.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import httpx
import pytest
from conftest import (
    ACCESS_TOKEN,
    CLIENT_ID,
    CLIENT_SECRET,
    REDIRECT_URI,
    STATE_SECRET,
)

from sillo_oauth import (
    DiscordOAuthProvider,
    GithubOAuthProvider,
    GoogleOAuthProvider,
    MicrosoftOAuthProvider,
    OAuthProfile,
    OAuthProvider,
    OAuthTokens,
    ProfileFetchFailed,
    ProviderMisconfigured,
    fetch_profile,
)

TOKENS = OAuthTokens(access_token=ACCESS_TOKEN)


def build(cls, stub, **kwargs):
    """Construct a provider of *cls* wired to *stub*."""
    kwargs.setdefault("client_id", CLIENT_ID)
    kwargs.setdefault("client_secret", CLIENT_SECRET)
    kwargs.setdefault("state_secret", STATE_SECRET)
    kwargs.setdefault("redirect_uri", REDIRECT_URI)
    kwargs.setdefault("transport", stub.transport)
    return cls(**kwargs)


class TestUserinfoRequest:
    """How the profile call is made."""

    async def test_sends_the_access_token(self, google, stub):
        await fetch_profile(google, TOKENS)

        request = stub.request_to(GoogleOAuthProvider.userinfo_endpoint)
        assert request.headers["authorization"] == f"Bearer {ACCESS_TOKEN}"

    async def test_uses_get(self, google, stub):
        await fetch_profile(google, TOKENS)

        assert stub.request_to(GoogleOAuthProvider.userinfo_endpoint).method == "GET"

    async def test_provider_specific_accept_header(self, stub):
        stub.route(
            GithubOAuthProvider.userinfo_endpoint, json={"id": 1, "email": "a@b.test"}
        )
        github = build(GithubOAuthProvider, stub)

        await fetch_profile(github, TOKENS)

        request = stub.request_to(GithubOAuthProvider.userinfo_endpoint)
        assert request.headers["accept"] == "application/vnd.github+json"

    async def test_provider_without_a_userinfo_endpoint(self, stub):
        provider = OAuthProvider(
            name="acme",
            client_id=CLIENT_ID,
            state_secret=STATE_SECRET,
            redirect_uri=REDIRECT_URI,
            authorize_endpoint="https://acme.test/authorize",
            token_endpoint="https://acme.test/token",
            transport=stub.transport,
        )

        with pytest.raises(ProviderMisconfigured, match="userinfo_endpoint"):
            await fetch_profile(provider, TOKENS)


class TestHeaderCustomisation:
    """Per-instance headers, without subclassing."""

    async def test_extra_userinfo_headers_are_sent(self, stub, google):
        provider = GoogleOAuthProvider(
            client_id=CLIENT_ID,
            state_secret=STATE_SECRET,
            redirect_uri=REDIRECT_URI,
            userinfo_headers={"X-Tenant": "acme"},
            transport=stub.transport,
        )

        await fetch_profile(provider, TOKENS)

        request = stub.request_to(GoogleOAuthProvider.userinfo_endpoint)
        assert request.headers["x-tenant"] == "acme"

    async def test_extra_headers_merge_rather_than_replace(self, stub, google):
        """Dropping Accept would make several providers answer non-JSON."""
        provider = GoogleOAuthProvider(
            client_id=CLIENT_ID,
            state_secret=STATE_SECRET,
            redirect_uri=REDIRECT_URI,
            userinfo_headers={"X-Tenant": "acme"},
            transport=stub.transport,
        )

        await fetch_profile(provider, TOKENS)

        request = stub.request_to(GoogleOAuthProvider.userinfo_endpoint)
        assert request.headers["accept"] == "application/json"

    async def test_a_default_header_can_still_be_overridden(self, stub, google):
        provider = GoogleOAuthProvider(
            client_id=CLIENT_ID,
            state_secret=STATE_SECRET,
            redirect_uri=REDIRECT_URI,
            userinfo_headers={"Accept": "application/ld+json"},
            transport=stub.transport,
        )

        await fetch_profile(provider, TOKENS)

        request = stub.request_to(GoogleOAuthProvider.userinfo_endpoint)
        assert request.headers["accept"] == "application/ld+json"

    async def test_authorization_cannot_be_overridden(self, stub, google):
        """The access token is not the application's to replace."""
        provider = GoogleOAuthProvider(
            client_id=CLIENT_ID,
            state_secret=STATE_SECRET,
            redirect_uri=REDIRECT_URI,
            userinfo_headers={"Authorization": "Bearer attacker-supplied"},
            transport=stub.transport,
        )

        await fetch_profile(provider, TOKENS)

        request = stub.request_to(GoogleOAuthProvider.userinfo_endpoint)
        assert request.headers["authorization"] == f"Bearer {ACCESS_TOKEN}"

    def test_instance_headers_do_not_leak_into_the_class(self, stub):
        """A plain dict here would be shared by every provider of the type."""
        before = dict(GoogleOAuthProvider.token_headers)

        GoogleOAuthProvider(
            client_id=CLIENT_ID,
            state_secret=STATE_SECRET,
            redirect_uri=REDIRECT_URI,
            token_headers={"X-One-Off": "yes"},
            transport=stub.transport,
        )

        assert dict(GoogleOAuthProvider.token_headers) == before

    def test_class_defaults_are_read_only(self):
        with pytest.raises(TypeError):
            GoogleOAuthProvider.token_headers["Accept"] = "text/plain"  # type: ignore[index]


class TestGoogleMapping:
    """Google's OIDC claims."""

    async def test_maps_every_field(self, google):
        profile = await fetch_profile(google, TOKENS)

        assert profile.provider == "google"
        assert profile.subject == "google-subject-1"
        assert profile.email == "ada@example.com"
        assert profile.email_verified is True
        assert profile.name == "Ada Lovelace"
        assert profile.avatar_url == "https://cdn.test/ada.png"

    async def test_unverified_email_is_reported_as_such(self, stub, google):
        stub.route(
            GoogleOAuthProvider.userinfo_endpoint,
            json={"sub": "s", "email": "a@b.test", "email_verified": False},
        )

        assert (await fetch_profile(google, TOKENS)).email_verified is False

    async def test_absent_email_verified_claim_is_not_trusted(self, stub, google):
        """ "Did not say" and "said no" must both mean unverified."""
        stub.route(
            GoogleOAuthProvider.userinfo_endpoint,
            json={"sub": "s", "email": "a@b.test"},
        )

        assert (await fetch_profile(google, TOKENS)).email_verified is False

    async def test_raw_payload_is_preserved(self, stub, google):
        stub.route(
            GoogleOAuthProvider.userinfo_endpoint,
            json={"sub": "s", "hd": "example.com"},
        )

        profile = await fetch_profile(google, TOKENS)

        assert profile.raw["hd"] == "example.com"

    async def test_tokens_are_attached(self, google):
        profile = await fetch_profile(google, TOKENS)

        assert profile.tokens is not None
        assert profile.tokens.access_token == ACCESS_TOKEN


class TestGithubMapping:
    """GitHub's user payload, including the private-email detour."""

    async def test_maps_id_login_and_avatar(self, stub):
        stub.route(
            GithubOAuthProvider.userinfo_endpoint,
            json={
                "id": 4242,
                "login": "ada",
                "name": "Ada Lovelace",
                "email": "ada@example.com",
                "avatar_url": "https://cdn.test/ada.png",
            },
        )
        github = build(GithubOAuthProvider, stub)

        profile = await fetch_profile(github, TOKENS)

        assert profile.subject == "4242", "numeric ids are normalised to strings"
        assert profile.username == "ada"
        assert profile.name == "Ada Lovelace"
        assert profile.email == "ada@example.com"
        assert profile.avatar_url == "https://cdn.test/ada.png"

    async def test_falls_back_to_the_emails_endpoint(self, stub):
        """GitHub omits the address when the user keeps it private."""
        stub.route(
            GithubOAuthProvider.userinfo_endpoint,
            json={"id": 4242, "login": "ada", "email": None},
        )
        stub.route(
            GithubOAuthProvider.emails_endpoint,
            json=[
                {"email": "old@example.com", "primary": False, "verified": True},
                {"email": "ada@example.com", "primary": True, "verified": True},
            ],
        )
        github = build(GithubOAuthProvider, stub)

        profile = await fetch_profile(github, TOKENS)

        assert profile.email == "ada@example.com"
        assert profile.email_verified is True

    async def test_does_not_call_the_emails_endpoint_when_not_needed(self, stub):
        stub.route(
            GithubOAuthProvider.userinfo_endpoint,
            json={"id": 4242, "login": "ada", "email": "ada@example.com"},
        )
        github = build(GithubOAuthProvider, stub)

        await fetch_profile(github, TOKENS)

        urls = [str(request.url) for request in stub.requests]
        assert GithubOAuthProvider.emails_endpoint not in urls

    async def test_ignores_unverified_primary_addresses(self, stub):
        stub.route(
            GithubOAuthProvider.userinfo_endpoint,
            json={"id": 4242, "login": "ada", "email": None},
        )
        stub.route(
            GithubOAuthProvider.emails_endpoint,
            json=[{"email": "ada@example.com", "primary": True, "verified": False}],
        )
        github = build(GithubOAuthProvider, stub)

        profile = await fetch_profile(github, TOKENS)

        assert profile.email is None
        assert profile.email_verified is False

    async def test_ignores_verified_non_primary_addresses(self, stub):
        stub.route(
            GithubOAuthProvider.userinfo_endpoint,
            json={"id": 4242, "login": "ada", "email": None},
        )
        stub.route(
            GithubOAuthProvider.emails_endpoint,
            json=[{"email": "other@example.com", "primary": False, "verified": True}],
        )
        github = build(GithubOAuthProvider, stub)

        assert (await fetch_profile(github, TOKENS)).email is None

    async def test_login_still_succeeds_when_the_email_scope_was_refused(self, stub):
        """A 403 on the emails endpoint must not fail an otherwise fine login."""
        stub.route(
            GithubOAuthProvider.userinfo_endpoint,
            json={"id": 4242, "login": "ada", "email": None},
        )
        stub.route(
            GithubOAuthProvider.emails_endpoint,
            json={"message": "Forbidden"},
            status=403,
        )
        github = build(GithubOAuthProvider, stub)

        profile = await fetch_profile(github, TOKENS)

        assert profile.subject == "4242"
        assert profile.email is None

    async def test_login_still_succeeds_when_the_emails_endpoint_is_down(self, stub):
        stub.route(
            GithubOAuthProvider.userinfo_endpoint,
            json={"id": 4242, "login": "ada", "email": None},
        )
        stub.fail(GithubOAuthProvider.emails_endpoint)
        github = build(GithubOAuthProvider, stub)

        assert (await fetch_profile(github, TOKENS)).email is None

    async def test_malformed_emails_response_is_ignored(self, stub):
        stub.route(
            GithubOAuthProvider.userinfo_endpoint,
            json={"id": 4242, "login": "ada", "email": None},
        )
        stub.route(GithubOAuthProvider.emails_endpoint, json={"not": "a list"})
        github = build(GithubOAuthProvider, stub)

        assert (await fetch_profile(github, TOKENS)).email is None


class TestDiscordMapping:
    """Discord's payload, including the avatar hash."""

    async def test_builds_the_cdn_avatar_url(self, stub):
        stub.route(
            DiscordOAuthProvider.userinfo_endpoint,
            json={
                "id": "80351110224678912",
                "username": "ada",
                "global_name": "Ada L",
                "avatar": "8342729096ea3675442027381ff50dfe",
                "email": "ada@example.com",
                "verified": True,
            },
        )
        discord = build(DiscordOAuthProvider, stub)

        profile = await fetch_profile(discord, TOKENS)

        assert profile.avatar_url == (
            "https://cdn.discordapp.com/avatars/80351110224678912/"
            "8342729096ea3675442027381ff50dfe.png"
        )
        assert profile.name == "Ada L"
        assert profile.username == "ada"
        assert profile.email_verified is True

    async def test_avatar_is_none_when_the_hash_is_absent(self, stub):
        stub.route(
            DiscordOAuthProvider.userinfo_endpoint,
            json={"id": "1", "username": "ada", "avatar": None},
        )
        discord = build(DiscordOAuthProvider, stub)

        assert (await fetch_profile(discord, TOKENS)).avatar_url is None

    async def test_falls_back_to_username_when_there_is_no_global_name(self, stub):
        stub.route(
            DiscordOAuthProvider.userinfo_endpoint,
            json={"id": "1", "username": "ada", "global_name": None},
        )
        discord = build(DiscordOAuthProvider, stub)

        assert (await fetch_profile(discord, TOKENS)).name == "ada"


class TestMicrosoftMapping:
    """Microsoft's userinfo claims."""

    async def test_maps_sub_and_email(self, stub):
        stub.route(
            MicrosoftOAuthProvider.userinfo_endpoint,
            json={
                "sub": "ms-subject-1",
                "email": "ada@contoso.test",
                "name": "Ada Lovelace",
            },
        )
        microsoft = build(MicrosoftOAuthProvider, stub)

        profile = await fetch_profile(microsoft, TOKENS)

        assert profile.subject == "ms-subject-1"
        assert profile.email == "ada@contoso.test"

    async def test_falls_back_to_upn(self, stub):
        stub.route(
            MicrosoftOAuthProvider.userinfo_endpoint,
            json={"sub": "s", "upn": "ada@contoso.test"},
        )
        microsoft = build(MicrosoftOAuthProvider, stub)

        assert (await fetch_profile(microsoft, TOKENS)).email == "ada@contoso.test"

    async def test_email_is_never_reported_as_verified(self, stub):
        """The endpoint states nothing, and unstated must not read as verified."""
        stub.route(
            MicrosoftOAuthProvider.userinfo_endpoint,
            json={"sub": "s", "email": "ada@contoso.test", "email_verified": True},
        )
        microsoft = build(MicrosoftOAuthProvider, stub)

        assert (await fetch_profile(microsoft, TOKENS)).email_verified is False


class TestGenericMapping:
    """The base provider's best-guess mapping."""

    async def test_finds_the_subject_under_sub(self, generic, stub):
        stub.route("https://acme.test/api/me", json={"sub": "abc"})

        assert (await fetch_profile(generic, TOKENS)).subject == "abc"

    async def test_finds_the_subject_under_id(self, generic, stub):
        stub.route("https://acme.test/api/me", json={"id": 77})

        assert (await fetch_profile(generic, TOKENS)).subject == "77"

    async def test_finds_the_subject_under_user_id(self, generic, stub):
        stub.route("https://acme.test/api/me", json={"user_id": "u-1"})

        assert (await fetch_profile(generic, TOKENS)).subject == "u-1"

    async def test_prefers_sub_over_id(self, generic, stub):
        stub.route("https://acme.test/api/me", json={"sub": "oidc", "id": "rest"})

        assert (await fetch_profile(generic, TOKENS)).subject == "oidc"

    async def test_picks_up_common_optional_fields(self, generic, stub):
        stub.route(
            "https://acme.test/api/me",
            json={
                "sub": "abc",
                "email": "ada@acme.test",
                "email_verified": True,
                "name": "Ada",
                "preferred_username": "ada",
                "picture": "https://cdn.test/a.png",
            },
        )

        profile = await fetch_profile(generic, TOKENS)

        assert profile.email == "ada@acme.test"
        assert profile.username == "ada"
        assert profile.avatar_url == "https://cdn.test/a.png"

    async def test_zero_is_a_valid_subject(self, generic, stub):
        """Falsy but present — a truthiness check here would drop it."""
        stub.route("https://acme.test/api/me", json={"id": 0})

        assert (await fetch_profile(generic, TOKENS)).subject == "0"


class TestCustomMapper:
    """Replacing the mapping without subclassing."""

    async def test_profile_mapper_overrides_the_default(self, stub):
        provider = OAuthProvider(
            name="acme",
            client_id=CLIENT_ID,
            state_secret=STATE_SECRET,
            redirect_uri=REDIRECT_URI,
            authorize_endpoint="https://acme.test/authorize",
            token_endpoint="https://acme.test/token",
            userinfo_endpoint="https://acme.test/api/me",
            transport=stub.transport,
            profile_mapper=lambda raw: {
                "subject": raw["employee_number"],
                "email": raw["work_email"],
                "name": raw["full_name"],
            },
        )
        stub.route(
            "https://acme.test/api/me",
            json={
                "employee_number": "E-1",
                "work_email": "ada@acme.test",
                "full_name": "Ada Lovelace",
            },
        )

        profile = await fetch_profile(provider, TOKENS)

        assert profile.subject == "E-1"
        assert profile.email == "ada@acme.test"
        assert profile.name == "Ada Lovelace"

    async def test_mapper_cannot_forge_the_provider_name(self, stub):
        """The provider vouching for an identity is not the mapper's to set."""
        provider = OAuthProvider(
            name="acme",
            client_id=CLIENT_ID,
            state_secret=STATE_SECRET,
            redirect_uri=REDIRECT_URI,
            authorize_endpoint="https://acme.test/authorize",
            token_endpoint="https://acme.test/token",
            userinfo_endpoint="https://acme.test/api/me",
            transport=stub.transport,
            profile_mapper=lambda raw: {"subject": "s", "provider": "google"},
        )
        stub.route("https://acme.test/api/me", json={})

        assert (await fetch_profile(provider, TOKENS)).provider == "acme"

    async def test_subclass_can_override_map_profile(self, stub):
        class AcmeProvider(OAuthProvider):
            name = "acme"
            authorize_endpoint = "https://acme.test/authorize"
            token_endpoint = "https://acme.test/token"
            userinfo_endpoint = "https://acme.test/api/me"

            def map_profile(self, raw):
                return {"subject": raw["uuid"], "name": raw["display"]}

        stub.route("https://acme.test/api/me", json={"uuid": "u-9", "display": "Ada"})
        provider = build(AcmeProvider, stub)

        profile = await fetch_profile(provider, TOKENS)

        assert profile.subject == "u-9"
        assert profile.name == "Ada"


class TestProfileFailures:
    """Responses that cannot produce a usable identity."""

    async def test_missing_subject_is_fatal(self, generic, stub):
        """A profile with no stable id has nothing to key an account on."""
        stub.route("https://acme.test/api/me", json={"email": "ada@acme.test"})

        with pytest.raises(ProfileFetchFailed, match="no account identifier"):
            await fetch_profile(generic, TOKENS)

    async def test_empty_response_is_fatal(self, generic, stub):
        stub.route("https://acme.test/api/me", json={})

        with pytest.raises(ProfileFetchFailed):
            await fetch_profile(generic, TOKENS)

    async def test_rejected_token(self, generic, stub):
        stub.route("https://acme.test/api/me", json={"error": "invalid"}, status=401)

        with pytest.raises(ProfileFetchFailed, match="rejected"):
            await fetch_profile(generic, TOKENS)

    async def test_non_json_response(self, generic, stub):
        stub.route(
            "https://acme.test/api/me",
            text="<html>oops</html>",
            content_type="text/html",
        )

        with pytest.raises(ProfileFetchFailed, match="not JSON"):
            await fetch_profile(generic, TOKENS)

    async def test_json_array_response(self, generic, stub):
        stub.route("https://acme.test/api/me", json=[1, 2, 3])

        with pytest.raises(ProfileFetchFailed, match="not a JSON object"):
            await fetch_profile(generic, TOKENS)

    async def test_unreachable_endpoint(self, generic, stub):
        stub.fail("https://acme.test/api/me", httpx.ConnectTimeout("slow"))

        with pytest.raises(ProfileFetchFailed, match="Could not reach"):
            await fetch_profile(generic, TOKENS)


class TestProfileModel:
    """Behaviour on the profile itself."""

    def test_key_combines_provider_and_subject(self):
        profile = OAuthProfile(provider="google", subject="123")

        assert profile.key == "google:123"

    def test_key_distinguishes_identical_subjects_across_providers(self):
        """The same numeric id at two providers is two different people."""
        first = OAuthProfile(provider="google", subject="42")
        second = OAuthProfile(provider="github", subject="42")

        assert first.key != second.key

    def test_profile_is_immutable(self):
        """A verified identity must not be editable after the fact."""
        profile = OAuthProfile(provider="google", subject="123")

        with pytest.raises(FrozenInstanceError):
            profile.subject = "456"  # type: ignore[misc]

    def test_defaults_are_conservative(self):
        profile = OAuthProfile(provider="google", subject="123")

        assert profile.email is None
        assert profile.email_verified is False
        assert profile.tokens is None
        assert profile.return_to is None
