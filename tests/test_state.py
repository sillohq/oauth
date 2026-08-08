"""State cookies and PKCE derivation.

This is the security boundary of the whole package: everything else assumes
that a callback which clears :func:`verify_state` really was started by this
server. The tests below try to get past it.
"""

from __future__ import annotations

import base64
import hashlib
import json

import pytest
from sillo.helpers.crypto import sign_value

from sillo_oauth import (
    StateExpired,
    StateMismatch,
    derive_verifier,
    issue_state,
    pkce_challenge,
    verify_state,
)

SECRET = "state-signing-secret"
OTHER_SECRET = "a-different-secret"


class TestIssueState:
    """Minting a state value."""

    def test_returns_state_and_signed_cookie(self):
        state, cookie = issue_state("google", SECRET)

        assert state
        assert cookie
        assert state != cookie, "the cookie must carry more than the bare state"

    def test_state_is_unguessable_and_unique(self):
        values = {issue_state("google", SECRET)[0] for _ in range(100)}

        assert len(values) == 100, "state values must not repeat"
        # 32 random bytes, base64url without padding.
        assert all(len(value) == 43 for value in values)

    def test_state_is_url_safe(self):
        state, _ = issue_state("google", SECRET)

        assert "+" not in state
        assert "/" not in state
        assert "=" not in state

    def test_cookie_does_not_contain_the_secret(self):
        _, cookie = issue_state("google", SECRET)

        assert SECRET not in cookie
        assert (
            SECRET
            not in base64.urlsafe_b64decode(cookie.partition(".")[0] + "==").decode()
        )

    def test_return_to_is_carried(self):
        state, cookie = issue_state("google", SECRET, return_to="/dashboard")

        assert verify_state(cookie, state, "google", SECRET).return_to == "/dashboard"

    def test_return_to_defaults_to_none(self):
        state, cookie = issue_state("google", SECRET)

        assert verify_state(cookie, state, "google", SECRET).return_to is None


class TestVerifyState:
    """Accepting a genuine callback."""

    def test_round_trip(self):
        state, cookie = issue_state("google", SECRET)

        payload = verify_state(cookie, state, "google", SECRET)

        assert payload.state == state
        assert payload.provider == "google"

    def test_accepts_just_before_expiry(self):
        state, cookie = issue_state("google", SECRET, ttl=600, now=1000.0)

        payload = verify_state(cookie, state, "google", SECRET, now=1599.0)

        assert payload.state == state


class TestVerifyStateRejects:
    """Everything that must not get through."""

    def test_missing_cookie(self):
        state, _ = issue_state("google", SECRET)

        with pytest.raises(StateMismatch):
            verify_state(None, state, "google", SECRET)

    def test_empty_cookie(self):
        state, _ = issue_state("google", SECRET)

        with pytest.raises(StateMismatch):
            verify_state("", state, "google", SECRET)

    def test_missing_state_parameter(self):
        _, cookie = issue_state("google", SECRET)

        with pytest.raises(StateMismatch):
            verify_state(cookie, None, "google", SECRET)

    def test_state_parameter_does_not_match_cookie(self):
        _, cookie = issue_state("google", SECRET)
        other_state, _ = issue_state("google", SECRET)

        with pytest.raises(StateMismatch):
            verify_state(cookie, other_state, "google", SECRET)

    def test_cookie_signed_with_another_secret(self):
        state, cookie = issue_state("google", OTHER_SECRET)

        with pytest.raises(StateMismatch):
            verify_state(cookie, state, "google", SECRET)

    def test_forged_cookie_with_no_signature(self):
        payload = json.dumps({"s": "attacker", "p": "google", "e": 9e9})
        forged = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")

        with pytest.raises(StateMismatch):
            verify_state(forged, "attacker", "google", SECRET)

    def test_tampered_payload_keeping_the_original_signature(self):
        state, cookie = issue_state("google", SECRET)
        _, _, signature = cookie.rpartition(".")
        swapped = json.dumps({"s": "attacker", "p": "google", "e": 9e9})
        tampered = (
            base64.urlsafe_b64encode(swapped.encode()).decode().rstrip("=")
            + "."
            + signature
        )

        with pytest.raises(StateMismatch):
            verify_state(tampered, "attacker", "google", SECRET)

    def test_cookie_issued_for_another_provider(self):
        """A GitHub cookie must not satisfy a Google callback.

        Without the provider binding, an application offering two providers
        could have a login started at the weaker one completed at the
        stronger one's callback.
        """
        state, cookie = issue_state("github", SECRET)

        with pytest.raises(StateMismatch):
            verify_state(cookie, state, "google", SECRET)

    def test_expired_cookie(self):
        state, cookie = issue_state("google", SECRET, ttl=600, now=1000.0)

        with pytest.raises(StateExpired):
            verify_state(cookie, state, "google", SECRET, now=1601.0)

    def test_expiry_is_reported_separately_from_mismatch(self):
        """Expiry gets its own code so callers can say "try again"."""
        state, cookie = issue_state("google", SECRET, ttl=1, now=0.0)

        with pytest.raises(StateExpired) as caught:
            verify_state(cookie, state, "google", SECRET, now=100.0)

        assert caught.value.code == "state_expired"
        assert caught.value.provider == "google"

    def test_signed_payload_that_is_not_a_json_object(self):
        cookie = sign_value(json.dumps(["not", "an", "object"]), SECRET)

        with pytest.raises(StateMismatch):
            verify_state(cookie, "whatever", "google", SECRET)

    def test_signed_payload_that_is_not_json(self):
        cookie = sign_value("plain text", SECRET)

        with pytest.raises(StateMismatch):
            verify_state(cookie, "whatever", "google", SECRET)

    def test_signed_payload_with_a_non_numeric_expiry(self):
        state = "abc"
        cookie = sign_value(
            json.dumps({"s": state, "p": "google", "e": "soon"}), SECRET
        )

        with pytest.raises(StateMismatch):
            verify_state(cookie, state, "google", SECRET)

    def test_signed_payload_with_a_non_string_state(self):
        cookie = sign_value(json.dumps({"s": 42, "p": "google", "e": 9e9}), SECRET)

        with pytest.raises(StateMismatch):
            verify_state(cookie, "42", "google", SECRET)

    def test_garbage_cookie(self):
        with pytest.raises(StateMismatch):
            verify_state("......", "state", "google", SECRET)


class TestPKCE:
    """Verifier derivation and challenge computation."""

    def test_verifier_is_deterministic(self):
        state, _ = issue_state("google", SECRET)

        assert derive_verifier(state, SECRET) == derive_verifier(state, SECRET)

    def test_verifier_depends_on_the_state(self):
        first, _ = issue_state("google", SECRET)
        second, _ = issue_state("google", SECRET)

        assert derive_verifier(first, SECRET) != derive_verifier(second, SECRET)

    def test_verifier_depends_on_the_secret(self):
        """Knowing the state must not be enough to compute the verifier.

        This is what makes derivation safe: the state travels through the
        provider and the browser in the clear, so if the verifier followed
        from it alone, PKCE would protect nothing.
        """
        state, _ = issue_state("google", SECRET)

        assert derive_verifier(state, SECRET) != derive_verifier(state, OTHER_SECRET)

    def test_verifier_meets_rfc7636_length(self):
        state, _ = issue_state("google", SECRET)

        assert 43 <= len(derive_verifier(state, SECRET)) <= 128

    def test_verifier_uses_only_permitted_characters(self):
        allowed = set(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
        )
        state, _ = issue_state("google", SECRET)

        assert set(derive_verifier(state, SECRET)) <= allowed

    def test_challenge_is_the_s256_of_the_verifier(self):
        verifier = derive_verifier("some-state", SECRET)
        expected = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .decode()
            .rstrip("=")
        )

        assert pkce_challenge(verifier) == expected

    def test_challenge_is_not_the_verifier(self):
        verifier = derive_verifier("some-state", SECRET)

        assert pkce_challenge(verifier) != verifier
