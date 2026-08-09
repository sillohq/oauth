# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] — 2026-08-09

### Changed

- **Requires `sillo-framework>=0.0.2a1`**, where the application class was
  renamed from `silloApp` to `SilloApp`.

  Nothing in `sillo_oauth` names that class — the API is plain functions
  taking a `Request`, and the README shows handlers rather than an
  application — so no code here changed. The floor moves for two narrower
  reasons: the integration suite builds a real Sillo app and so cannot run
  against an older core, and 0.1.1 is tested against 0.0.2a1 and nothing
  below it.

  If you are still on `silloApp`, it keeps working under 0.0.2a1 with a
  `DeprecationWarning` and is removed in sillo-core 0.1.0.

### Fixed

- **A release could ship with `sillo_oauth.__version__` reporting the wrong
  version.** The release workflow compared the tag against `pyproject.toml`
  only, and `__version__` is exported — so a bump that missed it would
  publish and report success. The check now covers both.

## [0.1.0] — 2026-08-08

First release. The package was written and then reviewed in one sitting, so
the fixes below are against unreleased commits rather than against anything
anyone installed — they are kept because two of them are worth a reader's
attention, and because the reasoning is the useful part.

Requires `sillo-framework>=0.0.1a15`. That is still an alpha, so this release
is only as stable as the framework under it; the API here is what is being
called stable at 0.1.0, not the ground it stands on.

### Added

- `refresh_tokens()`, and `OAuthProvider.refresh_request_data()` as the
  provider-level hook. `OAuthTokens.refresh_token` had been captured since the
  first commit with no way to spend it. When a provider does not rotate the
  refresh token — most reuse it and omit it from the response — the one passed
  in is carried onto the result, so a caller that stores
  `tokens.refresh_token` cannot overwrite a working token with `None`.
- `exchange(..., state_value=...)`, for applications that keep the state in the
  session or a cache rather than the cookie.
- `token_headers` and `userinfo_headers` constructor arguments, merged over the
  class defaults so adding one header does not mean restating the `Accept` that
  several providers need in order to answer with JSON.
- `GithubOAuthProvider(emails_endpoint=...)`.
- `py.typed`, so the annotations are visible to downstream type checkers.
- CI across Python 3.10–3.13, gating on tests, `ruff check`, `ruff format` and
  `mypy`, plus a packaging job that asserts the built wheel contains
  `py.typed`.

### Fixed

- **Authorize parameters that the package manages are now refused instead of
  overridden.** `extra_params` and `authorize_params` were merged *over* the
  computed parameters, so `extra_params={"state": ...}` replaced the value the
  cookie had just been signed against. At best every login failed as a
  mismatch; at worst an attacker-chosen value was sent and the CSRF guarantee
  quietly stopped holding. The same applied to `code_challenge` and PKCE.
- **`OAuthTokens` no longer prints its credentials.** Every field on it is a
  live token and the generated dataclass repr showed all of them, so
  `logger.info("signed in %s", profile)` wrote a working access token to the
  log, as did any traceback holding a profile in a frame.
- **GitHub's emails endpoint follows `userinfo_endpoint`.** It was hardcoded to
  `api.github.com`, so pointing the provider at a GitHub Enterprise host moved
  only half the flow and sent an Enterprise access token to the public API.
- **An endpoint's own query no longer duplicates a managed parameter.** A
  configured `authorize_endpoint` carrying `state=` got ours appended after it,
  producing a URL with the parameter twice and leaving the provider to choose.
- **`expires_in` is read in whatever shape the provider sent.** The old guard
  silently dropped every lifetime that was not a plain non-negative integer
  literal, including the decimals and numeric strings that providers do send.
  Negatives and booleans are still dropped deliberately.
- Class-level header mappings are `MappingProxyType`. As plain dicts they were
  shared by every instance, so mutating one to add a header to a single
  provider changed every other provider of that type.
- Two documented examples that would have failed if anyone ran them: the module
  docstring set the cookie before the redirect, which sillo's `Responder`
  cannot do, and the session example called `Session.pop()`, which does not
  exist.

### Security notes

Two of the fixes above would have been advisories had they shipped, and are
called out here for anyone auditing the history:

- `extra_params` could override `state` and `code_challenge`, disarming CSRF
  and PKCE.
- `OAuthTokens`' repr printed live credentials into logs and tracebacks.

[0.1.0]: https://github.com/sillohq/oauth/releases/tag/oauth-v0.1.0
