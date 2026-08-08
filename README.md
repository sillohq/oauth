# sillo-oauth

[![Test](https://github.com/sillohq/oauth/actions/workflows/test.yml/badge.svg)](https://github.com/sillohq/oauth/actions/workflows/test.yml)

OAuth 2.0 and OpenID Connect login for [Sillo](https://github.com/sillohq/core).

Two functions and a provider object. Neither function takes a response, builds
one, or registers a route — so the routes, the error handling, and the decision
of what a login *means* stay in your application.

```bash
pip install sillo-oauth
```

## The whole API

```python
from sillo_oauth import GoogleOAuthProvider, authorize_url, exchange, OAuthError

google = GoogleOAuthProvider(
    client_id=...,
    client_secret=...,
    state_secret=...,  # signs the state cookie; your own key
    redirect_uri="https://example.com/auth/google/callback",
)


@app.get("/auth/google/redirect")
async def start(request, response):
    authorize = authorize_url(google)
    return response.redirect(authorize.url).set_cookie(**authorize.cookie_kwargs())


@app.get("/auth/google/callback")
async def finish(request, response):
    try:
        profile = await exchange(google, request)
    except OAuthError as exc:
        return response.redirect(f"/login?error={exc.code}")

    user = await User.objects.get_or_create_from_oauth("google", profile)
    login(request, user)
    return response.redirect(profile.return_to or "/")
```

That is the entire integration. `authorize_url` is pure — no request, no I/O —
and returns a URL plus the state you need to store. `exchange` reads the
callback request and returns a verified `OAuthProfile`. Nothing else is
implied.

> **Local development over `http://`** needs `cookie_kwargs(secure=False)`.
> Otherwise the browser accepts the `Secure` cookie and never sends it back,
> and every callback fails as a state mismatch.

## What it deliberately does not do

Turning a verified external identity into a logged-in user is your
application's decision, not this package's. So there is no `on_success` hook,
no user model, no session handling — just the four lines after `exchange`:

```python
# a server-rendered app
login(request, user)
return response.redirect("/dashboard")

# an SPA or mobile client
token = create_jwt({"id": user.id}, SECRET)
return response.json({"access_token": token})

# linking a provider to the user who is already signed in
await OAuthIdentity.objects.link(request.user, "github", profile.subject)

# nothing at all — just prove the address
return response.json({"verified_email": profile.email})
```

The same two functions serve all of them.

## Providers

`GoogleOAuthProvider`, `GithubOAuthProvider`, `DiscordOAuthProvider` and
`MicrosoftOAuthProvider` ship with endpoints, scopes and profile mapping
filled in. Every one of those is overridable per instance.

Anything else uses `OAuthProvider` directly:

```python
gitlab = OAuthProvider(
    name="gitlab",
    client_id=...,
    client_secret=...,
    state_secret=...,
    authorize_endpoint="https://gitlab.com/oauth/authorize",
    token_endpoint="https://gitlab.com/oauth/token",
    userinfo_endpoint="https://gitlab.com/api/v4/user",
    scopes=["read_user"],
)
```

Self-hosted installations override the endpoints, and everything derived from
them follows — pointing GitHub at an Enterprise host also moves the address
lookup it falls back to:

```python
github = GithubOAuthProvider(
    ...,
    userinfo_endpoint="https://github.acme-corp.test/api/v3/user",
)
```

Extra headers are merged over the provider's defaults, so adding one does not
mean restating the rest:

```python
acme = OAuthProvider(..., userinfo_headers={"X-Tenant": "acme"})
```

To map a provider's fields yourself, pass `profile_mapper` or subclass and
override `map_profile`:

```python
acme = OAuthProvider(
    ...,
    profile_mapper=lambda raw: {
        "subject": raw["employee_number"],
        "email": raw["work_email"],
        "name": raw["full_name"],
    },
)
```

## `OAuthProfile`

```python
profile.provider  # "google"
profile.subject  # stable provider-side id — the only safe account key
profile.key  # "google:112233" — unique across providers
profile.email
profile.email_verified  # False also means "the provider did not say"
profile.name
profile.username
profile.avatar_url
profile.raw  # the untouched userinfo payload
profile.tokens  # access/refresh tokens, for calling the provider later
profile.return_to  # whatever you passed to authorize_url(return_to=...)
```

Key accounts on `subject`, never on `email`: addresses get reassigned, and an
unverified one is an account-takeover vector.

## Errors

Every failure raises an `OAuthError` subclass carrying a stable, URL-safe
`.code`, so one `except` is enough and codes can go straight into a redirect.

| `.code` | Raised when |
|---|---|
| `denied` | The person declined consent. Not a fault — send them back to the login page. |
| `provider_error` | The provider reported some other `error` parameter. |
| `state_mismatch` | The callback does not match a redirect this server issued: no cookie, no `state`, a forged or tampered cookie, or one minted for another provider. |
| `state_expired` | Genuine state, but too old. Worth a "that took too long, try again". |
| `exchange_failed` | The provider would not trade the code for a token. |
| `profile_failed` | A token was issued but no usable profile came back. |
| `provider_misconfigured` | Programming error — a missing secret, redirect URI, or endpoint. |

## Security

* **State is signed, not stored.** No session store, no database, no sticky
  routing — the CSRF token rides in an HMAC-signed cookie carrying an expiry
  and the provider name, so a cookie minted for one provider cannot complete
  another's callback.
* **PKCE verifiers are derived, never stored.** The verifier is recomputed at
  exchange time as `HMAC(state_secret, state)`. Putting it in the cookie would
  have placed a secret somewhere readable; keeping it server-side would have
  reintroduced the state store. The provider only ever sees the S256
  challenge.
* **State is verified before anything is sent to the provider**, so a forged
  callback cannot make your server issue a token request.
* Reserved parameters (`state`, `code_challenge`, `client_id`, …) cannot be
  overridden through `extra_params`. Supplying one raises rather than being
  ignored, because an application that believes it is setting `state` and
  silently is not has a security expectation the code no longer meets.
* **Tokens are redacted from reprs.** `logger.info("signed in %s", profile)` is
  an ordinary line to write, and an error tracker collects tracebacks holding
  profiles in frames. Neither leaks a credential; attribute access is
  unaffected.

`state_secret` is unrelated to `client_secret`: it protects your own cookies,
not your relationship with the provider. Any high-entropy application key
works, and one can be shared across providers.

## Lower-level entry points

`exchange(provider, request)` is a convenience over functions that take no
request at all, for callers whose callback did not arrive as a Sillo request —
a worker, a CLI, a test:

```python
profile = await complete(provider, code=..., state=..., cookie_value=...)
tokens = await exchange_code(provider, code=..., verifier=...)
profile = await fetch_profile(provider, tokens)
tokens = await refresh_tokens(provider, refresh_token=...)
```

Storing state somewhere other than a cookie works the same way — hand the
stored value back explicitly:

```python
# at the redirect step
request.session["oauth_state"] = authorize.cookie_value

# at the callback — sillo's Session has get/delete, not pop
stored = request.session.get("oauth_state")
request.session.delete("oauth_state")
profile = await exchange(google, request, state_value=stored)
```

## Development

```bash
pip install -e ".[dev]"
pytest              # 240+ tests, no network
ruff check .
ruff format --check .
mypy sillo_oauth/
```

The suite never touches the network and never needs real credentials. Provider
responses are canned through an injected `httpx` transport, and an autouse
fixture breaks the real transport so a test that forgets a stub fails loudly
instead of reaching out to Google.

## Licence

BSD-3-Clause.
