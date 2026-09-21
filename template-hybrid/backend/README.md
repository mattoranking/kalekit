# kalekit backend

FastAPI application for the Kalekit property-viewing service.

Run tasks from the repo root via the `Makefile` (`make help`), or directly here
with `uv run …`. See the [root README](../README.md) for setup.

## Package layout

```
kalekit/
├── main.py          # app factory + lifespan (engines, sessionmakers)
├── api.py           # /v1 router — mounts auth, oauth, users
├── config.py        # pydantic-settings, KALEKIT_ env prefix
├── postgres.py      # engine/session helpers + per-request session middleware
├── auth/            # register / login / refresh / logout, JWT, RBAC, scopes
├── oauth/           # OAuth2 authorization-code flow (GitHub, Google, X)
├── user/            # user read/update
├── models/          # SQLAlchemy models (User, Role, RefreshToken, OAuthAccount)
├── health/          # /health
└── utils/db/        # declarative base, engine factories
```

## OAuth sign-in stores no provider tokens

Google, GitHub and X are used for login only. The callback exchanges the code
and reads the profile in memory; `OAuthAccount` keeps just `platform`,
`account_id` (the provider's stable id, which matches a returning user),
`account_email` and `user_id`. Kalekit issues its own access and refresh tokens.

If you later need to call a provider's API on the user's behalf, add an
encrypted token store first; do not put tokens back in plain columns. Sign in
with Apple (#19) will need one to revoke tokens when an account is deleted.
