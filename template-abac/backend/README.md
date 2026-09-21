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

## Password length

Passwords are checked by length only (no composition rules, per NIST SP
800-63B), counted in characters. Two settings control it:

| Setting | Default | Meaning |
| --- | --- | --- |
| `KALEKIT_PASSWORD_MIN_LENGTH` | `12` | Shortest password accepted when one is set |
| `KALEKIT_PASSWORD_MAX_LENGTH` | `128` | Longest password accepted anywhere |

Register returns `422` when the password is outside the range. Login
enforces only the maximum: an oversized password gets the same
`401 Invalid credentials` as a wrong one, without running the hash, and
existing accounts with shorter passwords can still sign in. The rule
lives in `kalekit/auth/password_policy.py`; any endpoint that sets a
password should use its `NewPassword` type.

## Access token issuer

Access tokens carry an `iss` claim set from `KALEKIT_JWT_ISSUER` (default
`kalekit`), and verification rejects any token whose `iss` is missing or
different. Set a distinct value per environment so a token minted by
another service or environment that shares the signing key is not
accepted here. Changing it invalidates outstanding access tokens; clients
recover by refreshing (refresh tokens are opaque and unaffected).
