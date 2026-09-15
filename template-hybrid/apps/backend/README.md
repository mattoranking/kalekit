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
