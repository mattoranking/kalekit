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
├── cli.py           # operator commands (create-admin), run out of band
└── utils/db/        # declarative base, engine factories
```

## Creating an admin

Self-signup (password or OAuth) never grants the `admin` role -- everyone
starts as `visitor`. To create the first admin, or promote an existing
user, run:

```bash
uv run python -m kalekit.cli create-admin --email you@example.com --password 'a strong one'
```

If a user with that email already exists, `--password` is ignored and
they're promoted in place; otherwise it's required and a new, pre-verified
admin user is created directly.
