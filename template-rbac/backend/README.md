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

## Password length

Passwords are checked by length only (no composition rules, per NIST SP
800-63B), counted in characters. Two settings control it:

| Setting | Default | Meaning |
| --- | --- | --- |
| `KALEKIT_PASSWORD_MIN_LENGTH` | `12` | Shortest password accepted when one is set |
| `KALEKIT_PASSWORD_MAX_LENGTH` | `128` | Longest password accepted anywhere |

Register, change-password and reset-password return `422` when the new
password is outside the range (the `create-admin` command applies the
same rule). Login enforces only the maximum: an oversized password gets
the same `401 Invalid credentials` as a wrong one, without running the
hash, and existing accounts with shorter passwords can still sign in and
change them. The rule lives in `kalekit/auth/password_policy.py`; new
endpoints that set a password should use its `NewPassword` type.

## Refresh token retention

Every refresh, and every login/OAuth exchange, inserts a new `refresh_tokens`
row (see `kalekit/models/refresh_token.py` and the rotation flow in
`kalekit/auth/endpoints.py`); rows are never deleted automatically. Left
alone, a long-lived, regularly-used account's row count grows unbounded.

`GET /v1/auth/sessions` (`kalekit.auth.repository.list_user_sessions`) only
ever reads currently-usable rows -- it does its per-family grouping and
usable/latest filtering in SQL, so the growing table doesn't slow that
endpoint down. But the table itself still grows, which is undesirable for
storage and backup size regardless.

This template has no built-in job scheduler (no Celery/arq/cron process),
so rather than invent one, retention is a manual operator command in the
same spirit as `create-admin`:

```bash
uv run python -m kalekit.cli prune-refresh-tokens --older-than-days 30
```

This deletes refresh token rows that are both *dead* (revoked, or expired)
and have been dead for at least the given window -- still-usable tokens are
never touched regardless of age. Wire this into whatever cron/scheduled-job
mechanism your deployment already has (e.g. a daily job); 30 days is a
reasonable default but pick a window based on how far back you want to be
able to investigate a compromised-session incident.

## OAuth: login only, no provider tokens stored

Google, GitHub and X are used for login only. The callback exchanges the
code and reads the profile in memory, then issues Kalekit's own access and
refresh tokens; the provider's tokens are never persisted. `oauth_accounts`
holds `platform`, `account_id` (the provider's stable id, which is how a
returning user is matched), `account_email` and `user_id`. If you later need
to call a provider's API on the user's behalf, add an encrypted token store
then. Sign in with Apple (#19) will need one to revoke the token when an
account is deleted.
