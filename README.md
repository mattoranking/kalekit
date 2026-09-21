# Kalekit

A scaffolding kit that generates a full-stack monorepo in one command: a FastAPI backend with authentication, three Next.js web apps, an Expo mobile app, shared packages, Docker Compose and CI/CD.

It is built to be run by Claude Code as a skill: you name the project and pick an access-control style, and Claude generates it, starts it and helps if something breaks. You can also run the generator by hand.

## What you get

```
<name>/
├── backend/          FastAPI, SQLAlchemy 2 (async), Alembic, pytest, uv
├── apps/
│   ├── web/          Next.js 15, main app
│   ├── site/         Next.js 15, marketing site
│   ├── admin/        Next.js 15, ops panel
│   └── mobile/       Expo, expo-router, EAS profiles
├── packages/
│   ├── config/       shared tsconfig and Tailwind preset
│   └── api-client/   typed client generated from the backend's OpenAPI
├── .github/workflows/  CI, and DigitalOcean deploy and preview
├── compose.yml       Postgres, Redis, Traefik, backend, web, site, admin
└── Makefile
```

Local development runs behind Traefik with mkcert TLS. The JavaScript side is a pnpm and turbo workspace.

## Choose an access-control style

Each template is a complete backend, not a variation of a shared one. Pick the one that matches your data.

| Style | Tenancy | How access is decided | Pick it for |
|---|---|---|---|
| `rbac` | Single tenant | Roles and permissions; routes declare `require_permission(...)` | Internal tools where all users share the data |
| `abac` | Multi-tenant | Queries are filtered to the caller's organization; a non-member gets a 404, not a 403 | SaaS where the question is "whose data is this" |
| `hybrid` | Multi-tenant | Organization membership plus a fixed role on it: `owner`, `admin`, `member`, `viewer` | B2B SaaS where tenants also need privilege tiers |

## Authentication in the backend

The three templates share the same base and differ in how far the auth work has gone. `rbac` is the most complete.

| Feature | `rbac` | `abac` | `hybrid` |
|---|---|---|---|
| Register, login, refresh, logout, `/me` | yes | yes | yes |
| Password hashing | Argon2 | bcrypt | bcrypt |
| Refresh tokens stored hashed and rotated on use | yes | yes | yes |
| Logout everywhere | yes | no | yes |
| Redis blocklist for revoked access tokens | yes | no | yes |
| Session list and revoke, change password, re-authenticate | yes | no | no |
| Email verification and password reset | yes | no | no |
| Rate limits on auth endpoints | yes | no | no |
| Create-first-admin CLI | yes | no | no |

All three include OAuth sign-in with GitHub, Google and X, and short-lived JWT access tokens.

In `rbac` and `hybrid`, a Redis outage makes token checks fail closed with a 503. In `rbac`, rate limits fail open.

## Prerequisites

| Tool | Version |
|---|---|
| Python | 3.13+ |
| [uv](https://docs.astral.sh/uv/) | current |
| Node.js | 20+ |
| [pnpm](https://pnpm.io/) | 8+ |
| Docker with Compose | current |
| [mkcert](https://github.com/FiloSottile/mkcert) | current |

Using Claude Code, you also need Claude Code itself. Claude checks the rest and tells you what is missing.

## Create a project with Claude Code

This is the recommended way. Claude asks what it needs, runs the generator, brings the stack up, checks it and helps when something goes wrong.

**1. Install Kalekit as a skill.** The repository is the skill, so clone it into your skills folder:

```bash
git clone https://github.com/mattoranking/kalekit.git ~/.claude/skills/kalekit
```

**2. Ask Claude to create the project.** Start Claude Code in the folder where the project should live and say what you want, for example:

> Create a new project called `acme` with hybrid auth.

Or run `/kalekit`. If you leave out the name or the auth style, Claude asks. The name must match `^[a-z][a-z0-9]{1,29}$`: lowercase, starting with a letter, no `-` or `_`. If yours doesn't, Claude proposes a valid one, such as `myapp` for `my-app`. Not sure which style to pick? Use the table above.

**3. Let Claude work through the setup.** It will:

1. Check that the prerequisites are installed and tell you what is missing.
2. Run the generator, which installs dependencies and makes the first commit.
3. Ask you to run `make setup`, because it writes `/etc/hosts` and needs your sudo password. In Claude Code, type `! make setup` to run it in the session.
4. Start the stack with Docker Compose and generate and apply the initial database migration.
5. Check the health endpoint and the web apps, then report the URLs.

**4. If something fails, tell Claude.** A common case is ports 80 or 443 already in use by a system nginx. Claude reads the error, explains it and proposes a fix: stop the service or remap Traefik's ports in `compose.yml`.

## Create a project without Claude

Run the generator yourself. The project name follows the same rule as above, and the script does not start any services.

```bash
git clone https://github.com/mattoranking/kalekit.git
cd kalekit
bash scripts/generate.sh --auth <rbac|abac|hybrid> <name> [target-dir]
```

`target-dir` defaults to `./<name>`. For example, a multi-tenant project named `acme` in `~/code/acme`:

```bash
bash scripts/generate.sh --auth hybrid acme ~/code/acme
```

Then start it from the generated project:

```bash
make setup                      # writes /etc/hosts entries and mkcert certificates (needs sudo)
docker compose up -d --build

# No migrations ship with a template. Generate the schema from the models you copied:
docker compose exec -T backend uv run alembic revision --autogenerate -m "initial schema"
docker compose exec -T backend uv run alembic upgrade head
```

Check that it is up:

```bash
curl -sk https://api.<name>.dev/health        # {"status":"ok"}
```

| Service | URL |
|---|---|
| API and docs | `https://api.<name>.dev/docs` |
| Web app | `https://app.<name>.dev` |
| Marketing site | `https://<name>.dev` |
| Admin | `https://admin.<name>.dev` |
| Traefik dashboard | `http://localhost:8080` |

If ports 80 or 443 are taken, for example by a system nginx, stop it or remap Traefik's ports in `compose.yml`.

## Common commands

Run `make help` in a generated project for the full list.

| Command | What it does |
|---|---|
| `make up` / `make down` | Start or stop all services |
| `make backend-dev` | Run the backend with reload, outside Docker |
| `make backend-test` | Run the backend tests against a test database |
| `make backend-test-ci` | Lint, type-check and test with coverage, as CI does |
| `make backend-fmt` | Format backend code with ruff |
| `make db-migrate m="..."` | Generate a migration |
| `make db-upgrade` | Apply pending migrations |
| `make fe-lint` / `make fe-typecheck` / `make fe-build` | Check and build the JavaScript workspace |
| `make api-client-gen` | Regenerate the typed API client from the running backend |

## After generating

- **First admin (`rbac`):** no sign-up path grants the `admin` role, so everyone starts as `visitor`. Create the first admin from `backend/`:
  ```bash
  uv run python -m <name>.cli create-admin --email you@example.com --password '...'
  ```
- **Project brief:** edit the generated `CLAUDE.md`. Its domain sections are stubs for you to fill in.
- **Domains:** the apps use `<name>.dev` locally and `<name>.one` in the OpenAPI server list and the preview workflow. Point them at your real hosts before deploying.
- **Deployment:** only the backend deploys through the GitHub workflows. They expect DigitalOcean droplets and a set of Actions secrets, listed in the workflow files.
- **Mobile:** run `eas init` and replace `PROJECT_ID_HERE` in `apps/mobile/app.json`.

## Repository layout

| Path | Contents |
|---|---|
| `template-rbac/`, `template-abac/`, `template-hybrid/` | The three complete project templates |
| `scripts/generate.sh` | The generator |
| `SKILL.md` | The Claude Code skill definition |
| `PRODUCT_UPDATE.md` | Log of the auth hardening work across the templates |

Each template has its own `README.md` and `CLAUDE.md` with its architecture and rules.
