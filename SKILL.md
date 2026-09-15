---
name: fullstack-monorepo
description: Generate a new, ready-to-run full-stack monorepo (FastAPI backend + Next.js web/site/admin + Expo mobile + shared packages + Docker Compose + GitHub Actions CI/CD). Use when the user wants to start a new project / scaffold a codebase / "spin up" a new app from this stack. Takes a project name and produces a working repo where `make setup` then `docker compose up` just runs.
---

# fullstack-monorepo

Scaffolds a complete monorepo from one of three bundled `template-<style>/` trees
and leaves it running.

## Stack it produces

```
<name>/
├── backend/       FastAPI + uv — auth (see below), OAuth2 (GitHub/Google/X),
│                  SQLAlchemy 2 async, Alembic, pytest
├── apps/
│   ├── web/       Next.js 15 (App Router) + Tailwind
│   ├── site/      Next.js 15  (marketing)
│   ├── admin/     Next.js 15  (ops panel)
│   └── mobile/    Expo SDK 53 + expo-router + EAS profiles
├── packages/
│   ├── config/       shared tsconfig + Tailwind preset
│   └── api-client/   OpenAPI-typed backend client
├── .github/workflows/  CI (backend + web/site/admin) + DigitalOcean deploy/preview/release
├── compose.yml   db, redis, traefik, backend, web, site, admin
└── Makefile
```

`backend/` sits alongside `apps/`, not inside it — it's a separate service, not a
frontend surface, and this leaves room for future non-Python backend services
(e.g. a Go or Elixir service) to live as further siblings without implying they
belong under `apps/` either.

pnpm + turbo workspace, `pnpm.overrides` pinning React, mkcert + Traefik local TLS.

## Auth style — pick one

There are three complete, independent backend templates. They are not variations
on the same files — the resource modules (`user`/`organization`/`chat`) differ
by style too, since each style demonstrates its access-control pattern on real
endpoints, not just in the auth module:

- **`rbac`** — single-tenant. `Role`/`Permission` tables, a `require_permission(...)`
  dependency, a `/users` admin listing. Pick this for internal tools where every
  user shares the same data and the only difference is rank.
- **`abac`** — multi-tenant. Every user belongs to an `Organization` via a flat
  `OrganizationMember` row (no role). Access is enforced by filtering queries to
  the caller's org membership (`chat/repository.py::get_readable_statement`), not
  by a permission lookup — a non-member gets a 404, never a 403. Pick this for
  multi-tenant SaaS where the main question is "whose data is this."
- **`hybrid`** — multi-tenant + a role on the membership itself (`owner` / `admin`
  / `member` / `viewer`, fixed in code, not a DB-configurable catalog — see
  `auth/roles.py`). The same person can be `owner` in one org and `member` in
  another. Pick this when tenants also need internal privilege tiers (most real
  B2B SaaS — Slack/GitHub/Linear-shaped).

**Ask which style if the user's request doesn't say.** Don't default silently —
the generator's own `rbac` default only exists for scripting/back-compat.

## Steps

1. **Get the project name and auth style.** Ask for whichever wasn't given. The
   name must match `^[a-z][a-z0-9]{1,29}$` — lowercase, letter first, no `-` or
   `_` (it becomes a Python package name and a pnpm scope). If the user gives
   something invalid (e.g. `my-app`), propose a valid form (`myapp`) and confirm.
   Also ask where to create it (default: current directory).

2. **Check prerequisites** are on PATH: `pnpm` (8+), `uv`, `node` (20+), `docker`,
   and `mkcert`. Note any that are missing before proceeding.

3. **Run the generator:**
   ```
   bash ~/.claude/skills/fullstack-monorepo/scripts/generate.sh --auth <rbac|abac|hybrid> <name> <target-dir>
   ```
   It copies the matching `template-<style>/` tree, renames every token
   (`kalekit`→`<name>`, `KALEKIT`→`<NAME>`, `Kalekit`→`<Name>` — including the Python
   package dir, pnpm scope, DB/container names, and the `<NAME>_` env prefix),
   writes working `.env` files, runs `pnpm install` and `uv sync`, and makes the
   first git commit.

4. **Local TLS + hosts:** run `make setup` from the project dir. It needs sudo
   (writes `/etc/hosts`) and runs `mkcert`. If the shell is non-interactive, tell
   the user to run `! make setup` themselves.

5. **Bring it up:**
   ```
   docker compose up -d --build
   docker compose exec -T backend uv run alembic revision --autogenerate -m "initial schema"
   docker compose exec -T backend uv run alembic upgrade head
   ```
   No migration files ship in any template — the schema is generated fresh from
   whichever style's models were copied in, so it can never drift from them.
   If port 80/443 is taken (common: system nginx), say so — `sudo systemctl stop nginx`
   or remap Traefik's ports in `compose.yml`.

6. **Verify and report:**
   ```
   docker compose ps
   curl -sk https://api.<name>.dev/health        # -> {"status":"ok"}
   curl -sko /dev/null -w '%{http_code}\n' https://app.<name>.dev
   ```
   Report the URLs: API/docs `https://api.<name>.dev/docs`, web `https://app.<name>.dev`,
   site `https://<name>.dev`, admin `https://admin.<name>.dev`, Traefik `http://localhost:8080`.

## After generation — tell the user

- Edit `CLAUDE.md` — the domain sections are stubs (`What this is`, `Domain
  language`, the state machine). The architecture and load-bearing rules are filled in.
- `apps/*` domains are placeholders (`<name>.dev` local, `<name>.one` in the OpenAPI
  server list and preview workflow). Point them at real hosts before deploying.
- Frontend CD is not wired — only backend deploys. `mobile` needs `eas init` +
  filling `PROJECT_ID_HERE` in `apps/mobile/app.json`.
- The GitHub deploy workflows expect DigitalOcean droplets + a set of Actions
  secrets (see the deploy workflow files).

## Notes

- `make dev` targets, `make help` lists everything.
- Re-running the skill for the same name is refused if the target dir is non-empty.
- The generator does not touch the internet beyond `pnpm install` / `uv sync`.
- Removing an unwanted app (e.g. "spin up a web+backend only, no mobile/site/admin")
  is a separate, composable step — not part of this skill yet.
