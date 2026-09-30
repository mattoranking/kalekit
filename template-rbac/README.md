# kalekit

Full-stack monorepo: one FastAPI backend, three web clients (Next.js), one
mobile client (Expo), shared non-visual packages.

See [`CLAUDE.md`](CLAUDE.md) for architecture and the load-bearing rules.

---

## Layout

```
kalekit/
├── apps/
│   ├── backend/        # FastAPI service (uv)
│   ├── web/            # primary web app       — Next.js 16  (app.kalekit.dev)
│   ├── site/           # marketing site        — Next.js 16  (kalekit.dev)
│   ├── admin/          # admin / ops panel     — Next.js 16  (admin.kalekit.dev)
│   └── mobile/         # mobile app            — Expo / React Native
├── packages/
│   ├── config/         # shared tsconfig + Tailwind preset (design tokens)
│   └── api-client/     # typed backend client, generated from OpenAPI
├── .github/workflows/  # CI/CD
├── compose.yml         # local dev: db, redis, traefik, backend, web, site, admin
└── Makefile            # task runner (`make help`)
```

- **Backend** is Python (`uv`). **Clients** are TypeScript (`pnpm` + `turbo`).
- `mobile` builds and OTA updates run through **EAS**, not this repo's Actions.

## Prerequisites

- Python 3.13+, [uv](https://docs.astral.sh/uv/)
- Node.js 20+, [pnpm](https://pnpm.io/) 8
- Docker & Docker Compose
- [mkcert](https://github.com/FiloSottile/mkcert) (local TLS)

## Getting started

```bash
cd backend && uv sync && cd ../..   # backend deps
pnpm install                             # JS workspace deps

cp .env.example .env                                 # root — docker compose reads this
cp backend/.env.template backend/.env      # backend, non-Docker local dev

make setup     # /etc/hosts entries + local mkcert certs for every *.kalekit.dev host
```

### Run

```bash
make up            # everything via docker compose (db, redis, traefik + all apps)

# or individually:
make backend-dev   # :8000
make web-dev       # :3000   app.kalekit.dev
make site-dev      # :3001   kalekit.dev
make admin-dev     # :3002   admin.kalekit.dev
make mobile-dev    # Expo dev client (Metro)
```

| Surface | Local URL |
|---|---|
| Backend API / docs | https://api.kalekit.dev · `/docs` |
| Web app | https://app.kalekit.dev |
| Marketing site | https://kalekit.dev |
| Admin | https://admin.kalekit.dev |
| Traefik dashboard | http://localhost:8080 |

### Common tasks

```bash
make help
make db-migrate m="add widgets table"
make backend-test
make fe-lint
make fe-typecheck
make api-client-gen   # regenerate @kalekit/api-client from the running backend
```

## Security headers

The API (`backend/kalekit/security.py`), Traefik (HSTS, HTTPS routers only) and
each Next.js app (`next.config.mjs`) each own a distinct set of headers; the
table in `CLAUDE.md` ("Security headers") lists exactly where each is set. Set
`KALEKIT_ALLOWED_HOSTS` to the API's public hostname when you deploy.

## Deployment

Backend deploys to DigitalOcean via `.github/workflows/deploy-*.yml`
(`feat/**` → preview, `main` → staging, `vX.Y.Z` tag → production).
Frontend CD is not wired — decide per surface (container vs Vercel).
Mobile: `eas init`, then EAS Build / EAS Update.

### GitHub Environment secrets and variables

Each workflow deploys through a GitHub Environment (`test`, `staging`,
`production`; Settings > Environments). Set these before the next deploy.
Set every value per Environment; do not reuse one across environments.

| Name | Kind | `test` (preview) | `staging` | `production` |
|---|---|---|---|---|
| `JWT_SECRET_KEY` | secret, **required** | yes | yes | yes |
| `JWT_ISSUER` | variable, optional | default `kalekit-preview` | default `kalekit-staging` | default `kalekit-production` |
| `CR_PAT` | secret | yes | yes | yes |
| `GEMINI_API_KEY` | secret | yes | yes | yes |
| `ACME_EMAIL` | secret | yes | yes | not used |
| `STAGING_HOST`, `STAGING_USER`, `STAGING_SSH_KEY` | secret | yes | yes | not used |
| `PRODUCTION_HOST`, `PRODUCTION_USER`, `PRODUCTION_SSH_KEY` | secret | not used | not used | yes |
| `GH_ACTOR` | secret | yes | not used | not used |
| `TEST_DB_PASSWORD` | secret | yes | not used | not used |
| `KALEKIT_POSTGRES_USER`, `KALEKIT_POSTGRES_PWD`, `KALEKIT_POSTGRES_STAGING_DATABASE` | secret | not used | yes | not used |
| `STAGING_API_DOMAIN`, `CORS_ORIGINS` | secret | not used | yes | not used |
| `DB_USER`, `DB_PASSWORD`, `API_DOMAIN`, `CORS_ORIGINS` | secret | not used | not used | yes |

The preview cleanup job in `deploy-test.yml` runs without an Environment, so
`STAGING_HOST`, `STAGING_USER` and `STAGING_SSH_KEY` must also exist as
repository secrets.

`JWT_SECRET_KEY` signs access tokens. The backend refuses to start in
preview, staging and production if it is a placeholder or shorter than 32
bytes. Each deploy stops before writing any configuration if it is missing
or shorter than 32 characters. In production a separate `Check JWT secret`
step runs first on the runner, and the `Rollback on failure` step is skipped
when it fails, so the running backend is left as it is. Generate one per
environment:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
```

`JWT_ISSUER` is stamped on every token and checked on decode. Leave it unset to
use the per-environment default above, or set a variable of that name on the
Environment to override it.

The preview environments share one `JWT_SECRET_KEY` and one default issuer
(`kalekit-preview`), so a token from one preview passes the signature and
issuer checks on another. This is accepted for now: user ids are random UUIDs,
so a token only matches a user in the preview whose database holds that id.

The deploys also give the backend a Redis container on the internal Docker
network (no published port) at `redis://redis:6379/0`, and set
`KALEKIT_TRUST_PROXY_HEADERS=true` because the API only receives traffic
through Traefik. Neither needs a secret. The workflows do not print container
logs; read them on the host over SSH.

The backend publishes no host port, so the post-deploy health checks run
`python -c "urllib.request.urlopen('http://localhost:8000/health')"` inside
the backend container with `docker exec` (production: `kalekit_backend_prod`;
staging: `staging-backend-<first 6 chars of the commit sha>`, the container the
blue-green step starts with `docker compose run`). Previews rely on
`docker compose up --wait`, which waits for the container healthcheck.

Production rollback. The deploy writes `.version.switched` in
`/home/deploy/opt/kalekit/production` just before it replaces the backend
container, and the health check writes `.version.healthy` only after it
passes. If the job fails, `Rollback on failure` does nothing unless this run
wrote the switch marker, because otherwise the running backend was never
replaced. If it did switch, the step puts the last healthy version back in
`.env`, pulls that image and recreates the backend. It logs which case
applied. When no healthy version is recorded (for example the first deploy on a
host, or a host deployed before this change) or the last healthy version is the
one that just failed, it logs that it did not roll back and leaves the backend
as it is. Production deploys run one at a time (a `concurrency` group), and the
health check records a version only if `kalekit_backend_prod` runs that
version's image. The `.version` and `.version.previous` files are no longer used.

CI and the staging `test-backend` job start a Redis service and set
`KALEKIT_REDIS_URL` to `redis://localhost:6379/15`; the suite refuses Redis
db 0.

## License

MIT
