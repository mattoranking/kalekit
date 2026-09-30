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
or shorter than 32 characters; in production the `Rollback on failure` step
still runs after that and recreates the backend from the previous
configuration. Generate one per environment:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
```

`JWT_ISSUER` is stamped on every token and checked on decode. Leave it unset to
use the per-environment default above, or set a variable of that name on the
Environment to override it.

The deploys also give the backend a Redis container on the internal Docker
network (no published port) at `redis://redis:6379/0`, and set
`KALEKIT_TRUST_PROXY_HEADERS=true` because the API only receives traffic
through Traefik. Neither needs a secret. `KALEKIT_TRUSTED_PROXY_HOPS` (default
1) is how many proxies append to `X-Forwarded-For`; the API takes the entry that
many places from the right, so the default fits one Traefik in front and a
client-supplied header can't choose the rate-limit key. The workflows do not
print container logs; read them on the host over SSH.

## License

MIT
