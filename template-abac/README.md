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
│   ├── web/            # primary web app       — Next.js 15  (app.kalekit.dev)
│   ├── site/           # marketing site        — Next.js 15  (kalekit.dev)
│   ├── admin/          # admin / ops panel     — Next.js 15  (admin.kalekit.dev)
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

### OAuth

Google, GitHub and X are used for **login only**. The callback exchanges the
code and reads the profile in memory, then issues Kalekit's own access and
refresh tokens. The provider's tokens are not stored: `oauth_accounts` keeps
`platform`, `account_id` (the provider's stable id, which is how a returning
user is matched), `account_email` and `user_id`. If you later need to call a
provider's API on the user's behalf, add an encrypted token store first. Sign
in with Apple (#19) will need one to revoke tokens on account deletion.

## Deployment

Backend deploys to DigitalOcean via `.github/workflows/deploy-*.yml`
(`feat/**` → preview, `main` → staging, `vX.Y.Z` tag → production).
Frontend CD is not wired — decide per surface (container vs Vercel).
Mobile: `eas init`, then EAS Build / EAS Update.

## License

MIT
