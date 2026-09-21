# CLAUDE.md — kalekit

## What this is

<!-- Describe the product in two or three sentences. What does it do, for whom,
     and what is the single central domain object? Replace this stub. -->

## Domain language

<!-- List the 5–10 nouns/verbs that must appear verbatim in code. Pick one term
     per concept and forbid synonyms. Example:

- **Account** — a customer who signs in.
- **Order** — one purchase. The central domain object.
- **Job** — a unit of async work tied to an Order.
-->

## Architecture

**Style:** modular monolith, API-first, multi-client. One backend deployable
with internal module boundaries. Not microservices — third-party integrations
(payments, identity, video, push, email/SMS, error tracking) make it look
distributed, but there is exactly one service we operate.

```
backend/   FastAPI service — the one thing we operate
apps/web/       primary web client   (Next.js)   app.kalekit.dev
apps/site/      marketing site       (Next.js)   kalekit.dev
apps/admin/     admin / ops panel    (Next.js)   admin.kalekit.dev
apps/mobile/    mobile client        (Expo / React Native)
packages/config/      shared tsconfig + Tailwind preset (design tokens)
packages/api-client/  typed backend client, generated from OpenAPI
```

Backend is Python (`uv`); clients are TypeScript (`pnpm` + `turbo`). `mobile`
builds/OTA go through EAS, not this repo's Actions.

## Repo conventions

Shared packages cover the **non-visual** layer only: API client (generated from
OpenAPI), TypeScript types and validation, auth handling, design tokens,
formatting utilities.

**Do not build a shared component library beyond primitives.** The clients share
almost no UI. Resist `variant="admin"` props.

Codegen `@kalekit/api-client` from OpenAPI as a build step or types will drift.

## The core state machine

Model the central domain object's lifecycle as **one explicit state machine with
logged transitions** — not a scatter of boolean flags. Two flags disagreeing
about state is the classic bug. Every client and the admin panel depend on it.
Get it right first.

```
<!-- created → paid → ... → done  — fill in your real states -->
```

## Rules that are load-bearing

**Large media never touches the backend.** Uploads go phone/browser → blob
storage via presigned URL; the backend issues the URL and receives a completion
callback. Video/audio streams flow client ↔ provider directly. If bytes flow
through the API, things get stuck and you recover them by hand.

**Anything with a timer goes on the queue.** Reminders, escalations, payout
release, PDF generation, webhook retries. Never in a request handler.

**Jobs run more than once.** Every job must be safe to retry — check state
before acting. Duplicate notification = annoying. Duplicate charge = money gone.

**Jobs take IDs, not objects.** Re-read from the database inside the job. A
serialised row from 20 minutes ago is stale.

**Webhooks are where the truth lives.** Payment success, KYC approval, etc.
arrive asynchronously, not in the response to your call. Verify signatures,
handle idempotently.

**Contended writes need a lock.** Two clients racing for the same resource —
exactly one wins. Postgres row lock or Redis lock, but not nothing.

**Buy, don't build:** payments, identity verification, video, email/SMS.

**No tenant query without `organization_id`.** The ABAC gate is
`WHERE organization_id = ...` on every query against a tenant-scoped
table — there is no separate permission table. Build that filter through
`tenant_select()` / `tenant_filter()` (`backend/kalekit/utils/db/tenancy.py`)
instead of writing `Model.organization_id == ...` by hand: both take
`organization_id` as a required keyword-only argument, so the filter can't
be dropped by omitting an argument the way a positional one could be, and
calling either on a model with no `organization_id` column fails loudly
instead of silently matching every tenant. Every org-scoped endpoint needs
a cross-tenant denial test alongside it — member of org A calling org B's
URL gets 404 and no rows — see `two_tenants` in `backend/tests/conftest.py`.

## Privacy / GDPR

Treat it as a design constraint, not a checkbox. EU region for database and blob
storage. Never store third-party ID documents yourself — status and a provider
reference only. Short retention on sensitive media. Deletion is scoped per
profile; the financial ledger is retained for tax.

## Auth model

Separate account types per audience where their data differs. Verification
status, payout details, and audience-specific settings belong to their audience.
Ratings/metrics are scoped per side and never averaged together.

## Security headers

Each header is set in exactly one place, so layers cannot conflict.

| Header | Set by |
|---|---|
| `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` | API: `backend/kalekit/security.py` |
| `Cache-Control: no-store` on `/v1/auth/*` and `/v1/oauth/*` | API: `backend/kalekit/security.py` |
| Host allow-list (`KALEKIT_ALLOWED_HOSTS`, 400 otherwise) | API: `TrustedHostMiddleware` |
| `Strict-Transport-Security` | Traefik, HTTPS routers only (`traefik/dynamic.yml`, `hsts@file`; the deploy workflows' Traefik labels). Never the app: local development runs over HTTP |
| the same three basic headers, plus `Content-Security-Policy-Report-Only` | each Next.js app's `next.config.mjs` `headers()` |
| enforced `Content-Security-Policy: frame-ancestors 'none'` | `apps/admin` only |

Set `KALEKIT_ALLOWED_HOSTS` to the API's public hostname wherever it is
deployed (also add a LAN IP if a phone reaches the dev API directly).

**CSRF: not applicable, do not re-check.** Authentication is a bearer token in
the `Authorization` header. The API sets no cookies and reads none, so a
cross-site request cannot carry credentials. If a client ever moves tokens into
cookies, this stance ends and CSRF protection becomes required.

## The admin panel is the product

For the first hundred records, a human does the matching and fixes the edge
cases. Every unhandled case in the other clients becomes an admin action. Build
it early — it buys the right to ship everything else thin.

## Known fragilities

**Expo OTA ships JavaScript, not native code.** Set runtime versions correctly
from the first binary. Push a bundle to a mismatched native runtime and you
crash the app.

**Expo needs development builds from day one** — anything with native modules
(WebRTC, background upload) rules out Expo Go. EAS Build in week one.

**Metro + monorepo** module resolution has sharp edges. `apps/mobile/metro.config.js`
is already set up for the workspace; budget a day if you touch it.
