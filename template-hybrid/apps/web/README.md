# @kalekit/web

The **Seeker** app — responsive web, no install. Where a Seeker books and pays
for a viewing and reads the report.

Responsive web is a decided constraint: Seekers book 1–3 times ever, often from
a laptop with a funda tab open. Revisit only on evidence of repeat booking.

```bash
pnpm --filter @kalekit/web dev     # http://localhost:3000
```

- Framework: Next.js 15 (App Router), React 19, Tailwind 3
- Backend types: `@kalekit/api-client` (generated from OpenAPI)
- Env: `NEXT_PUBLIC_API_URL` (default `http://localhost:8000`)
