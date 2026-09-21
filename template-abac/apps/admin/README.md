# @kalekit/admin

The **Admin** panel — web, desktop-first. Separate client, separate risk
profile, same API.

The admin panel is the product for the first hundred bookings: reassign a Local,
refund a Seeker, chase a late report, correct a wrong address. Every unhandled
edge case in the other clients becomes an admin action here.

```bash
pnpm --filter @kalekit/admin dev   # http://localhost:3002
```

- Framework: Next.js 16 (App Router), desktop-first layouts.
- Auth: staff-only — wire to the backend auth module before exposing anything.
