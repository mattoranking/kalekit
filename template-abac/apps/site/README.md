# @kalekit/site

The **marketing site** (kalekit.dev / the ViewNowNL website). Public, content-first,
no auth. Explains the service and the tiers, and links to the Seeker app.

```bash
pnpm --filter @kalekit/site dev    # http://localhost:3001
```

- Framework: Next.js 15 (App Router). Kept on the same toolchain as `web`/`admin`
  for shared config; can move to `output: 'export'` (static) if it stays purely
  content.
- No backend calls on the critical path.
