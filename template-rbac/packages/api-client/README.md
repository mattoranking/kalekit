# @kalekit/api-client

Non-visual shared layer: the typed client for the Kalekit backend.

- Types are **generated** from the backend's OpenAPI spec into `src/schema.d.ts`
  (git-ignored). Regenerate whenever the backend contract changes:

  ```bash
  # backend must be running, or point at a spec file / URL
  pnpm --filter @kalekit/api-client generate
  ```

- `src/index.ts` holds the small hand-written helpers (base URL, health check).
  Add typed request wrappers here as endpoints stabilise.
