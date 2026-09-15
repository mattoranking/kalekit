/**
 * Thin, hand-written surface over the Kalekit backend.
 *
 * Request/response *types* are generated from the backend OpenAPI spec into
 * `src/schema.d.ts` (git-ignored) via `pnpm --filter @kalekit/api-client generate`.
 * Import them as:  import type { paths } from '@kalekit/api-client/src/schema';
 *
 * Codegen the client from OpenAPI as a build step or the types will drift.
 */

export const API_BASE_URL =
  (typeof process !== 'undefined' && process.env.NEXT_PUBLIC_API_URL) ||
  'http://localhost:8000';

export async function checkHealth(): Promise<{ status: string }> {
  const res = await fetch(`${API_BASE_URL}/health`);
  if (!res.ok) throw new Error('Backend unhealthy');
  return res.json() as Promise<{ status: string }>;
}
