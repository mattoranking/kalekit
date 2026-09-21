import assert from 'node:assert/strict';
import test from 'node:test';

import nextConfig from './next.config.mjs';

async function headerMap() {
  const rules = await nextConfig.headers();
  assert.equal(rules.length, 1);
  assert.equal(rules[0].source, '/:path*');
  return new Map(rules[0].headers.map((h) => [h.key, h.value]));
}

test('serves the basic security headers', async () => {
  const headers = await headerMap();
  assert.equal(headers.get('X-Content-Type-Options'), 'nosniff');
  assert.equal(headers.get('X-Frame-Options'), 'DENY');
  assert.equal(headers.get('Referrer-Policy'), 'no-referrer');
});

test('never sends HSTS (Traefik owns it)', async () => {
  const headers = await headerMap();
  assert.equal(headers.has('Strict-Transport-Security'), false);
});

test('the full CSP is report-only', async () => {
  const headers = await headerMap();
  const policy = headers.get('Content-Security-Policy-Report-Only');
  assert.ok(policy?.includes("default-src 'self'"));
  assert.ok(policy?.includes("object-src 'none'"));
  assert.equal(headers.has('Content-Security-Policy'), false);
});
