const isDev = process.env.NODE_ENV !== 'production';

// Origin the browser may call (the API). Read at build time.
const apiOrigin = new URL(
  process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000',
).origin;

// Content-Security-Policy, shipped as Report-Only for the first release: it
// logs violations in the browser console and blocks nothing. Once a release
// is clean, switch the header name below to 'Content-Security-Policy'.
//
// script-src keeps 'unsafe-inline' because Next.js emits inline bootstrap
// scripts and a nonce needs per-request rendering (middleware), which would
// turn every page dynamic. Moving to nonces is the follow-up to enforcing.
// React needs 'unsafe-eval' in development only.
// frame-ancestors is ignored in Report-Only, so the admin panel also sends an
// enforced, frame-ancestors-only policy next to X-Frame-Options.
const csp = [
  "default-src 'self'",
  `script-src 'self' 'unsafe-inline'${isDev ? " 'unsafe-eval'" : ''}`,
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "font-src 'self' data:",
  `connect-src 'self' ${apiOrigin}`,
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
].join('; ');

export const securityHeaders = [
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'Referrer-Policy', value: 'no-referrer' },
  { key: 'Content-Security-Policy-Report-Only', value: csp },
  // Enforced. Only this directive; the full policy above stays report-only.
  { key: 'Content-Security-Policy', value: "frame-ancestors 'none'" },
];

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  outputFileTracingRoot: new URL('../../', import.meta.url).pathname,
  async headers() {
    return [{ source: '/:path*', headers: securityHeaders }];
  },
};

export default nextConfig;
