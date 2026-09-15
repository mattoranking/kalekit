# Multi-stage build for a Next.js app in the pnpm monorepo.
# Build context is the REPO ROOT (see CI). Pass the app dir name via --build-arg APP=web.
FROM node:20-alpine AS base
RUN apk add --no-cache libc6-compat && corepack enable && corepack prepare pnpm@8.15.0 --activate
ARG APP
ENV APP=${APP}

FROM base AS deps
WORKDIR /repo
# pnpm-lock.yaml covers the whole workspace, so --frozen-lockfile needs every
# member's package.json present, not just the app being built.
COPY pnpm-workspace.yaml package.json pnpm-lock.yaml* ./
COPY packages ./packages
COPY apps/web/package.json ./apps/web/package.json
COPY apps/site/package.json ./apps/site/package.json
COPY apps/admin/package.json ./apps/admin/package.json
COPY apps/mobile/package.json ./apps/mobile/package.json
RUN pnpm install --frozen-lockfile

FROM base AS builder
WORKDIR /repo
COPY --from=deps /repo/node_modules ./node_modules
COPY --from=deps /repo/packages ./packages
COPY pnpm-workspace.yaml package.json turbo.json ./
COPY apps/${APP} ./apps/${APP}
# pnpm gives each workspace package its own node_modules (with the actual
# binaries, e.g. next) -- the root node_modules alone doesn't have it.
COPY --from=deps /repo/apps/${APP}/node_modules ./apps/${APP}/node_modules
ENV NEXT_TELEMETRY_DISABLED=1
RUN pnpm --filter "./apps/${APP}" build

FROM base AS runner
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 HOSTNAME=0.0.0.0 PORT=3000
RUN addgroup --system --gid 1001 nodejs && adduser --system --uid 1001 nextjs
# Next.js standalone output preserves the apps/<name>/ path (outputFileTracingRoot = repo root).
COPY --from=builder --chown=nextjs:nodejs /repo/apps/${APP}/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /repo/apps/${APP}/.next/static ./apps/${APP}/.next/static
COPY --from=builder --chown=nextjs:nodejs /repo/apps/${APP}/public ./apps/${APP}/public
USER nextjs
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/', (r) => process.exit(r.statusCode === 200 ? 0 : 1))"
CMD ["sh", "-c", "node apps/$APP/server.js"]
