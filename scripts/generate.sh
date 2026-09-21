#!/usr/bin/env bash
# Generate a fresh full-stack monorepo from the bundled template.
#
#   generate.sh [--auth rbac|abac|hybrid] <slug> [target-dir]
#
#   --auth        which access-control style to scaffold the backend
#                 with (default: rbac):
#                   rbac    single-tenant, Role/Permission tables
#                   abac    multi-tenant, org-membership ownership filtering
#                   hybrid  multi-tenant, org membership + a per-membership role
#   <slug>        lowercase, starts with a letter, [a-z0-9] only, 2-30 chars.
#                 Becomes: repo dir name, Python package, pnpm scope (@<slug>/*),
#                 DB/container names, and the <SLUG>_ env-var prefix.
#   [target-dir]  where to create the project (default: ./<slug>).
#
# Does NOT run `make setup` / `docker compose up` — the caller does that
# (they need sudo / a running Docker daemon).

set -euo pipefail

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

AUTH_STYLE="rbac"
POSITIONAL=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --auth)
      AUTH_STYLE="${2:-}"
      shift 2
      ;;
    --auth=*)
      AUTH_STYLE="${1#--auth=}"
      shift
      ;;
    *)
      POSITIONAL+=("$1")
      shift
      ;;
  esac
done
set -- "${POSITIONAL[@]:-}"

if [[ "$AUTH_STYLE" != "rbac" && "$AUTH_STYLE" != "abac" && "$AUTH_STYLE" != "hybrid" ]]; then
  echo "error: --auth must be one of: rbac, abac, hybrid (got '$AUTH_STYLE')" >&2
  exit 2
fi

TEMPLATE="$SKILL_DIR/template-$AUTH_STYLE"

SLUG="${1:-}"
DEST="${2:-./$SLUG}"

if [[ -z "$SLUG" ]]; then
  echo "usage: generate.sh [--auth rbac|abac|hybrid] <slug> [target-dir]" >&2; exit 2
fi
if [[ ! "$SLUG" =~ ^[a-z][a-z0-9]{1,29}$ ]]; then
  echo "error: slug must match ^[a-z][a-z0-9]{1,29}$ (lowercase, letter first, no - or _)" >&2
  exit 2
fi
if [[ -e "$DEST" && -n "$(ls -A "$DEST" 2>/dev/null)" ]]; then
  echo "error: $DEST already exists and is not empty" >&2; exit 2
fi
if [[ ! -d "$TEMPLATE" ]]; then
  echo "error: template not found at $TEMPLATE" >&2; exit 2
fi

SLUG_UPPER="$(printf '%s' "$SLUG" | tr '[:lower:]' '[:upper:]')"
SLUG_TITLE="$(printf '%s' "${SLUG:0:1}" | tr '[:lower:]' '[:upper:]')${SLUG:1}"

echo "==> Creating $DEST (auth style: $AUTH_STYLE)"
mkdir -p "$DEST"
cp -a "$TEMPLATE/." "$DEST/"
cd "$DEST"

echo "==> Renaming template tokens -> $SLUG / $SLUG_UPPER / $SLUG_TITLE"
# rename the Python package dir and the vscode workspace file
mv backend/kalekit "backend/$SLUG"
mv kalekit.code-workspace "$SLUG.code-workspace"

# case-aware text substitution across every file (template is all text)
#  - 'kalekit-backend' before 'kalekit' so the pyproject name renames cleanly
find . -type f -print0 | LC_ALL=C xargs -0 sed -i \
  -e "s/kalekit-backend/${SLUG}-backend/g" \
  -e "s/kalekit/${SLUG}/g" \
  -e "s/KALEKIT/${SLUG_UPPER}/g" \
  -e "s/Kalekit/${SLUG_TITLE}/g"

echo "==> Writing local .env files (working dev defaults)"
cat > .env <<EOF
# Local dev — docker compose reads this automatically.
${SLUG_UPPER}_POSTGRES_USER=${SLUG}
${SLUG_UPPER}_POSTGRES_PASSWORD=${SLUG}
${SLUG_UPPER}_POSTGRES_DB=${SLUG}_dev_db

${SLUG_UPPER}_ENV=development
${SLUG_UPPER}_JWT_SECRET_KEY=dev-only-not-secret
${SLUG_UPPER}_CORS_ORIGINS=https://app.${SLUG}.dev,https://admin.${SLUG}.dev,http://localhost:3000,http://localhost:3002

GEMINI_API_KEY=changeme
EOF

cat > backend/.env <<EOF
${SLUG_UPPER}_ENV=development
${SLUG_UPPER}_POSTGRES_USER=${SLUG}
${SLUG_UPPER}_POSTGRES_PWD=${SLUG}
${SLUG_UPPER}_POSTGRES_HOST=127.0.0.1
${SLUG_UPPER}_POSTGRES_PORT=5433
${SLUG_UPPER}_POSTGRES_DATABASE=${SLUG}_dev_db
${SLUG_UPPER}_JWT_SECRET_KEY=dev-only-not-secret
${SLUG_UPPER}_CORS_ORIGINS=http://localhost:3000,http://localhost:3002
${SLUG_UPPER}_REDIS_URL=redis://localhost:6379/0

GEMINI_API_KEY=changeme
EOF

echo "==> pnpm install"
pnpm install

echo "==> uv sync (backend)"
( cd backend && uv sync )

echo "==> git init + first commit"
git init -q
git add -A
git -c user.email=scaffold@local -c user.name=scaffold \
    commit -qm "chore: initial scaffold from the Kalekit skill (auth: $AUTH_STYLE)"

cat <<EOF

==> Done.  $DEST  (auth style: $AUTH_STYLE)

Next (the skill runs these):
  cd $DEST
  make setup                       # /etc/hosts + mkcert certs (needs sudo)
  docker compose up -d --build     # db, redis, traefik, backend, web, site, admin
  docker compose exec -T backend uv run alembic revision --autogenerate -m "initial schema"
  docker compose exec -T backend uv run alembic upgrade head

Then:
  https://api.${SLUG}.dev/docs   https://app.${SLUG}.dev   https://${SLUG}.dev   https://admin.${SLUG}.dev
EOF
