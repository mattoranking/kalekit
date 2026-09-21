BACKEND_DIR := backend
DEV_HOSTS := kalekit.dev app.kalekit.dev admin.kalekit.dev api.kalekit.dev

.PHONY: help setup dev down \
	backend-fmt backend-lint backend-typecheck \
	backend-test backend-test-cov backend-test-ci \
	backend-dev backend-clean \
	db-migrate db-upgrade db-downgrade db-history db-current db-stamp \
	fe-install fe-lint fe-typecheck fe-build web-dev site-dev admin-dev mobile-dev \
	api-client-gen

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# --- Infrastructure ---

setup: ## Set up local dev environment (hosts, certs) for all web surfaces
	@mkdir -p traefik/certs
	@for h in $(DEV_HOSTS); do \
		grep -q " $$h" /etc/hosts || echo "127.0.0.1 $$h" | sudo tee -a /etc/hosts >/dev/null ; \
		echo "🔧 mkcert $$h" ; \
		mkcert -cert-file traefik/certs/$$h.pem -key-file traefik/certs/$$h-key.pem $$h ; \
	done
	@echo "✅ Setup complete"

up: ## Start all services via docker compose
	docker compose up --build

down: ## Stop all services
	docker compose down

# --- Backend: Code Quality ---

backend-fmt: ## Format backend code with ruff
	cd $(BACKEND_DIR) && uv run ruff format .
	cd $(BACKEND_DIR) && uv run ruff check --fix .

backend-lint: ## Lint backend code (no auto-fix)
	cd $(BACKEND_DIR) && uv run ruff format --check .
	cd $(BACKEND_DIR) && uv run ruff check .

backend-typecheck: ## Run mypy on backend
	cd $(BACKEND_DIR) && uv run mypy kalekit/

# --- Backend: Tests ---

backend-db-up: ## Start test database
	docker compose up -d db-test
	@echo "Waiting for test database..."
	@until docker compose exec db-test pg_isready -U kalekit > /dev/null 2>&1; do sleep 0.5; done
	@echo "Test database ready"

backend-db-down: ## Stop test database
	docker compose down db-test

# Export KEY=VALUE lines from .env.testing, skipping blank and comment lines.
# A variable that is already set (shell or make command line) wins over the file.
LOAD_TEST_ENV = while IFS= read -r line || [ -n "$$line" ]; do \
		case "$$line" in \
			''|'\#'*) ;; \
			*=*) k=$${line%%=*}; v=$${line\#*=}; printenv "$$k" > /dev/null || export "$$k=$$v" ;; \
		esac; \
	done < .env.testing

backend-test: backend-db-up ## Run backend tests
	cd $(BACKEND_DIR) && $(LOAD_TEST_ENV) && uv run pytest -v

backend-test-cov: backend-db-up ## Run backend tests with coverage
	cd $(BACKEND_DIR) && $(LOAD_TEST_ENV) && uv run pytest -v --cov=kalekit --cov-report=term-missing --cov-report=html

backend-test-ci: backend-lint backend-typecheck backend-test-cov ## Run full backend CI locally

# --- Backend: Development ---

backend-dev: ## Start backend dev server (uvicorn with reload)
	cd $(BACKEND_DIR) && uv run uvicorn kalekit.main:app --reload --host 0.0.0.0 --port 8000

# --- Backend: Migrations ---

db-migrate: ## Generate a new migration (usage: make db-migrate m="add users table")
	cd $(BACKEND_DIR) && uv run alembic revision --autogenerate -m "$(m)"

db-upgrade: ## Apply all pending migrations
	cd $(BACKEND_DIR) && uv run alembic upgrade head

db-downgrade: ## Revert the last migration
	cd $(BACKEND_DIR) && uv run alembic downgrade -1

db-history: ## Show migration history
	cd $(BACKEND_DIR) && uv run alembic history --verbose

db-current: ## Show current migration revision
	cd $(BACKEND_DIR) && uv run alembic current

db-stamp: ## Stamp DB to head without running migrations
	cd $(BACKEND_DIR) && uv run alembic stamp head

backend-clean: ## Remove backend build artifacts
	cd $(BACKEND_DIR) && rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage coverage.xml
	cd $(BACKEND_DIR) && find . -type d -name __pycache__ -exec rm -rf {} +

# --- Frontend (pnpm workspace: web, site, admin, mobile) ---

fe-install: ## Install JS workspace dependencies
	pnpm install

fe-lint: ## Lint all JS apps/packages (turbo)
	pnpm turbo run lint

fe-typecheck: ## Typecheck all JS apps/packages (turbo)
	pnpm turbo run typecheck

fe-build: ## Build web, site and admin
	pnpm turbo run build --filter=@kalekit/web --filter=@kalekit/site --filter=@kalekit/admin

web-dev: ## Start the Seeker web app (:3000)
	pnpm --filter @kalekit/web dev

site-dev: ## Start the marketing site (:3001)
	pnpm --filter @kalekit/site dev

admin-dev: ## Start the admin panel (:3002)
	pnpm --filter @kalekit/admin dev

mobile-dev: ## Start the Local app (Expo, dev client)
	pnpm --filter @kalekit/mobile dev

api-client-gen: ## Regenerate @kalekit/api-client types from the running backend
	pnpm --filter @kalekit/api-client generate
