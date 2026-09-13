# ThreatVeil developer tasks. Run `make` for the list.
# Docker targets act only on the "threatveil" Compose project and its two local images;
# nothing here prunes global Docker state.

COMPOSE ?= $(shell docker compose version >/dev/null 2>&1 && echo "docker compose" || echo docker-compose)
LOCAL_IMAGES := threatveil-python:local threatveil-web:local threatveil-website:local

.DEFAULT_GOAL := help
.PHONY: help up down logs demo demo-live quick-demo setup dev-db migrate dev-api dev-web \
	test test-python lint typecheck test-sdk test-web test-terraform build clean clean-deps \
	clean-docker reset-dev website website-preview

help: ## List targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "} {printf "  %-15s %s\n", $$1, $$2}'

## Docker: nothing but Docker required

up: ## Build and start PostgreSQL, API and web at http://127.0.0.1:3000
	$(COMPOSE) up --build --detach --wait
	@echo "ThreatVeil is running at http://127.0.0.1:3000 (local identity, synthetic data)."

down: ## Stop the stack; the local database is kept
	$(COMPOSE) --profile demo down

logs: ## Follow service logs
	$(COMPOSE) logs --follow

demo: up ## Run the canonical synthetic demonstration end to end
	$(COMPOSE) --profile demo run --rm demo

demo-live: up ## Stop the demonstration at "cleared" and print a sign-in email to continue in the browser
	$(COMPOSE) --profile demo run --rm demo --stop-at cleared

quick-demo: ## Five synthetic cases with no database or API (JSON on stdout)
	$(COMPOSE) build api
	$(COMPOSE) run --rm --no-deps api threatveil demo

build: ## Build the Python and web images
	$(COMPOSE) build

## Host development: Python 3.13 + uv, Node 24 + pnpm, PostgreSQL 17

setup: ## Install locked Python and JavaScript dependencies
	uv sync --locked
	pnpm install --frozen-lockfile

dev-db: ## Start the project-local PostgreSQL on 127.0.0.1:55432 (writes .local/database.env)
	bash scripts/local_db.sh start

migrate: ## Apply database migrations to the project-local PostgreSQL
	uv run alembic upgrade head

dev-api: ## Run the API with reload on 127.0.0.1:8000
	TV_ENV=local TV_LOCAL_AUTH=true uv run uvicorn threatveil.api:app --host 127.0.0.1 --port 8000 --reload

dev-web: ## Run the web workspace with hot reload on 127.0.0.1:3000
	pnpm dev

test: lint test-python ## Lint and run the Python suite (needs `make dev-db migrate`)

test-python: ## Python unit, integration and security tests against the local PostgreSQL
	uv run pytest

lint: ## Ruff
	uv run ruff check src tests infra/scripts scripts

typecheck: ## Strict TypeScript for the web workspace
	pnpm typecheck

test-sdk: ## Build and test the TypeScript SDK
	pnpm test:sdk

test-web: ## Playwright browser suite (needs `make dev-api` and `make dev-web` running)
	pnpm test:web

test-terraform: ## Terraform validate and mocked-provider tests, in a container
	docker run --rm -v "$(CURDIR)/infra":/src:ro --entrypoint sh hashicorp/terraform:1.16.1 \
	  -c 'cp -r /src /infra && cd /infra && terraform init -backend=false -input=false && terraform validate && terraform test'

## Website (threatveil.com)

website: ## Rebuild the static site into website/public from website/src and docs/blog
	uv run --no-project --with markdown==3.8.2 python website/build.py

website-preview: website ## Serve the built site at http://127.0.0.1:8088 with its production nginx image
	docker build -t threatveil-website:local website
	docker run --rm -p 127.0.0.1:8088:8080 threatveil-website:local

## Cleanup

clean: ## Remove regeneratable build output and caches inside this repository
	rm -rf apps/web/.next apps/web/.next-category apps/web/tsconfig.tsbuildinfo \
	  src/threatveil/sdk/typescript/dist .pytest_cache .ruff_cache infra/.terraform \
	  test-results playwright-report apps/web/test-results .local/browser-tests
	find src tests migrations scripts infra apps -type d -name __pycache__ -prune -exec rm -rf {} +

clean-deps: clean ## Also remove installed dependencies (.venv, node_modules)
	rm -rf .venv node_modules apps/web/node_modules src/threatveil/sdk/typescript/node_modules

clean-docker: ## Remove this project's containers, volumes (local database) and local images
	$(COMPOSE) --profile demo down --volumes --remove-orphans
	-docker image rm $(LOCAL_IMAGES)

reset-dev: ## Delete the Compose database and signing key, then start fresh
	$(COMPOSE) --profile demo down --volumes --remove-orphans
	$(MAKE) up
