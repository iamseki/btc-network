# Repository workflow Makefile.
#
# Conventions:
# - Run `make help` for the generated command list grouped by section.
# - Put a target's one-line help text after `##` on the same line as the target.
# - Start a help section with `##@ Section Name`.
# - Keep recipes small and direct. Move multi-step or reusable shell logic into
#   scripts/ instead of growing large inline recipes here.
# - Prefer repo-specific workflows here. Do not add wrappers for generic tools
#   unless they remove repeated project-specific setup.
#
# Examples:
# - `make crawler ARGS="--mmdb-asn-path ... --mmdb-country-path ..."`
# - `make postgres-migrate`
# - `make test`
# - `make setup-git-hooks`
#
.DEFAULT_GOAL := help
MAKEFLAGS += --no-print-directory

# These are convenience targets rather than real build artifacts.
.PHONY: \
	help \
	crawler \
	postgres-migrate \
	infra-postgres-up \
	infra-postgres-down \
	infra-postgres-reset \
	infra-crawler-up \
	infra-api-up \
	infra-crawler-api-up \
	infra-compose-down \
	crawler-mmdb-update \
	api \
	listener \
	crawler-debug \
	cli \
	build \
	security-tools-install \
	setup-git-hooks \
	web-install \
	desktop-install \
	web-dev \
	desktop-dev \
	web-test \
	web-build \
	rust-test \
	desktop-test \
	api-test \
	security-rust-audit \
	security-rust-deny \
	security-rust \
	security-web-audit \
	security-web-signatures \
	security-web \
	security \
	test \
	clean

# Local caches and per-clone configuration stay inside the repository so setup
# is reproducible and does not depend on the developer's global machine state.
LOCAL_CARGO_HOME := $(CURDIR)/.cargo-home
LOCAL_ADVISORY_DB := $(LOCAL_CARGO_HOME)/advisory-db
LOCAL_DENY_ADVISORY_DB := $(firstword $(wildcard $(LOCAL_CARGO_HOME)/advisory-dbs/*))
LOCAL_NPM_CACHE := $(CURDIR)/.npm-cache
LOCAL_GIT_HOOKS_PATH := .githooks
DOCKER_COMPOSE := docker compose -f docker-compose.yml

# Shared local PostgreSQL defaults used by the crawler, API, and migration
# targets. Override per command via ARGS when a non-default local setup is
# needed.
CRAWLER_POSTGRES_LOCAL_URL := postgresql://btc_network_dev:btc_network_dev@localhost:5432/btc_network
CRAWLER_POSTGRES_LOCAL_MAX_CONNECTIONS := 16

POSTGRES_LOCAL_ENV = \
	BTC_NETWORK_POSTGRES_URL="$(CRAWLER_POSTGRES_LOCAL_URL)" \
	BTC_NETWORK_POSTGRES_MAX_CONNECTIONS="$(CRAWLER_POSTGRES_LOCAL_MAX_CONNECTIONS)"

##@ Runtime

crawler: ## Run the crawler binary with local PostgreSQL defaults; pass crawler flags via ARGS="..."
	@$(POSTGRES_LOCAL_ENV) cargo run -p btc-network-crawler -- $(ARGS)

postgres-migrate: ## Apply PostgreSQL migrations with local development defaults; pass overrides via ARGS="..."
	@$(POSTGRES_LOCAL_ENV) cargo run -p btc-network-postgres-migrate -- $(ARGS)

infra-postgres-up: ## Start the shared local PostgreSQL service
	@mkdir -p .dev-data/postgres
	@$(DOCKER_COMPOSE) up -d --wait postgres

infra-postgres-down: ## Stop the shared local PostgreSQL service
	@$(DOCKER_COMPOSE) stop postgres

infra-postgres-reset: ## Reset local PostgreSQL data under .dev-data/postgres
	@$(DOCKER_COMPOSE) rm -fs postgres >/dev/null 2>&1 || true
	@mkdir -p .dev-data/postgres
	@docker run --rm -v "$(CURDIR)/.dev-data/postgres:/data" alpine:3.21 sh -c 'rm -rf /data/* /data/.[!.]* /data/..?* 2>/dev/null || true'

infra-crawler-up: ## Start postgres, migrations, and the crawler via the crawler Compose profile
	@mkdir -p .dev-data/postgres
	@$(DOCKER_COMPOSE) --profile crawler up

infra-api-up: ## Start postgres, migrations, and the API via the api Compose profile
	@mkdir -p .dev-data/postgres
	@$(DOCKER_COMPOSE) --profile api up

infra-crawler-api-up: ## Start postgres, migrations, crawler, and API via both Compose profiles
	@mkdir -p .dev-data/postgres
	@$(DOCKER_COMPOSE) --profile crawler --profile api up

infra-compose-down: ## Stop and remove all local Compose services in this repository stack
	@$(DOCKER_COMPOSE) down

crawler-mmdb-update: ## Download or refresh local MMDB files for crawler development
	@bash scripts/update-crawler-mmdb.sh

api: ## Run the crawler analytics API with local PostgreSQL defaults
	@$(POSTGRES_LOCAL_ENV) cargo run -p btc-network-api -- $(ARGS)

listener: ## Run the listener binary; pass extra flags via ARGS="..."
	@cargo run -p btc-network-listener -- $(ARGS)

crawler-debug: ## Capture crawler timing artifacts; set OUT=... and optional TIMEOUT_MINUTES/MAX_CONCURRENCY/IDLE_TIMEOUT_MINUTES
	@scripts/crawler_timing.sh $(OUT) --timeout-minutes $(TIMEOUT_MINUTES) -- --max-concurrency $(MAX_CONCURRENCY) --idle-timeout-minutes $(IDLE_TIMEOUT_MINUTES)

cli: ## Run btc-network-cli; pass command flags via ARGS="..."
	@cargo run -p btc-network-cli -- $(ARGS)

##@ Setup

security-tools-install: ## Install local Rust security tooling into .cargo-home
	@mkdir -p "$(LOCAL_CARGO_HOME)"
	@CARGO_HOME="$(LOCAL_CARGO_HOME)" cargo install --locked cargo-audit cargo-deny

setup-git-hooks: ## Enable repo-local git hooks for this clone
	@git config --local core.hooksPath "$(LOCAL_GIT_HOOKS_PATH)"
	@echo "Configured core.hooksPath=$(LOCAL_GIT_HOOKS_PATH) for this clone"

web-install: ## Install web dependencies with npm ci
	@npm ci --prefix apps/web

desktop-install: ## Install desktop dependencies with npm ci
	@npm ci --prefix apps/desktop

##@ Development

web-dev: ## Run the web frontend in dev mode
	@npm run dev --prefix apps/web

desktop-dev: ## Run the Tauri desktop app in dev mode
	@test -x apps/desktop/node_modules/.bin/tauri || (echo "desktop dependencies are missing. Run: make desktop-install" && exit 1)
	@npm run dev --prefix apps/desktop

build: ## Build all workspace binaries
	@cargo build --workspace --bins

clean: ## Clean Rust build artifacts
	@cargo clean

##@ Verification

web-test: ## Run frontend tests
	@npm run test --prefix apps/web

web-build: ## Build the web frontend
	@npm run build --prefix apps/web

rust-test: ## Run Rust workspace tests
	@cargo test --workspace --locked

desktop-test: ## Run desktop Rust tests
	@cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml --locked

api-test: ## Run API tests
	@cargo test -p btc-network-api --locked

test: ## Run the repository test summary flow
	@bash scripts/test_summary.sh

##@ Security

security-rust-audit: ## Audit Rust dependencies against RustSec
	@mkdir -p "$(LOCAL_CARGO_HOME)"
	@if test -d "$(LOCAL_ADVISORY_DB)/.git"; then \
		CARGO_HOME="$(LOCAL_CARGO_HOME)" cargo audit --db "$(LOCAL_ADVISORY_DB)" --no-fetch --stale; \
	else \
		CARGO_HOME="$(LOCAL_CARGO_HOME)" cargo audit; \
	fi

security-rust-deny: ## Enforce Rust dependency policy for advisories, bans, and sources
	@mkdir -p "$(LOCAL_CARGO_HOME)"
	@if test -n "$(LOCAL_DENY_ADVISORY_DB)" && test -d "$(LOCAL_DENY_ADVISORY_DB)/.git"; then \
		CARGO_HOME="$(LOCAL_CARGO_HOME)" cargo deny check advisories bans sources --disable-fetch; \
	else \
		CARGO_HOME="$(LOCAL_CARGO_HOME)" cargo deny check advisories bans sources; \
	fi

security-rust: ## Run Rust dependency security checks
	@$(MAKE) security-rust-audit
	@$(MAKE) security-rust-deny

security-web-audit: ## Run npm vulnerability audit for the web app
	@mkdir -p "$(LOCAL_NPM_CACHE)"
	@npm_config_cache="$(LOCAL_NPM_CACHE)" npm audit --prefix apps/web --audit-level=high

security-web-signatures: ## Verify npm package signatures for the web app
	@mkdir -p "$(LOCAL_NPM_CACHE)"
	@npm_config_cache="$(LOCAL_NPM_CACHE)" npm audit signatures --prefix apps/web

security-web: ## Run frontend dependency security checks when the npm registry is reachable
	@if getent ahosts registry.npmjs.org >/dev/null 2>&1; then \
		$(MAKE) security-web-audit; \
		$(MAKE) security-web-signatures; \
	else \
		echo "Skipping web security checks: npm registry is unreachable"; \
	fi

security: ## Run all dependency security checks with concise output; set SECURITY_VERBOSE=1 for full tool output
	@bash scripts/security_summary.sh

##@ Help

help: ## Show available commands
	@awk 'BEGIN { \
		FS = ":.*## "; \
		printf "\nUsage:\n  make <target>\n"; \
		printf "\nNotes:\n"; \
		printf "  ARGS=... passes extra CLI flags to wrapper targets such as crawler, cli, api, and postgres-migrate.\n"; \
		printf "  Targets are grouped by section below.\n"; \
	} \
	/^##@/ { \
		printf "\n%s\n", substr($$0, 5); \
		next; \
	} \
	/^[a-zA-Z0-9_.-]+:.*## / { \
		printf "  %-24s %s\n", $$1, $$2; \
	}' $(MAKEFILE_LIST)
