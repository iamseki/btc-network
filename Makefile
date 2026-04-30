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
# - `make crawler-unreachable-recovery ARGS="--mmdb-asn-path ... --mmdb-country-path ..."`
# - `make postgres-migrate`
# - `make infra-tf-prod-plan TF_STATE_BUCKET=...`
# - `make infra-aws-api-status API_SSM_INSTANCE_ID=i-...`
# - `make infra-aws-postgres-status POSTGRES_SSM_INSTANCE_ID=i-...`
# - `make test`
# - `make setup-git-hooks`
#
.DEFAULT_GOAL := help
MAKEFLAGS += --no-print-directory

# These are convenience targets rather than real build artifacts.
.PHONY: \
	help \
	crawler \
	crawler-unreachable-recovery \
	postgres-migrate \
	infra-postgres-up \
	infra-postgres-down \
	infra-postgres-reset \
	infra-crawler-up \
	infra-crawler-up-build \
	infra-api-up \
	infra-api-up-build \
	infra-crawler-api-up \
	infra-crawler-api-up-build \
	infra-compose-down \
	infra-compose-reset \
	infra-linux-check \
	infra-tf-fmt \
	infra-tf-fmt-check \
	infra-tf-bootstrap-init \
	infra-tf-bootstrap-plan \
	infra-tf-bootstrap-apply \
	infra-tf-prod-init \
	infra-tf-prod-validate \
	infra-tf-prod-plan \
	infra-tf-prod-apply \
	infra-aws-ssm-session \
	infra-aws-ssm-command \
	infra-aws-api-status \
	infra-aws-postgres-status \
	infra-aws-postgres-backup-status \
	infra-aws-postgres-backup-run \
	infra-aws-crawler-status \
	infra-aws-crawler-timer-status \
	infra-aws-crawler-run \
	crawler-mmdb-update \
	api \
	crawler-debug \
	cli \
	build \
	security-tools-install \
	setup-git-hooks \
	web-install \
	desktop-install \
	web-dev \
	web-dev-demo \
	desktop-dev \
	web-test \
	web-build \
	web-build-demo \
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
COMPOSE_BUILD_FLAG := $(if $(filter 1 true yes,$(BUILD)),--build,)
AWS ?= aws
AWS_REGION ?= us-east-1
TERRAFORM ?= terraform
TERRAFORM_BOOTSTRAP_DIR := infra/terraform/bootstrap
TERRAFORM_PROD_DIR := infra/terraform/envs/prod
TF_BOOTSTRAP_VAR_FILE ?= terraform.tfvars
TF_PROD_VAR_FILE ?= terraform.tfvars
TF_STATE_KEY ?= envs/prod/terraform.tfstate
TF_STATE_REGION ?= $(AWS_REGION)
TF_STATE_BUCKET ?=
SSM_INSTANCE_ID ?=
API_SSM_INSTANCE_ID ?= $(SSM_INSTANCE_ID)
POSTGRES_SSM_INSTANCE_ID ?= $(SSM_INSTANCE_ID)
CRAWLER_SSM_INSTANCE_ID ?= $(API_SSM_INSTANCE_ID)
SSM_COMMAND ?=
SYSTEMD_VERIFY ?=

# Shared local PostgreSQL defaults used by the crawler, API, and migration
# targets. Override per command via ARGS when a non-default local setup is
# needed.
CRAWLER_POSTGRES_LOCAL_URL := postgresql://btc_network_dev:btc_network_dev@localhost:5432/btc_network
CRAWLER_POSTGRES_LOCAL_MAX_CONNECTIONS := 16
TEST_POSTGRES_ADMIN_URL := postgresql://btc_network_dev:btc_network_dev@localhost:5432/postgres

POSTGRES_LOCAL_ENV = \
	BTC_NETWORK_POSTGRES_URL="$(CRAWLER_POSTGRES_LOCAL_URL)" \
	BTC_NETWORK_POSTGRES_MAX_CONNECTIONS="$(CRAWLER_POSTGRES_LOCAL_MAX_CONNECTIONS)"

API_TEST_ENV = \
	BTC_NETWORK_TEST_POSTGRES_ADMIN_URL="$(TEST_POSTGRES_ADMIN_URL)"

##@ Runtime

crawler: ## Run the crawler binary with local PostgreSQL defaults; pass crawler flags via ARGS="..."
	@$(POSTGRES_LOCAL_ENV) cargo run -p btc-network-crawler -- $(ARGS)

crawler-unreachable-recovery: ## Retry only currently unreachable nodes; pass flags via ARGS="..."
	@$(POSTGRES_LOCAL_ENV) cargo run -p btc-network-crawler -- recover-unreachable $(ARGS)

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

infra-crawler-up: ## Start postgres, migrations, tor, and the crawler via the crawler Compose profile; set BUILD=1 to force image rebuilds
	@mkdir -p .dev-data/postgres
	@$(DOCKER_COMPOSE) --profile crawler up $(COMPOSE_BUILD_FLAG)

infra-api-up: ## Start postgres, migrations, and the API via the api Compose profile; set BUILD=1 to force image rebuilds
	@mkdir -p .dev-data/postgres
	@$(DOCKER_COMPOSE) --profile api up $(COMPOSE_BUILD_FLAG)

infra-crawler-api-up: ## Start postgres, migrations, tor, crawler, and API via both Compose profiles; set BUILD=1 to force image rebuilds
	@mkdir -p .dev-data/postgres
	@$(DOCKER_COMPOSE) --profile crawler --profile api up $(COMPOSE_BUILD_FLAG)

infra-crawler-up-build: ## Start postgres, migrations, tor, and crawler with forced image rebuilds
	@$(MAKE) infra-crawler-up BUILD=1

infra-api-up-build: ## Start postgres, migrations, and API with forced image rebuilds
	@$(MAKE) infra-api-up BUILD=1

infra-crawler-api-up-build: ## Start postgres, migrations, tor, crawler, and API with forced image rebuilds
	@$(MAKE) infra-crawler-api-up BUILD=1

infra-compose-down: ## Stop and remove all local Compose services in this repository stack
	@$(DOCKER_COMPOSE) --profile crawler --profile api down --remove-orphans

infra-compose-reset: ## Force-remove local Compose containers and network metadata when Docker state is stale
	@$(DOCKER_COMPOSE) --profile crawler --profile api down --remove-orphans >/dev/null 2>&1 || true
	@docker rm -f btc-network-postgres btc-network-postgres-migrate btc-network-tor btc-network-crawler btc-network-api >/dev/null 2>&1 || true
	@docker network rm btc-network_default >/dev/null 2>&1 || true

##@ Hosted Infrastructure

infra-linux-check: ## Check portable Linux shell artifacts; set SYSTEMD_VERIFY=1 to verify units locally
	@bash -n infra/linux/scripts/*.sh infra/linux/firewall/*.sh
	@if test "$(SYSTEMD_VERIFY)" = "1" && command -v systemd-analyze >/dev/null 2>&1; then \
		systemd-analyze verify infra/linux/systemd/*.service infra/linux/systemd/*.timer; \
	else \
		echo "Skipping systemd unit verification. Set SYSTEMD_VERIFY=1 on a compatible Linux host to enable it."; \
	fi

infra-tf-fmt: ## Format all Terraform HCL under infra/terraform
	@$(TERRAFORM) fmt -recursive infra/terraform

infra-tf-fmt-check: ## Check Terraform HCL formatting under infra/terraform
	@$(TERRAFORM) fmt -check -recursive infra/terraform

infra-tf-bootstrap-init: ## Initialize bootstrap Terraform root with local state
	@cd "$(TERRAFORM_BOOTSTRAP_DIR)" && $(TERRAFORM) init

infra-tf-bootstrap-plan: ## Plan bootstrap Terraform root; override TF_BOOTSTRAP_VAR_FILE or pass ARGS="..."
	@cd "$(TERRAFORM_BOOTSTRAP_DIR)" && $(TERRAFORM) plan -var-file="$(TF_BOOTSTRAP_VAR_FILE)" $(ARGS)

infra-tf-bootstrap-apply: ## Apply bootstrap Terraform root; requires CONFIRM_APPLY=1
	@test "$(CONFIRM_APPLY)" = "1" || (echo "Refusing apply. Re-run with CONFIRM_APPLY=1 after reviewing the plan." && exit 1)
	@cd "$(TERRAFORM_BOOTSTRAP_DIR)" && $(TERRAFORM) apply -var-file="$(TF_BOOTSTRAP_VAR_FILE)" $(ARGS)

infra-tf-prod-init: ## Initialize prod Terraform backend; requires TF_STATE_BUCKET=...
	@test -n "$(TF_STATE_BUCKET)" || (echo "Set TF_STATE_BUCKET to the bootstrap state bucket." && exit 1)
	@cd "$(TERRAFORM_PROD_DIR)" && $(TERRAFORM) init \
		-backend-config="bucket=$(TF_STATE_BUCKET)" \
		-backend-config="key=$(TF_STATE_KEY)" \
		-backend-config="region=$(TF_STATE_REGION)" \
		-backend-config="use_lockfile=true"

infra-tf-prod-validate: ## Validate prod Terraform root without remote backend access
	@cd "$(TERRAFORM_PROD_DIR)" && $(TERRAFORM) init -backend=false
	@cd "$(TERRAFORM_PROD_DIR)" && $(TERRAFORM) validate

infra-tf-prod-plan: ## Plan prod Terraform root after init; override TF_PROD_VAR_FILE or pass ARGS="..."
	@cd "$(TERRAFORM_PROD_DIR)" && $(TERRAFORM) plan -var-file="$(TF_PROD_VAR_FILE)" $(ARGS)

infra-tf-prod-apply: ## Apply prod Terraform root; requires CONFIRM_APPLY=1
	@test "$(CONFIRM_APPLY)" = "1" || (echo "Refusing apply. Re-run with CONFIRM_APPLY=1 after reviewing the plan." && exit 1)
	@cd "$(TERRAFORM_PROD_DIR)" && $(TERRAFORM) apply -var-file="$(TF_PROD_VAR_FILE)" $(ARGS)

infra-aws-ssm-session: ## Open an AWS SSM shell session; requires SSM_INSTANCE_ID=...
	@test -n "$(SSM_INSTANCE_ID)" || (echo "Set SSM_INSTANCE_ID to the EC2 instance id." && exit 1)
	@$(AWS) ssm start-session --region "$(AWS_REGION)" --target "$(SSM_INSTANCE_ID)"

infra-aws-ssm-command: ## Run one AWS SSM shell command; requires SSM_INSTANCE_ID=... SSM_COMMAND='...'
	@test -n "$(SSM_INSTANCE_ID)" || (echo "Set SSM_INSTANCE_ID to the EC2 instance id." && exit 1)
	@test -n "$(SSM_COMMAND)" || (echo "Set SSM_COMMAND to the host command to run." && exit 1)
	@command_id="$$($(AWS) ssm send-command \
		--region "$(AWS_REGION)" \
		--instance-ids "$(SSM_INSTANCE_ID)" \
		--document-name "AWS-RunShellScript" \
		--comment "btc-network make infra-aws-ssm-command" \
		--parameters commands='["$(SSM_COMMAND)"]' \
		--query 'Command.CommandId' \
		--output text)"; \
	echo "SSM command id: $$command_id"; \
	$(AWS) ssm wait command-executed \
		--region "$(AWS_REGION)" \
		--command-id "$$command_id" \
		--instance-id "$(SSM_INSTANCE_ID)" || true; \
	$(AWS) ssm get-command-invocation \
		--region "$(AWS_REGION)" \
		--command-id "$$command_id" \
		--instance-id "$(SSM_INSTANCE_ID)" \
		--query '{Status:Status,ResponseCode:ResponseCode,Stdout:StandardOutputContent,Stderr:StandardErrorContent}' \
		--output json

infra-aws-api-status: ## Request btc-network API systemd status through SSM; requires API_SSM_INSTANCE_ID=...
	@test -n "$(API_SSM_INSTANCE_ID)" || (echo "Set API_SSM_INSTANCE_ID to the API/crawler EC2 instance id." && exit 1)
	@$(MAKE) infra-aws-ssm-command SSM_INSTANCE_ID="$(API_SSM_INSTANCE_ID)" SSM_COMMAND='systemctl status btc-network-api --no-pager'

infra-aws-postgres-status: ## Request PostgreSQL systemd status through SSM; requires POSTGRES_SSM_INSTANCE_ID=...
	@test -n "$(POSTGRES_SSM_INSTANCE_ID)" || (echo "Set POSTGRES_SSM_INSTANCE_ID to the PostgreSQL EC2 instance id." && exit 1)
	@$(MAKE) infra-aws-ssm-command SSM_INSTANCE_ID="$(POSTGRES_SSM_INSTANCE_ID)" SSM_COMMAND='systemctl status postgresql --no-pager'

infra-aws-postgres-backup-status: ## Request PostgreSQL backup timer status through SSM; requires POSTGRES_SSM_INSTANCE_ID=...
	@test -n "$(POSTGRES_SSM_INSTANCE_ID)" || (echo "Set POSTGRES_SSM_INSTANCE_ID to the PostgreSQL EC2 instance id." && exit 1)
	@$(MAKE) infra-aws-ssm-command SSM_INSTANCE_ID="$(POSTGRES_SSM_INSTANCE_ID)" SSM_COMMAND='systemctl status btc-network-postgres-backup.timer --no-pager'

infra-aws-postgres-backup-run: ## Trigger one PostgreSQL backup service run through SSM; requires POSTGRES_SSM_INSTANCE_ID=...
	@test -n "$(POSTGRES_SSM_INSTANCE_ID)" || (echo "Set POSTGRES_SSM_INSTANCE_ID to the PostgreSQL EC2 instance id." && exit 1)
	@$(MAKE) infra-aws-ssm-command SSM_INSTANCE_ID="$(POSTGRES_SSM_INSTANCE_ID)" SSM_COMMAND='systemctl start btc-network-postgres-backup.service'

infra-aws-crawler-status: ## Request crawler systemd status through SSM; requires CRAWLER_SSM_INSTANCE_ID=...; defaults to API_SSM_INSTANCE_ID
	@test -n "$(CRAWLER_SSM_INSTANCE_ID)" || (echo "Set API_SSM_INSTANCE_ID or CRAWLER_SSM_INSTANCE_ID to the crawler EC2 instance id." && exit 1)
	@$(MAKE) infra-aws-ssm-command SSM_INSTANCE_ID="$(CRAWLER_SSM_INSTANCE_ID)" SSM_COMMAND='systemctl status btc-network-crawler --no-pager'

infra-aws-crawler-timer-status: ## Request crawler timer status through SSM; requires CRAWLER_SSM_INSTANCE_ID=...; defaults to API_SSM_INSTANCE_ID
	@test -n "$(CRAWLER_SSM_INSTANCE_ID)" || (echo "Set API_SSM_INSTANCE_ID or CRAWLER_SSM_INSTANCE_ID to the crawler EC2 instance id." && exit 1)
	@$(MAKE) infra-aws-ssm-command SSM_INSTANCE_ID="$(CRAWLER_SSM_INSTANCE_ID)" SSM_COMMAND='systemctl status btc-network-crawler.timer --no-pager'

infra-aws-crawler-run: ## Trigger one crawler oneshot run through SSM; requires CRAWLER_SSM_INSTANCE_ID=...; defaults to API_SSM_INSTANCE_ID
	@test -n "$(CRAWLER_SSM_INSTANCE_ID)" || (echo "Set API_SSM_INSTANCE_ID or CRAWLER_SSM_INSTANCE_ID to the crawler EC2 instance id." && exit 1)
	@$(MAKE) infra-aws-ssm-command SSM_INSTANCE_ID="$(CRAWLER_SSM_INSTANCE_ID)" SSM_COMMAND='systemctl start btc-network-crawler.service'

crawler-mmdb-update: ## Download or refresh local MMDB files for crawler development
	@bash scripts/update-crawler-mmdb.sh

api: ## Run the crawler analytics API with local PostgreSQL defaults
	@$(POSTGRES_LOCAL_ENV) cargo run -p btc-network-api -- $(ARGS)

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

web-dev-demo: ## Run the web frontend in mock/demo mode with VITE_DEMO_MODE=true
	@VITE_DEMO_MODE=true npm run dev --prefix apps/web

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

web-build-demo: ## Build the web frontend in mock/demo mode with VITE_DEMO_MODE=true
	@VITE_DEMO_MODE=true npm run build --prefix apps/web

rust-test: ## Run Rust workspace tests
	@cargo test --workspace --locked

desktop-test: ## Run desktop Rust tests
	@cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml --locked

api-test: ## Run API tests against shared local PostgreSQL; start it first with make infra-postgres-up
	@$(API_TEST_ENV) cargo test -p btc-network-api --locked $(ARGS)

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

loc-summary: ## Show line count summary for apps, compose, and crates
	@for dir in apps compose crates; do \
		git ls-files "$$dir/*" | xargs wc -l | tail -n 1 | sed "s/total$$/$$dir/"; \
	done
	@echo "----------"
	@git ls-files 'apps/*' 'compose/*' 'crates/*' | xargs wc -l | tail -n 1

##@ Help

help: ## Show available commands
	@awk 'BEGIN { \
		FS = ":.*## "; \
		printf "\nUsage:\n  make <target>\n"; \
		printf "\nNotes:\n"; \
		printf "  ARGS=... passes extra CLI flags to wrapper targets such as crawler, cli, api, and postgres-migrate.\n"; \
		printf "  Hosted infra targets use AWS_REGION, TF_STATE_BUCKET, API_SSM_INSTANCE_ID, POSTGRES_SSM_INSTANCE_ID, CONFIRM_APPLY, and ARGS where relevant.\n"; \
		printf "  Demo web mode: use make web-dev-demo for local mocked analytics or make web-build-demo for a demo build.\n"; \
		printf "  Targets are grouped by section below.\n"; \
	} \
	/^##@/ { \
		printf "\n%s\n", substr($$0, 5); \
		next; \
	} \
	/^[a-zA-Z0-9_.-]+:.*## / { \
		printf "  %-24s %s\n", $$1, $$2; \
	}' $(MAKEFILE_LIST)
