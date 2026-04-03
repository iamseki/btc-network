# Default target
.DEFAULT_GOAL := help
MAKEFLAGS += --no-print-directory

LOCAL_CARGO_HOME := $(CURDIR)/.cargo-home
LOCAL_ADVISORY_DB := $(LOCAL_CARGO_HOME)/advisory-db
LOCAL_DENY_ADVISORY_DB := $(firstword $(wildcard $(LOCAL_CARGO_HOME)/advisory-dbs/*))
LOCAL_NPM_CACHE := $(CURDIR)/.npm-cache
CRAWLER_CLICKHOUSE_LOCAL_URL := http://localhost:8123
CRAWLER_CLICKHOUSE_LOCAL_DATABASE := btc_network
CRAWLER_CLICKHOUSE_LOCAL_USER := btc_network_dev
CRAWLER_CLICKHOUSE_LOCAL_PASSWORD := btc_network_dev

## Run the crawler binary
crawler:
	@BTC_NETWORK_CLICKHOUSE_URL="$(CRAWLER_CLICKHOUSE_LOCAL_URL)" \
	BTC_NETWORK_CLICKHOUSE_DATABASE="$(CRAWLER_CLICKHOUSE_LOCAL_DATABASE)" \
	BTC_NETWORK_CLICKHOUSE_USER="$(CRAWLER_CLICKHOUSE_LOCAL_USER)" \
	BTC_NETWORK_CLICKHOUSE_PASSWORD="$(CRAWLER_CLICKHOUSE_LOCAL_PASSWORD)" \
	cargo run -p btc-network-crawler -- $(ARGS)

## Apply ClickHouse migrations for the shared persistence schema
clickhouse-migrate:
	@BTC_NETWORK_CLICKHOUSE_URL="$(CRAWLER_CLICKHOUSE_LOCAL_URL)" \
	BTC_NETWORK_CLICKHOUSE_DATABASE="$(CRAWLER_CLICKHOUSE_LOCAL_DATABASE)" \
	BTC_NETWORK_CLICKHOUSE_USER="$(CRAWLER_CLICKHOUSE_LOCAL_USER)" \
	BTC_NETWORK_CLICKHOUSE_PASSWORD="$(CRAWLER_CLICKHOUSE_LOCAL_PASSWORD)" \
	cargo run -p btc-network-clickhouse-migrate -- $(ARGS)

## Start local ClickHouse for crawler development
crawler-dev-up:
	@mkdir -p .dev-data/clickhouse
	@docker compose -f apps/crawler/docker-compose.yml up -d --wait

## Download or refresh local MMDB files for crawler development
crawler-mmdb-update:
	@bash scripts/update-crawler-mmdb.sh

## Stop local ClickHouse for crawler development
crawler-dev-down:
	@docker compose -f apps/crawler/docker-compose.yml down

## Reset local ClickHouse data for crawler development
crawler-dev-reset:
	@docker compose -f apps/crawler/docker-compose.yml down
	@mkdir -p .dev-data/clickhouse
	@docker run --rm -v "$(CURDIR)/.dev-data/clickhouse:/data" alpine:3.21 sh -c 'rm -rf /data/* /data/.[!.]* /data/..?* 2>/dev/null || true'

## Tail local ClickHouse logs for crawler development
crawler-dev-logs:
	@docker compose -f apps/crawler/docker-compose.yml logs -f clickhouse

## Run the listener binary
listener:
	@cargo run -p btc-network-listener

## Run the crawler analytics API with local ClickHouse defaults
api:
	@BTC_NETWORK_CLICKHOUSE_URL="$(CRAWLER_CLICKHOUSE_LOCAL_URL)" \
	BTC_NETWORK_CLICKHOUSE_DATABASE="$(CRAWLER_CLICKHOUSE_LOCAL_DATABASE)" \
	BTC_NETWORK_CLICKHOUSE_USER="$(CRAWLER_CLICKHOUSE_LOCAL_USER)" \
	BTC_NETWORK_CLICKHOUSE_PASSWORD="$(CRAWLER_CLICKHOUSE_LOCAL_PASSWORD)" \
	cargo run -p btc-network-api

## Run crawler timing debug workflow (captures raw logs + timing summary)
crawler-debug:
	@scripts/crawler_timing.sh $(OUT) --timeout-minutes $(TIMEOUT_MINUTES) -- --max-concurrency $(MAX_CONCURRENCY) --idle-timeout-minutes $(IDLE_TIMEOUT_MINUTES)

## Run btc-cli (pass args via ARGS="")
cli:
	@cargo run -p btc-network-cli -- $(ARGS)

## Build all binaries
build:
	@cargo build --workspace --bins

## Install local Rust security tooling
security-tools-install:
	@mkdir -p "$(LOCAL_CARGO_HOME)"
	@CARGO_HOME="$(LOCAL_CARGO_HOME)" cargo install --locked cargo-audit cargo-deny

## Install frontend dependencies
web-install:
	@npm install --prefix apps/web

## Install desktop shell dependencies
desktop-install:
	@npm install --prefix apps/desktop

## Run the web frontend in dev mode
web-dev:
	@npm run dev --prefix apps/web

## Run the Tauri desktop app in dev mode
desktop-dev:
	@test -x apps/desktop/node_modules/.bin/tauri || (echo "desktop dependencies are missing. Run: make desktop-install" && exit 1)
	@npm run dev --prefix apps/desktop

## Run frontend tests
web-test:
	@npm run test --prefix apps/web

## Build the web frontend
web-build:
	@npm run build --prefix apps/web

## Run Rust workspace tests
rust-test:
	@cargo test --workspace --locked

## Run desktop Rust tests
desktop-test:
	@cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml --locked

## Run API tests
api-test:
	@cargo test -p btc-network-api --locked

## Audit Rust dependencies against RustSec
security-rust-audit:
	@mkdir -p "$(LOCAL_CARGO_HOME)"
	@if test -d "$(LOCAL_ADVISORY_DB)/.git"; then \
		CARGO_HOME="$(LOCAL_CARGO_HOME)" cargo audit --db "$(LOCAL_ADVISORY_DB)" --no-fetch --stale; \
	else \
		CARGO_HOME="$(LOCAL_CARGO_HOME)" cargo audit; \
	fi

## Enforce Rust dependency policy (advisories, bans, sources)
security-rust-deny:
	@mkdir -p "$(LOCAL_CARGO_HOME)"
	@if test -n "$(LOCAL_DENY_ADVISORY_DB)" && test -d "$(LOCAL_DENY_ADVISORY_DB)/.git"; then \
		CARGO_HOME="$(LOCAL_CARGO_HOME)" cargo deny check advisories bans sources --disable-fetch; \
	else \
		CARGO_HOME="$(LOCAL_CARGO_HOME)" cargo deny check advisories bans sources; \
	fi

## Run Rust dependency security checks
security-rust:
	@$(MAKE) security-rust-audit
	@$(MAKE) security-rust-deny

## Run npm vulnerability audit
security-web-audit:
	@mkdir -p "$(LOCAL_NPM_CACHE)"
	@npm_config_cache="$(LOCAL_NPM_CACHE)" npm audit --prefix apps/web --audit-level=high

## Verify npm package signatures
security-web-signatures:
	@mkdir -p "$(LOCAL_NPM_CACHE)"
	@npm_config_cache="$(LOCAL_NPM_CACHE)" npm audit signatures --prefix apps/web

## Run frontend dependency security checks
security-web:
	@if getent ahosts registry.npmjs.org >/dev/null 2>&1; then \
		$(MAKE) security-web-audit; \
		$(MAKE) security-web-signatures; \
	else \
		echo "Skipping web security checks: npm registry is unreachable"; \
	fi

## Run all dependency security checks
security:
	@$(MAKE) security-rust
	@$(MAKE) security-web

## Run tests
test:
	@bash scripts/test_summary.sh

## Clean build artifacts
clean:
	@cargo clean

## Show available commands
help:
	@echo ""
	@echo "Available targets:"
	@echo "  make crawler ARGS=\"--mmdb-asn-path .dev-data/mmdb/GeoLite2-ASN.mmdb --mmdb-country-path .dev-data/mmdb/GeoLite2-Country.mmdb\""
	@echo "  make clickhouse-migrate"
	@echo "    uses local dev ClickHouse defaults: url=$(CRAWLER_CLICKHOUSE_LOCAL_URL) db=$(CRAWLER_CLICKHOUSE_LOCAL_DATABASE) user=$(CRAWLER_CLICKHOUSE_LOCAL_USER)"
	@echo "  make crawler-dev-up"
	@echo "  make crawler-mmdb-update"
	@echo "  make crawler-dev-down"
	@echo "  make crawler-dev-reset"
	@echo "  make crawler-dev-logs"
	@echo "  make crawler-debug"
	@echo "    example: make crawler-debug TIMEOUT_MINUTES=5 MAX_CONCURRENCY=1000 IDLE_TIMEOUT_MINUTES=5 OUT=artifacts/crawler-timing-run-1"
	@echo "  make listener"
	@echo "  make api"
	@echo "    uses local dev ClickHouse defaults: url=$(CRAWLER_CLICKHOUSE_LOCAL_URL) db=$(CRAWLER_CLICKHOUSE_LOCAL_DATABASE) user=$(CRAWLER_CLICKHOUSE_LOCAL_USER)"
	@echo "  make cli ARGS=\"--node host:port ping\""
	@echo "  make build"
	@echo "  make test"
	@echo "    runs Rust workspace tests and web tests with an aggregate summary"
	@echo "  make security-tools-install"
	@echo "  make security-rust"
	@echo "  make security-web"
	@echo "  make security"
	@echo "  make web-install"
	@echo "  make web-dev"
	@echo "  make web-test"
	@echo "  make web-build"
	@echo "  make rust-test"
	@echo "  make api-test"
	@echo "  make desktop-install"
	@echo "  make desktop-dev"
	@echo "  make desktop-test"
	@echo "  make clean"
	@echo ""
