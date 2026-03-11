# Default target
.DEFAULT_GOAL := help

LOCAL_CARGO_HOME := $(CURDIR)/.cargo-home
LOCAL_NPM_CACHE := $(CURDIR)/.npm-cache

## Run the crawler binary
crawler:
	@cargo run --bin crawler

## Run the listener binary
listener:
	@cargo run --bin listener

## Run crawler timing debug workflow (captures raw logs + timing summary)
crawler-debug:
	@scripts/crawler_timing.sh $(OUT) --timeout-minutes $(TIMEOUT_MINUTES) -- --max-concurrency $(MAX_CONCURRENCY) --idle-timeout-minutes $(IDLE_TIMEOUT_MINUTES)

## Run btc-cli (pass args via ARGS="")
cli:
	@cargo run --bin cli -- $(ARGS)

## Build all binaries
build:
	@cargo build --bins

## Install local Rust security tooling
security-tools-install:
	@mkdir -p "$(LOCAL_CARGO_HOME)"
	@CARGO_HOME="$(LOCAL_CARGO_HOME)" cargo install --locked cargo-audit cargo-deny

## Install frontend dependencies
web-install:
	@npm install --prefix apps/web

## Run the web frontend in dev mode
web-dev:
	@npm run dev --prefix apps/web

## Run frontend tests
web-test:
	@npm run test --prefix apps/web

## Build the web frontend
web-build:
	@npm run build --prefix apps/web

## Audit Rust dependencies against RustSec
security-rust-audit:
	@mkdir -p "$(LOCAL_CARGO_HOME)"
	@CARGO_HOME="$(LOCAL_CARGO_HOME)" cargo audit

## Enforce Rust dependency policy (advisories, bans, sources)
security-rust-deny:
	@mkdir -p "$(LOCAL_CARGO_HOME)"
	@CARGO_HOME="$(LOCAL_CARGO_HOME)" cargo deny check advisories bans sources

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
	@$(MAKE) security-web-audit
	@$(MAKE) security-web-signatures

## Run all dependency security checks
security:
	@$(MAKE) security-rust
	@$(MAKE) security-web

## Run tests
test:
	@cargo test

## Clean build artifacts
clean:
	@cargo clean

## Show available commands
help:
	@echo ""
	@echo "Available targets:"
	@echo "  make crawler"
	@echo "  make crawler-debug"
	@echo "    example: make crawler-debug TIMEOUT_MINUTES=5 MAX_CONCURRENCY=1000 IDLE_TIMEOUT_MINUTES=5 OUT=artifacts/crawler-timing-run-1"
	@echo "  make listener"
	@echo "  make cli ARGS=\"--node host:port ping\""
	@echo "  make build"
	@echo "  make test"
	@echo "  make security-tools-install"
	@echo "  make security-rust"
	@echo "  make security-web"
	@echo "  make security"
	@echo "  make web-install"
	@echo "  make web-dev"
	@echo "  make web-test"
	@echo "  make web-build"
	@echo "  make clean"
	@echo ""
