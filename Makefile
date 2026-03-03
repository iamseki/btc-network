# Default target
.DEFAULT_GOAL := help

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
	@echo "  make clean"
	@echo ""
