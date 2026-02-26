# Default target
.DEFAULT_GOAL := help

## Run the crawler binary
crawler:
	@cargo run --bin crawler

## Run the listener binary
listener:
	@cargo run --bin listener

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
	@echo "  make listener"
	@echo "  make cli ARGS=\"--node host:port ping\""
	@echo "  make build"
	@echo "  make test"
	@echo "  make clean"
	@echo ""