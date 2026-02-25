# Default target
.DEFAULT_GOAL := help

## Run the crawler binary
crawler:
	@cargo run --bin crawler

## Run the listener binary
listener:
	@cargo run --bin listener

## Run crawler in release mode
crawler-release:
	@cargo run --release --bin crawler

## Run listener in release mode
listener-release:
	@cargo run --release --bin listener

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
	@echo "  make crawler    - Run crawler binary"
	@echo "  make listener   - Run listener binary"
	@echo "  make build      - Build all binaries"
	@echo "  make test       - Run tests"
	@echo "  make clean      - Clean target directory"
	@echo ""