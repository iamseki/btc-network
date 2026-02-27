# AGENTS.md

Guidance for Codex and other coding agents working in this repository.

## Project Summary

Language: Rust (edition 2024)
Crate: btc-network

## Goal

Develop a research-focused Bitcoin P2P implementation in Rust that exposes the protocol’s internal mechanics — from handshake to block and transaction decoding — emphasizing:

- Clear separation between transport, framing, decoding, and consensus modeling
- Typed representations of wire-level and consensus objects
- Deterministic parsing with explicit error handling
- Protocol correctness over feature completeness
- Architectural rigor suitable for systems exploration

This is not a wallet, miner, or full node clone. It is a protocol engineering project designed to understand how Bitcoin works under the hood.

## Architectural Principles

1. Transport Layer

- `TcpStream`
- No protocol knowledge
- No parsing logic

2. Wire Layer

Located under `src/wire/`.

Responsibilities:

- Envelope framing (magic, command, length, checksum)
- Byte-level parsing
- Typed message dispatch
- Deterministic decoding
- Explicit cursor management
- No connection state

Wire code must not:

- Perform business logic
- Depend on CLI behavior
- Mix transport and consensus interpretation

3. Session Layer

Located in src/session.rs.

Responsibilities:

- Stateful peer interaction
- Handshake ordering
- Ping/pong liveness
- Request/response orchestration

Session must not:

- Contain parsing logic
- Duplicate wire decoding
- Embed CLI decisions

4. Binary Orchestration

Located under `src/bin/`.

Responsibilities:

- User-facing flows
- CLI commands
- Demonstration paths (crawler, listener)
- High-level orchestration

Binaries must not:

- Implement ad-hoc parsing
- Bypass session or wire layers
- Re-encode protocol rules locally

## Repository Layout

- src/lib.rs — crate entry
- src/session.rs — stateful peer interaction
- src/wire/codec.rs — framing (read/write envelope)
- src/wire/decode.rs — byte-level decode helpers (varint, slices, cursor)
- src/wire/message.rs — typed Message enum + dispatch
- src/wire/payload.rs — outbound message builders
- src/wire/constants.rs — protocol constants (magic, seeds, genesis, versions)
- src/bin/cli.rs — interactive CLI
- src/bin/crawler.rs — DNS seed crawler
- src/bin/listener.rs — long-running listener

## Protocol Rules To Preserve

These rules reflect real Bitcoin behavior and must not be violated.

### Handshake Ordering

- Send version
- Receive peer version
- Send sendaddrv2 (before verack)
- Send verack
- Receive peer verack

Ordering matters.

### Ping / Pong

- Ping must be answered with Pong
- Payload must match exactly
- Do not ignore keepalive

### Endianness Discipline

- Hashes transmitted little-endian
- Displayed big-endian
- Reversal must be explicit and localized
- Never silently reverse inside core types

## Design Constraints
- No hidden retries
- No silent error swallowing
- Explicit timeouts
- Deterministic decoding
- Avoid unnecessary dependencies
- Favor typed domain objects over raw byte vectors
- Preserve architectural boundaries

## Build, Run, Test

Primary commands:

```bash
make build
make test
make crawler
make listener
make cli ARGS="--node seed.bitcoin.sipa.be:8333 ping"
make cli ARGS="--node seed.bitcoin.sipa.be:8333 get-addr"
make cli ARGS="--node seed.bitcoin.sipa.be:8333 get-headers"
make cli ARGS="--node seed.bitcoin.sipa.be:8333 last-block-header"
make cli ARGS="--node seed.bitcoin.sipa.be:8333 get-block --hash <block-hash>"
```

Equivalent cargo commands are also valid (`cargo test`, `cargo run --bin cli -- ...`, etc.).

## Editing Guidelines

When adding new protocol support:

1. Map command in message.rs
2. Add typed decoder in decode.rs
3. Extend Message enum
4. Add outbound payload builder if needed
5. Add unit tests in the modified module

Never add parsing logic inside CLI.

## Testing Expectations

- Run `cargo test` after behavior changes.
Tests must verify:
  - Cursor alignment
  - Full payload consumption
  - SegWit detection correctness
  - Transaction boundary correctness

## Notes for Agents

- Favor minimal, precise changes
- Preserve separation of concerns
- Prefer structural correctness over convenience
- If documentation and code diverge, update both together
- Do not simplify abstractions that were intentionally separated
- This repository prioritizes understanding and correctness over rapid feature expansion.