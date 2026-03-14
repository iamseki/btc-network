# Contributing

This repository is a small workspace around a shared Bitcoin P2P Rust core and two UI surfaces.

Start here if you want to understand where a change belongs and what to run before opening a PR.

## Maintenance Style

- Prefer pragmatic changes over speculative architecture
- Apply YAGNI: do not add new abstractions or options until the codebase clearly needs them
- Apply KISS: favor direct logic, explicit naming, and small focused helpers
- Reach for reuse only when it removes real duplication or protects an existing boundary

## Where Things Live

- `crates/btc-network/` — shared Rust protocol, session, and client workflow library
- `apps/cli/` — interactive Rust CLI
- `apps/crawler/` — crawler binary
- `apps/listener/` — listener binary
- `apps/web/` — primary web frontend
- `apps/desktop/` — Tauri desktop shell

See also:

- `docs/architecture-decisions.md`
- `docs/frontend-architecture.md`

## Pick the Right Layer

Protocol parsing or message decoding:

- change `crates/btc-network/src/wire/`

Stateful peer behavior over a connection:

- change `crates/btc-network/src/session/`

Reusable app-facing workflows used by CLI and desktop:

- change `crates/btc-network/src/client/`

CLI-only orchestration:

- change `apps/cli/`
- prefer calling `crates/btc-network/src/client/` workflows when a shared single-peer flow already exists

Desktop command bridge:

- change `apps/desktop/src-tauri/`

Frontend UI or shell:

- change `apps/web/`

## Frontend Rules

- The frontend is web-first
- React components must not import Tauri APIs directly
- Desktop-only behavior must stay behind the frontend API adapter layer
- The current desktop-backed UI surface is handshake, ping, peer addresses, chain height, block summary, and block download
- The plain web runtime is still placeholder-backed until a browser-safe backend exists
- Start with a relevant shadcn block when building a sidebar, header, shell, or other common page structure
- Drop to lower-level shadcn primitives only when no suitable block exists or the block is heavier than needed

## Common Change Paths

Add a new protocol feature:

1. Extend wire decoding and message mapping
2. Add or update session behavior
3. Expose the workflow through `crates/btc-network/src/client/` if apps need it
4. Wire it into CLI or desktop as needed
5. Add focused tests in the touched modules

Add a new desktop-backed UI feature:

1. Add or extend the shared Rust client workflow
2. Expose it through a Tauri command
3. Update the frontend client adapter
4. Wire it into the relevant page or component
5. Add Rust and frontend tests

Keep the Rust bridge thin:

- put workflow logic in `crates/btc-network/src/client/`
- keep `apps/desktop/src-tauri/src/commands.rs` focused on request/response mapping
- prefer direct tests in the shared crate for workflow behavior, with desktop tests covering bridge mapping and command wiring

Adjust frontend layout or navigation:

1. Start from a shadcn block if a matching pattern exists
2. Adapt it to the repository's cleaner retro style
3. Keep Tauri out of components
4. Add or update render tests when behavior changes

Keep the frontend API surface small:

- only keep adapter methods that are wired to the current product surface
- remove dead placeholder methods when a page is not using them
- do not mirror every CLI command in the frontend boundary unless the UI actually exposes it

## Verification

Run the smallest relevant checks while working, then run the broader project check before finishing.

Useful commands:

- `make test` — full project gate
- `cargo test -p btc-network` — shared Rust crate
- `cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml` — desktop Rust bridge
- `npm run test --prefix apps/web` — frontend tests
- `npm run build --prefix apps/web` — frontend production build
- `make security` — dependency security checks

## Before Opening a PR

- Run the relevant targeted tests for the area you changed
- Run `make test`
- Run `make security` when dependencies or security tooling changed
- Keep documentation updated when architecture or workflow decisions move
- Prefer small, boundary-respecting changes over convenience shortcuts

## What Not To Do

- Do not add protocol parsing logic to the CLI
- Do not bypass the session or wire layers from binaries
- Do not import Tauri APIs directly into React components
- Do not rebuild common frontend shells from scratch when a shadcn block already fits
