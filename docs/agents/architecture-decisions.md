# Architecture Decisions

Compact decision index for agents. Read this before rediscovering settled structure.

## Monorepo Shape

- `apps/` contains runnable products and binaries
- `crates/` contains shared Rust libraries
- The root `Cargo.toml` is a virtual workspace manifest only

## Shared Rust Boundary

- `crates/btc-network` is the shared Rust library crate
- `crates/btc-network/src/wire/` owns framing and deterministic parsing
- `crates/btc-network/src/session/` owns stateful peer interaction over an established connection
- `crates/btc-network/src/client/` owns app-facing workflows reused by CLI and desktop

## Frontend Architecture

- Frontend is web-first
- Desktop is a thin Tauri shell over the same frontend concepts
- React components must not import Tauri APIs directly
- Frontend code talks to an app-facing client boundary under `apps/web/src/lib/api/`
- The current real desktop-backed flows are handshake, ping, peer address lookup, chain height, block summary, and block download
- The plain web runtime remains placeholder-backed until a browser-safe backend/API exists

## Frontend Composition Rule

- Use shadcn blocks first for page shells, sidebars, headers, settings/profile chrome, and similar product structure
- Adapt blocks down to the repository style rather than rebuilding the same pattern from scratch
- Use lower-level shadcn primitives only when no suitable block exists or the block is materially heavier than needed

## Frontend Visual Direction

- Keep interfaces clean and restrained
- Use a black / carbon base with restrained Bitcoin-gold accents
- Favor a retro instrument-panel / terminal-console feel over generic SaaS styling
- Avoid decorative chrome that does not help protocol exploration

## Maintenance Bias

- Prefer maintainable, pragmatic code over speculative architecture
- Apply YAGNI before adding new layers, options, or generalized helpers
- Apply KISS with direct control flow and explicit types unless a real boundary needs more structure

## Verification Defaults

- `make test` is the project-level verification command
- Frontend-only changes: `npm run test --prefix apps/web` and `npm run build --prefix apps/web`
- Shared Rust changes: `cargo test -p btc-network`
- Desktop Rust bridge changes: `cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml`

## Security Tooling

- Dependency auditing is the current security baseline
- Use `make security`, `make security-rust`, and `make security-web`
- Do not expand dependency-audit work into SAST/DAST unless explicitly requested

## Editor and Workspace Rules

- Keep `apps/desktop/src-tauri` in the workspace for `rust-analyzer`
- The root `Cargo.lock` is authoritative for the Rust workspace
- If editor discovery regresses, update `.vscode/settings.json` rather than adding ad-hoc workarounds
