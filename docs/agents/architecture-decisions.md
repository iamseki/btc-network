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

## Async Networking Direction

- The crawler runtime uses the async session path for cancellation-aware socket I/O and shutdown
- The shared peer client workflows under `crates/btc-network/src/client/peer.rs` are still synchronous today
- Do not add protocol or session logic to desktop or web adapters just to get async behavior
- If async networking is extended beyond the crawler, prefer migrating the shared client boundary in `crates/btc-network/src/client/peer.rs` first, then keep app adapters thin
- Prioritize longer-running shared workflows such as chain height, peer address lookup, and block download before rewriting short single-peer commands

## Crawler Terms

- `frontier_size` means the pending frontier: discovered endpoints that are tracked but not yet attempted by a worker
- `unique_nodes` counts tracked endpoints, not persisted observations; it can be much larger than completed node visits
- `scheduled_tasks` is the count of attempted node visits dequeued by workers
- `crawl_run_id` and `observation_id` are stored as native UUID values and generated as UUIDv7 in the current crawler implementation
- persisted observations derive success/failure outcome from whether `failure_classification` is null; there is no separate `confidence_level` column in the current schema
- persisted observations do not carry a separate `batch_id` column in the current schema
- failed persisted observations can reflect connect, handshake, or peer-discovery failure, so use `failure_classification` for the exact stage
- crawler no longer performs durable startup recovery; after crash or manual restart, operators start a fresh run from seed nodes
- overlapping crawler writers against the same persistence database are still a deployment bug, but checkpoints are now operator history only rather than restart state
- the default crawler persistence adapter is PostgreSQL in `crates/btc-network-postgres`

## Frontend Architecture

- Frontend is web-first
- Desktop is a thin Tauri shell over the same frontend concepts
- React components must not import Tauri APIs directly
- Frontend code talks to an app-facing client boundary under `apps/web/src/lib/api/`
- The current real desktop-backed flows are handshake, ping, peer address lookup, chain height, block summary, and block download
- Crawler analytics reads now go through the browser-safe HTTP app in `apps/api`
- The default analytics storage adapter behind `apps/api` is PostgreSQL
- Both web and desktop analytics reads use the same HTTP helper and `VITE_API_BASE_URL`
- Hosted browser builds may opt into `VITE_DEMO_MODE` to serve deterministic mock analytics data instead of calling the HTTP API
- Hosted demo mode may replay a client-only latest-snapshot cycle from the most recent run, persist replay state in local storage, and restart a fresh live cycle when the user returns after a longer absence
- Do not add crawler analytics Tauri commands in the current slice
- The plain web runtime remains placeholder-backed only for the single-peer flows that still lack a browser-safe backend
- The public product home now lives on `Network Analytics` overview; header snapshot preview should route there, not to a duplicate crawler-only surface
- `Network Risk API` is a web-only mocked commercial preview page for now; do not treat it as a live SLA-backed surface yet
- The public product home should stay globe-first, keep `Risk Brief` as the secondary companion panel, and use a full-width `Risk Drivers` strip instead of crawler-internal checkpoint rails

## Frontend Composition Rule

- Use shadcn blocks first for page shells, sidebars, headers, settings/profile chrome, and similar product structure
- Adapt blocks down to the repository style rather than rebuilding the same pattern from scratch
- Use lower-level shadcn primitives only when no suitable block exists or the block is materially heavier than needed
- Keep analytics summaries compact and aligned with page actions when the main section already shows the important state
- Avoid duplicating the same run context in both a summary box and a primary section on the same screen
- Keep score-like product signals derived from the current API contract explicit and easy to trace back to source fields
- Keep the mobile ordering deliberate: globe first, `Risk Brief` second, evidence strips after the hero row
- Prefer lightweight custom charts before adding chart or map dependencies; add heavier tooling only when the product or API shape requires it

## Frontend Visual Direction

- Keep interfaces clean and restrained
- Use a black / carbon base with restrained Bitcoin-gold accents
- Favor a retro instrument-panel / terminal-console feel over generic SaaS styling
- Avoid decorative chrome that does not help protocol exploration
- Prefer `snapshot` as the user-facing term for public crawler replay state

## Maintenance Bias

- Prefer maintainable, pragmatic code over speculative architecture
- Make major tradeoffs explicit when a design balances simplicity, correctness, operability, and speed
- Apply YAGNI before adding new layers, options, or generalized helpers
- Apply KISS with direct control flow and explicit types unless a real boundary needs more structure

## Performance And Scale Bias

- Treat performance and scalability as design concerns, not only as post-hoc tuning work
- Identify the dominant cost driver before proposing an optimization or storage change
- Prefer measured evidence, targeted tests, benchmarks, or concrete workload reasoning over instinct
- Avoid speculative optimization, but call out obvious scale risks in hot paths, persistence shape, and high-cardinality data flows
- When choosing the simpler design over the faster design, or the reverse, make the tradeoff explicit in code review notes, docs, or BNDD text as appropriate

## Verification Defaults

- `make test` is the project-level verification command
- Frontend-only changes: `npm run test --prefix apps/web` and `npm run build --prefix apps/web`
- Shared Rust changes: `cargo test -p btc-network`
- PostgreSQL adapter changes: `cargo test -p btc-network-postgres`
- Desktop Rust bridge changes: `cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml`

## Security Tooling

- Dependency auditing is the current security baseline
- Use `make security`, `make security-rust`, and `make security-web`
- Do not expand dependency-audit work into SAST/DAST unless explicitly requested

## Editor and Workspace Rules

- Keep `apps/desktop/src-tauri` in the workspace for `rust-analyzer`
- The root `Cargo.lock` is authoritative for the Rust workspace
- If editor discovery regresses, update `.vscode/settings.json` rather than adding ad-hoc workarounds
