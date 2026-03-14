# AGENTS.md

Guidance for coding agents working in this repository.

Start with `docs/architecture-decisions.md` for the compact version of settled repo decisions.

## Project Summary

Language: Rust (edition 2024)
Core crate: btc-network

## Goal

Develop a research-focused Bitcoin P2P implementation in Rust that exposes the protocol’s internal mechanics — from handshake to block and transaction decoding — emphasizing:

- Clear separation between transport, framing, decoding, and consensus modeling
- Typed representations of wire-level and consensus objects
- Deterministic parsing with explicit error handling
- Protocol correctness over feature completeness
- Architectural rigor suitable for systems exploration

This is not a wallet, miner, or full node clone. It is a protocol engineering project designed to understand how Bitcoin works under the hood.

## Maintenance Rule

Prefer code that is easy to maintain.

- Choose pragmatic changes over speculative architecture
- Apply YAGNI: do not add abstractions, layers, or options before the project clearly needs them
- Apply KISS: prefer straightforward control flow, explicit types, and small focused helpers over clever reuse
- Add indirection only when it removes real duplication or protects an important boundary

## Open These First

Pick the smallest relevant set.

Frontend shell or page task:

- `docs/architecture-decisions.md`
- `docs/frontend-architecture.md`
- `apps/web/src/App.tsx`
- the specific page or component being changed

Frontend API/runtime task:

- `docs/architecture-decisions.md`
- `apps/web/src/lib/api/client.ts`
- `apps/web/src/lib/api/types.ts`
- the relevant adapter (`tauri-client.ts` or `web-client.ts`)

Shared Rust protocol/session task:

- `docs/architecture-decisions.md`
- `crates/btc-network/src/lib.rs`
- the target module under `crates/btc-network/src/`
- the tests next to that module

Desktop bridge task:

- `docs/architecture-decisions.md`
- `apps/desktop/src-tauri/src/commands.rs`
- `crates/btc-network/src/client/peer.rs`
- the relevant frontend adapter file

CI or security task:

- `docs/architecture-decisions.md`
- `Makefile`
- `.github/workflows/ci.yml`
- `audit.toml`
- `deny.toml`

## Suspicious Package Rule

When a task touches dependencies, install scripts, or repo automation:

- Check for malicious, suspicious, or unexpected package/script behavior before normal implementation work
- Treat postinstall hooks, curl-or-bash patterns, obfuscated scripts, credential exfiltration, filesystem-wide writes, and unrelated binary downloads as suspicious by default
- Treat RustSec `informational = "malicious"` advisories as a stop condition, not a warning to hand-wave away
- If anything looks malicious or materially suspicious, stop and ask the user before adding, updating, or executing it
- Do not silently ignore a suspicious package or script by adding it to an allowlist

## Usually Do Not Read

- `apps/crawler/` for frontend tasks
- `apps/web/` for wire parser work
- `crates/btc-network/src/wire/` for pure shell/layout tasks
- CLI files for desktop/web UI changes unless a user flow is being extracted

## Architectural Principles

1. Transport Layer

- `TcpStream`
- No protocol knowledge
- No parsing logic

2. Wire Layer

Located under `crates/btc-network/src/wire/`.

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

Located in `crates/btc-network/src/session/`.

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

Located under `apps/`.

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

- crates/btc-network/src/lib.rs — crate entry
- crates/btc-network/src/session/mod.rs — stateful peer interaction
- crates/btc-network/src/client/mod.rs — client-facing workflow entrypoints
- crates/btc-network/src/client/peer.rs — shared single-peer workflows reused by CLI and desktop
- crates/btc-network/src/wire/codec.rs — framing (read/write envelope)
- crates/btc-network/src/wire/decode.rs — byte-level decode helpers (varint, slices, cursor)
- crates/btc-network/src/wire/message.rs — typed Message enum + dispatch
- crates/btc-network/src/wire/payload.rs — outbound message builders
- crates/btc-network/src/wire/constants.rs — protocol constants (magic, seeds, genesis, versions)
- apps/cli/src/main.rs — interactive CLI
- apps/crawler/src/main.rs — DNS seed crawler
- apps/listener/src/main.rs — long-running listener
- docs/crawler-first-design.png — first crawler architecture draft

## Task Map

- Frontend shell: `apps/web/src/App.tsx`, `apps/web/src/components/ui/`
- Frontend pages: `apps/web/src/pages/`
- Frontend API boundary: `apps/web/src/lib/api/`
- Desktop bridge: `apps/desktop/src-tauri/src/commands.rs`
- Shared client workflows: `crates/btc-network/src/client/`
- Session layer: `crates/btc-network/src/session/`
- Wire layer: `crates/btc-network/src/wire/`
- CLI orchestration: `apps/cli/src/main.rs`

## Frontend Architecture Decision

The frontend strategy for this repository is web-first UI reuse with a thin Tauri desktop adapter.

This means:

- Build the frontend as a normal SPA using React + Vite + TypeScript
- Use shadcn/ui on top of Tailwind for the component layer
- Use shadcn blocks as the first source for page and shell composition before hand-assembling layouts from lower-level primitives
- Treat Tauri as a desktop shell and native bridge, not as the frontend architecture itself
- Keep the Rust crate as the protocol/core implementation
- Reuse the same UI concepts and components across desktop and future web deployment paths

Preferred structure:

- `crates/btc-network/` — core Rust protocol/session/domain code
- `crates/btc-network/src/client/` — client-facing Rust workflows reused by CLI and desktop
- `apps/cli/` — interactive CLI
- `apps/crawler/` — crawler binary
- `apps/listener/` — listener binary
- `apps/web/` — primary React frontend
- `apps/desktop/` — Tauri application reusing the frontend with native bindings
- `crates/` — shared Rust crates

Workspace/editor note:

- The root `Cargo.toml` is a virtual workspace manifest and must keep `apps/desktop/src-tauri`, `crates/btc-network`, and the Rust app crates as workspace members
- The workspace `default-members` must include the shared crate, Rust app crates, and `apps/desktop/src-tauri` so root-level `cargo test` covers the full Rust workspace
- `make test` is the project-level verification command and must continue to run both Rust workspace tests and frontend tests
- If editor discovery regresses, update `.vscode/settings.json` `rust-analyzer.linkedProjects` rather than adding ad-hoc editor instructions elsewhere
- The workspace root `Cargo.lock` is authoritative for both Rust crates; do not keep a second desktop-specific lockfile in sync

### Frontend Design Direction

When extending the UI:

- Start from a relevant shadcn block first when one exists; adapt it to the product instead of rebuilding the same pattern from scratch
- Prefer clean, restrained layouts over dashboard-heavy compositions
- Use a black / carbon base with Bitcoin-gold accents
- Favor a retro instrument-panel / terminal-console feel over polished SaaS styling
- Keep contrast high and hierarchy obvious
- Avoid decorative UI that does not help protocol exploration
- Use retro cues sparingly: mono labels, squarer frames, subtle glow, and panel texture are good; gimmicky effects are not
- Favor a small reusable component set over page-local styling
- Preserve web portability even when adding desktop-specific features

When using shadcn:

- Prefer blocks for app shells, sidebars, headers, auth chrome, and other common page structures
- Use component primitives directly only when there is no suitable block or the block would add unnecessary complexity
- Keep block adaptations restrained; remove excess copy and decorative sections rather than adding custom chrome

### Frontend Boundary Rules

- React components must not import Tauri APIs directly
- Tauri-specific calls must be isolated behind a frontend adapter/client layer
- The UI must depend on an application-facing interface, not on CLI code paths
- Do not invoke the CLI binary from the frontend as an integration mechanism
- Shared Rust application logic should be extracted into reusable library modules that both CLI and Tauri can call
- The current client-facing Rust workflow layer starts in `crates/btc-network/src/client/peer.rs`

### Web Compatibility Requirement

Future web deployment is a design goal.

Because of that:

- Favor a frontend API abstraction such as `client.ts`, `tauri-client.ts`, and `web-client.ts`
- Keep desktop-only behavior localized behind the Tauri adapter
- Avoid coupling page components to native filesystem, sockets, or Tauri runtime details
- Assume browser deployment will require a separate backend/API for operations that cannot run in the browser

### Frontend Scope Priority

Initial frontend pages should mirror the current CLI capabilities before adding new product surface:

- Connection / handshake
- Peer tools (`ping`, `get-addr`)
- Chain height (`last-block-header`)
- Block explorer (`get-block`, `download-block`)
- Crawler UI later, after the single-peer workflows are stable

Current real desktop-backed flows:

- Handshake
- Ping
- Get peer addresses
- Get last block height
- Get block summary
- Download block

### Frontend Working Set

For most frontend tasks, start with this minimal context:

- `docs/frontend-architecture.md`
- `apps/web/src/App.tsx`
- `apps/web/src/lib/api/client.ts`
- `apps/web/src/lib/api/types.ts`
- `apps/web/src/pages/connection-page.tsx`
- `apps/web/src/pages/peer-tools-page.tsx`
- `apps/web/src/pages/headers-page.tsx`
- `apps/web/src/pages/blocks-page.tsx`
- `apps/web/src/lib/api/tauri-client.ts`
- the specific page or component being changed

Do not read unrelated crawler, wire, or CLI files unless the task requires protocol or backend integration changes.

### Preferred Change Patterns

For new protocol support:

- wire decode/message support
- session behavior
- client-facing workflow
- CLI or desktop exposure
- focused tests in changed modules

For new desktop-backed UI features:

- shared Rust client workflow
- Tauri command
- frontend API adapter
- page/component wiring
- Rust and frontend tests

For frontend visual work:

- start from a relevant shadcn block
- adapt it down to the repo style
- use lower-level primitives only if the block is not a good fit
- add or update render tests when behavior changes

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

### Block Retrieval / Serialization

- `getdata` block requests must use witness-aware inventory (`MSG_WITNESS_BLOCK`)
- `download-block` writes raw block payload in Bitcoin `blk*.dat` record format:
  - 4 bytes network magic (little-endian)
  - 4 bytes raw block size (little-endian)
  - raw serialized block bytes
- When a different block hash is returned, ignore it explicitly and continue waiting

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
make cli ARGS="--node seed.bitcoin.sipa.be:8333 download-block --hash <block-hash>"
make security-tools-install
make security-rust
make security-web
make security
make desktop-install
make desktop-dev
make desktop-test
```

Equivalent cargo commands are also valid (`cargo test`, `cargo run -p btc-network-cli -- ...`, etc.).

Security config files:

- `deny.toml` — cargo-deny policy for advisories, bans, and sources
- `audit.toml` — cargo-audit configuration

Desktop/native prerequisites:

- The Tauri desktop shell depends on Linux system packages when built on Ubuntu/Debian
- The current package set is documented in `README.md` and `apps/desktop/README.md`

## Editing Guidelines

When adding new protocol support:

1. Map command in message.rs
2. Add typed decoder in decode.rs
3. Extend Message enum
4. Add outbound payload builder if needed
5. Add unit tests in the modified module

Never add parsing logic inside CLI.

When extending transaction/script modeling:

1. Keep wire bytes as source of truth (`script_sig`, `script_pubkey`, witness)
2. Add classification helpers as typed methods in `wire/message.rs`
3. Keep heuristics explicit (no hidden script execution assumptions)
4. Document limitations in rustdoc near the helper
5. Add focused tests for both standard and non-standard patterns

## Testing Expectations

- Run `cargo test` after behavior changes.
Tests must verify:
  - Cursor alignment
  - Full payload consumption
  - SegWit detection correctness
  - Transaction boundary correctness
  - Script classification correctness (`ScriptType`, `ScriptSigType`)
  - Exposed pubkey detection behavior

When changing dependency/security tooling:

- Run the relevant local security target when the required tools are available
- Prefer verifying both Rust and frontend dependency checks before updating CI
- Keep security tooling focused on supply-chain/dependency risk, not as a substitute for protocol tests

When changing desktop-backed flows:

- Add or update shared Rust tests in `crates/btc-network/src/client/`
- Add or update desktop command tests in `apps/desktop/src-tauri/src/commands.rs`
- Keep the web runtime path working through `web-client`
- Keep the desktop runtime path isolated in `tauri-client`

## Verification Matrix

- Full project: `make test`
- Frontend only: `npm run test --prefix apps/web` and `npm run build --prefix apps/web`
- Shared Rust only: `cargo test -p btc-network`
- Desktop Rust only: `cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml`
- Security/dependency checks: `make security`

When changing shared peer operations:

- Put connection setup and app-facing summaries in `crates/btc-network/src/client/`
- Put stateful peer protocol sequencing in `crates/btc-network/src/session/`
- Do not move TCP resolution/connection logic into `session/`
- Do not map protocol objects into UI/CLI DTOs inside `session/`

## Notes for Agents

- Favor minimal, precise changes
- Preserve separation of concerns
- Prefer structural correctness over convenience
- If documentation and code diverge, update both together
- Do not simplify abstractions that were intentionally separated
- This repository prioritizes understanding and correctness over rapid feature expansion.
- Keep context small: load only the files needed for the current task
- For frontend tasks, prefer updating shared primitives and page contracts over duplicating page-local patterns
- For documentation updates, reflect decisions succinctly so future turns do not spend tokens rediscovering established architecture
- For security tooling tasks, avoid expanding scope into SAST/DAST unless explicitly requested; dependency auditing is the current baseline
