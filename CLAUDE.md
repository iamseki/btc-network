# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Research-focused Bitcoin P2P client in Rust. Goal is protocol correctness and architectural clarity, not a wallet, miner, or full node.

## Maintenance Rule

Prefer maintainable code over speculative architecture.

- Apply YAGNI: do not introduce abstractions before there is a real second use or a boundary to protect
- Apply KISS: favor direct control flow, explicit naming, and small focused helpers
- Add complexity only when it clearly reduces duplication, risk, or boundary leakage

Layers (strict separation — each must not cross into the next):

- **wire** (`crates/btc-network/src/wire/`) — framing, deterministic parsing, typed message dispatch. No connection state, no business logic.
- **session** (`crates/btc-network/src/session/`) — stateful peer interaction, handshake, ping/pong. No parsing, no CLI decisions.
- **client** (`crates/btc-network/src/client/`) — app-facing workflows reused by CLI and desktop. No direct TCP or wire decoding.
- **apps** (`apps/`) — orchestration only. No ad-hoc parsing, no protocol re-encoding.

## Task Entrypoints

| Task | Start here |
|------|-----------|
| Frontend shell/page | `docs/frontend-architecture.md`, `apps/web/src/App.tsx`, target component |
| Frontend API/runtime | `apps/web/src/lib/api/client.ts`, `types.ts`, relevant adapter |
| Desktop bridge | `apps/desktop/src-tauri/src/commands.rs`, `crates/btc-network/src/client/peer.rs` |
| Shared Rust protocol | `crates/btc-network/src/lib.rs`, target module + its tests |
| CI/security | `Makefile`, `.github/workflows/ci.yml`, `deny.toml`, `audit.toml` |

Do not read crawler, wire, or CLI files for frontend-only tasks, and do not read `apps/web/` for wire parser work.

## Suspicious Package Rule

For dependency, install-script, or automation changes:

- Check for malicious or suspicious package/script behavior first
- Treat postinstall hooks, curl-or-bash patterns, obfuscated scripts, credential exfiltration, unrelated binary downloads, and broad filesystem writes as suspicious by default
- Treat RustSec `informational = "malicious"` advisories as a stop condition
- If anything looks malicious or materially suspicious, ask the user before proceeding
- Do not silently allowlist suspicious packages or scripts

## Verification

```bash
make test                                                                        # full project
cargo test -p btc-network                                                        # shared Rust only
cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml                   # desktop bridge
npm run test --prefix apps/web && npm run build --prefix apps/web               # frontend only
make security                                                                    # dependency audit
```

Run the smallest relevant scope for the task at hand.

## Editing Guidelines

**New protocol message:**
1. `wire/message.rs` — add `Command` mapping and `Message` variant
2. `wire/decode.rs` — add `impl Decode for YourType`
3. `TryFrom<RawMessage>` dispatch
4. `wire/payload.rs` — outbound builder if needed
5. Unit tests in the modified module

Never add parsing logic inside CLI or session.

**New transaction/script modeling:**
- Wire bytes (`script_sig`, `script_pubkey`, witness) are source of truth
- Add classification helpers as typed methods in `wire/message.rs`
- Keep heuristics explicit; document limitations in rustdoc near the helper

**New desktop-backed UI feature:**
1. Shared Rust workflow in `crates/btc-network/src/client/`
2. Tauri command in `apps/desktop/src-tauri/src/commands.rs`
3. Frontend adapter (`tauri-client.ts` / `web-client.ts`)
4. Page/component wiring
5. Rust and frontend tests

## Protocol Rules

**Handshake order** (must not reorder):
1. Send `version`
2. Recv peer `version`
3. Send `sendaddrv2` (before verack — required for BIP 155)
4. Send `verack`
5. Recv peer `verack`

**Block retrieval:** use `MSG_WITNESS_BLOCK` inventory type; `download-block` writes raw blk record format (4B magic + 4B size + raw bytes).

**Hash endianness:** wire = little-endian, display = big-endian. Reversal must be explicit and localized — never silently reverse inside core types.

**Ping/pong:** always respond to `Ping` with matching `Pong` payload. Do not ignore keepalive.

## Current Implementation State

What is real and wired end-to-end (Rust client → Tauri command → frontend):

| Flow | Rust (`client/peer.rs`) | Tauri command | Frontend |
|------|------------------------|---------------|----------|
| `handshake` | `handshake_node` / `handshake_session` | ✓ | ✓ real |
| `ping` | `ping_node` / `ping_session` | ✓ | ✓ real |
| `getAddr` | `get_peer_addresses_node` / `get_peer_addresses_session` | ✓ | ✓ real |
| `lastBlockHeight` | `get_last_block_height_node` / `get_last_block_height_session` | ✓ | ✓ real |
| `getBlock` | `get_block_summary_node` / `get_block_summary_session` | ✓ | ✓ real |
| `downloadBlock` | `download_block_node` / `download_block_session` | ✓ | ✓ real |
| `getHeaders` | not product-wired | ✗ | not exposed |

The plain web runtime still uses `web-client.ts` placeholders for browser-safe development. Do not wire Tauri commands directly to CLI code.

## Frontend Rules

- Components must not import Tauri APIs directly — isolate behind `tauri-client.ts`
- UI depends on `apps/web/src/lib/api/` interface, not on CLI paths or native sockets
- `web-client.ts` is the browser-safe adapter (currently mock/placeholder for unimplemented flows)
- Web portability is a design goal; avoid coupling pages to desktop-only capabilities

**Visual direction:** black/carbon base, restrained Bitcoin-gold accents, retro instrument-panel feel. Use shadcn blocks first for shells, sidebars, headers; adapt to repo style before dropping to lower-level primitives.

## Design Constraints

- No hidden retries, no silent error swallowing
- Explicit timeouts, deterministic decoding
- Favor typed domain objects over raw byte vectors
- Avoid unnecessary dependencies
- If documentation and code diverge, update both together

## Token Efficiency Policy

- Be concise and direct.
- Provide only the final solution unless asked for reasoning.
- Prefer compact, idiomatic code.
- If assumptions are needed, state them in one line.
- Put the outcome first and avoid padded explanations.
- Do not restate repo context unless it is necessary for the answer.
