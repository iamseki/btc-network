# Frontend Architecture

This repository adopts a web-first frontend architecture with a thin Tauri desktop adapter.

## Goals

- Keep the core Bitcoin protocol implementation in Rust
- Reuse the same page structure across desktop and future web deployment
- Prevent the frontend from depending directly on Tauri runtime APIs
- Mirror the current CLI workflows before introducing new product surface

## Visual Direction

The frontend visual language is intentionally retro while staying clean and readable.

Guidelines:

- Keep the black / carbon base with restrained Bitcoin-gold highlights
- Prefer a retro instrument-panel or terminal-console feel over a generic SaaS dashboard
- Use mono-forward typography, compact labels, and strong information hierarchy
- Favor squarer frames, panel borders, subtle glow, and scanline/grid texture only when they support the mood
- Avoid novelty effects that reduce readability or feel theatrical
- Preserve the same visual discipline on desktop and web builds

## High-Level Shape

```text
src/                    Rust protocol/session core
src/bin/                CLI, crawler, listener orchestration

apps/web/               Primary React frontend
  src/app/              App shell and page registry
  src/pages/            Route-level pages
  src/features/         Page-level UI and local state
  src/lib/api/          App-facing client boundary

apps/desktop/           Tauri shell
  src-tauri/            Native commands and desktop bridge
```

## Boundary Rule

The UI must depend on a frontend-facing client interface, not on Tauri imports and not on CLI binaries.

```text
React page -> feature component -> api client interface -> adapter implementation
```

Examples:

- Desktop: `tauri-client.ts` calls native commands exposed by Tauri
- Web: `web-client.ts` can call a future HTTP API or provide local mocks during early UI work

Current real desktop-backed commands:

- `handshake`
- `ping`

These commands are implemented in the desktop shell and mapped from the shared Rust application layer in `src/app/peer.rs`.

## Initial Pages

These pages map directly to the current CLI commands in `src/bin/cli.rs`.

### Connection

- Node input (`host:port`)
- Handshake action
- Peer version response summary
- Session event log

### Peer Tools

- `ping`
- `get-addr`
- Address list display

### Headers

- `get-headers`
- `last-block-header`
- Progress and summary metrics

### Block Explorer

- `get-block --hash`
- `download-block --hash`
- Header summary
- Transaction count
- Output file path for block record writes

## Implementation Sequence

1. Build page skeletons and frontend contracts in `apps/web`
2. Extract shared Rust application workflows from `src/bin/cli.rs`
3. Expose those workflows through Tauri commands in `apps/desktop`
4. Keep a separate web adapter for future browser deployment

Current implementation status:

- shared Rust handshake flow extracted
- shared Rust ping flow extracted
- Tauri desktop commands wired for handshake and ping
- frontend runtime selection between `web-client` and `tauri-client` in place

## Rust Extraction Direction

The CLI currently contains user flows that should be moved into reusable library modules before Tauri integration grows:

- handshake/connect flow
- ping flow
- address retrieval flow
- headers fetch/sync flow
- block fetch flow
- block download flow

The CLI and the desktop shell should both call the same Rust application layer once extracted.
