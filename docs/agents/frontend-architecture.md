# Frontend Architecture

This repository adopts a web-first frontend architecture with a thin Tauri desktop adapter.

## Goals

- Keep the core Bitcoin protocol implementation in Rust
- Reuse the same page structure across desktop and future web deployment
- Prevent the frontend from depending directly on Tauri runtime APIs
- Keep the single-peer workflows aligned with the existing shared Rust client flows while allowing browser-safe analytics pages to grow through the HTTP API

## Visual Direction

The frontend visual language is intentionally retro while staying clean and readable.

Guidelines:

- Keep the black / carbon base with restrained Bitcoin-gold highlights
- Prefer a retro instrument-panel or terminal-console feel over a generic SaaS dashboard
- Use mono-forward typography, compact labels, and strong information hierarchy
- Favor squarer frames, panel borders, subtle glow, and scanline/grid texture only when they support the mood
- Avoid novelty effects that reduce readability or feel theatrical
- Preserve the same visual discipline on desktop and web builds

## shadcn Workflow

Frontend composition should start from shadcn blocks when a matching pattern exists.

Default order:

1. Look for a relevant shadcn block first
2. Adapt that block to the repository's visual direction and feature needs
3. Drop to lower-level shadcn primitives only when no suitable block exists or the block is materially heavier than the interface needs

Practical rule:

- Use blocks first for sidebars, app shells, headers, menus, settings/profile chrome, and other common product frames
- Keep adapted blocks clean by removing extra marketing copy, oversized panels, or dashboard filler
- Do not rebuild a known shadcn block pattern from scratch unless there is a clear functional reason

## High-Level Shape

```text
crates/btc-network/     Rust protocol/session core
apps/cli/               CLI orchestration
apps/crawler/           Crawler orchestration
apps/listener/          Listener orchestration

apps/web/               Primary React frontend
  src/app/              App shell and page registry
  src/components/ui/    Shared UI primitives and sidebar shell pieces
  src/pages/            Page-level screens
  src/lib/api/          App-facing client boundary

apps/desktop/           Tauri shell
  src-tauri/            Native commands and desktop bridge
```

## Boundary Rule

The UI must depend on a frontend-facing client interface, not on Tauri imports and not on CLI binaries.

```text
React page -> shared UI/components -> api client interface -> adapter implementation
```

Examples:

- Desktop: `tauri-client.ts` calls native commands exposed by Tauri
- Web: `web-client.ts` uses the HTTP analytics helper for crawler analytics and placeholder/mock responses for the remaining single-peer flows that still lack a browser-safe backend

Current real desktop-backed commands:

- `handshake`
- `ping`
- `get_peer_addresses`
- `get_last_block_height`
- `get_block_summary`
- `download_block`

These commands are implemented in the desktop shell and mapped from the shared Rust client workflow layer in `crates/btc-network/src/client/peer.rs`.

## Initial Pages

These pages map directly to the current CLI commands in `apps/cli/src/main.rs`.

### Connection

- Node input (`host:port`)
- Handshake action
- Peer version response summary
- Session event log

### Peer Tools

- `ping`
- `get-addr`
- Address list display

### Chain Height

- `last-block-header`
- Height summary
- Best-block hash and sync timing

### Block Explorer

- `get-block --hash`
- `download-block --hash`
- Header summary
- Transaction count
- Output file path for block record writes

## Current Implementation State

Already in place:

- shared Rust handshake flow extracted into `crates/btc-network/src/client/peer.rs`
- shared Rust ping flow extracted into `crates/btc-network/src/client/peer.rs`
- shared Rust peer address flow extracted into `crates/btc-network/src/client/peer.rs`
- shared Rust last-block-height flow extracted into `crates/btc-network/src/client/peer.rs`
- shared Rust block summary and download flows extracted into `crates/btc-network/src/client/peer.rs`
- Tauri desktop commands wired for handshake, ping, peer addresses, chain height, block summary, and block download
- runtime selection between `web-client` and `tauri-client`
- shared HTTP analytics helper used by both runtime adapters for crawler run and ASN reads
- browser-safe Rust API app under `apps/api/` for public crawler analytics reads
- analytics-first pages for `Crawler Runs` and `Network Analytics`
- render tests for the app shell, sidebar behavior, and current page actions

Still intentionally incomplete:

- browser-safe backend/API for the remaining single-peer web execution
- one-shot `getheaders` UI if that workflow becomes a product need beyond chain height

## Rust Extraction Direction

The shared Rust client workflow layer already covers the current desktop-backed single-peer flows.

As integration grows, keep using the same pattern:

- session behavior in `crates/btc-network/src/session/`
- app-facing workflow extraction in `crates/btc-network/src/client/`
- Tauri commands as thin bridges only
- browser-safe analytics behavior isolated behind the HTTP helper under `apps/web/src/lib/api/`
