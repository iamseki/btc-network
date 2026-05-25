# BNDD-0006 Implementation Plan

Execution plan for [BNDD-0006](./BNDD-0006.md).

## Summary

Implement public crawler analytics in a way that keeps the React shell thin, keeps desktop parity with web, and pushes storage-adapter query logic behind shared Rust traits and the HTTP API adapter. The current default adapter is PostgreSQL.

## Progress Tracker

Status values:

- `pending`
- `in_progress`
- `reviewing`
- `merged`
- `blocked`

| Phase | Status | Last Updated | Branch or PR | Notes |
| --- | --- | --- | --- | --- |
| Phase 1: Shared analytics contract and API app | `merged` | `2026-04-02` | `#16` | `Shared crawler analytics read models, the storage-backed reader, the Axum API app, and the initial public-read hardening layer are merged.` |
| Phase 2: Web and desktop analytics UI wiring | `merged` | `2026-04-02` | `#16` | `The analytics-first web/desktop shell, shared HTTP analytics helper, hosted browser demo-mode fallback, latest-snapshot preview, Network Analytics home, compact summaries, lightweight charts, and responsive crawler-runs inspection surface are merged.` |

## Current State

- BNDD-0006 is implemented. Follow-up analytics work should keep the read-only API boundary and analytics-first shell direction unless a newer BNDD supersedes them.

## Explicit Agent Constraints

- keep crawler analytics queries in shared Rust and the API adapter, not in React
- keep desktop analytics reads on the shared HTTP path; do not add analytics-only Tauri commands in this slice
- keep existing single-peer Tauri commands intact
- keep storage-adapter details out of API responses
- prefer globe-first, score-first overview surfaces, focused tables, compact header summaries, product-facing risk-driver strips, and lightweight inline charts over heavier dashboard dependencies

## Verification

- `cargo test -p btc-network`
- `cargo test -p btc-network-postgres`
- `cargo test -p btc-network-api`
- `npm run test --prefix apps/web`
- `npm run build --prefix apps/web`
- `cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml`
