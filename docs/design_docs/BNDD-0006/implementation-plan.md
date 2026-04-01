# BNDD-0006 Implementation Plan

Execution plan for [BNDD-0006](./BNDD-0006.md).

## Summary

Implement public crawler analytics in a way that keeps the React shell thin, keeps desktop parity with web, and pushes ClickHouse-specific query logic behind shared Rust traits and the new HTTP API adapter.

## Progress Tracker

Status values:

- `pending`
- `in_progress`
- `reviewing`
- `merged`
- `blocked`

| Phase | Status | Last Updated | Branch or PR | Notes |
| --- | --- | --- | --- | --- |
| Phase 1: Shared analytics contract and API app | `reviewing` | `2026-04-01` | `PR #16` | `Shared crawler analytics read models, the ClickHouse-backed reader, the new Axum API app, and the initial public-read hardening layer remain on [PR #16](https://github.com/iamseki/btc-network/pull/16).` |
| Phase 2: Web and desktop analytics UI wiring | `reviewing` | `2026-04-01` | `PR #16` | `The web shell includes analytics-first pages, page-level secondary navigation, the shared HTTP analytics helper, and a hosted browser demo-mode fallback for analytics on [PR #16](https://github.com/iamseki/btc-network/pull/16).` |

## Immediate Next Slice

- review and merge [PR #16](https://github.com/iamseki/btc-network/pull/16)
- keep the BNDD and deploy docs aligned with the optional browser demo-mode path while the public API remains undeployed
- keep follow-up work out of this slice unless it preserves the read-only API and the current analytics-first shell direction

## Explicit Agent Constraints

- keep crawler analytics queries in shared Rust and the API adapter, not in React
- keep desktop analytics reads on the shared HTTP path; do not add analytics-only Tauri commands in this slice
- keep existing single-peer Tauri commands intact
- keep ClickHouse details out of API responses
- prefer flat tables, cards, and badges over heavier dashboard dependencies

## Verification

- `cargo test -p btc-network`
- `cargo test -p btc-network-clickhouse`
- `cargo test -p btc-network-api`
- `npm run test --prefix apps/web`
- `npm run build --prefix apps/web`
- `cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml`
