# BNDD-0006 Implementation Plan

Execution plan for [BNDD-0006](./BNDD-0006.md).

## Summary

Implement public crawler analytics in a way that keeps the React shell thin, keeps desktop parity with web, and pushes storage-adapter query logic behind shared Rust traits and the HTTP API adapter. The current default adapter is PostgreSQL and the preserved ClickHouse path is legacy only.

## Progress Tracker

Status values:

- `pending`
- `in_progress`
- `reviewing`
- `merged`
- `blocked`

| Phase | Status | Last Updated | Branch or PR | Notes |
| --- | --- | --- | --- | --- |
| Phase 1: Shared analytics contract and API app | `reviewing` | `2026-04-01` | `PR #16` | `Shared crawler analytics read models, the storage-backed reader, the new Axum API app, and the initial public-read hardening layer remain on [PR #16](https://github.com/iamseki/btc-network/pull/16).` |
| Phase 2: Web and desktop analytics UI wiring | `reviewing` | `2026-04-01` | `PR #16` | `The web shell includes analytics-first pages, page-level secondary navigation, the shared HTTP analytics helper, the hosted browser demo-mode fallback, the global latest-snapshot preview, the globe-first `Network Analytics` home page with compact `Risk Brief` and full-width `Risk Drivers`, compact header-row analytics summaries, lightweight inline charts, and the responsive crawler-runs inspection surface on [PR #16](https://github.com/iamseki/btc-network/pull/16).` |

## Immediate Next Slice

- review and merge [PR #16](https://github.com/iamseki/btc-network/pull/16)
- keep the BNDD and compact agent docs aligned with the optional browser demo-mode path, including the client-only latest-snapshot replay behavior, globe-first home-page guidance, `Risk Brief` and `Risk Drivers` layout rules, compact header-row summaries, and lightweight chart guidance while the public API remains undeployed
- keep follow-up work out of this slice unless it preserves the read-only API and the current analytics-first shell direction

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
