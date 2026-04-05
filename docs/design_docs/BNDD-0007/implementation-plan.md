# BNDD-0007 Implementation Plan

Execution plan for [BNDD-0007](./BNDD-0007.md).

## Summary

Replace the default ClickHouse-backed crawler persistence path with a PostgreSQL-backed path while preserving the ClickHouse implementation as documented legacy infrastructure.

## Progress Tracker

Status values:

- `pending`
- `in_progress`
- `reviewing`
- `merged`
- `blocked`

| Phase | Status | Last Updated | Branch or PR | Notes |
| --- | --- | --- | --- | --- |
| Phase 1: Decision docs and index updates | `merged` | `2026-04-04` | `main` | `BNDD-0007 is added and BNDD-0002 plus BNDD-0005 are marked historical rather than default.` |
| Phase 2: PostgreSQL adapter crate and migrations | `merged` | `2026-04-04` | `main` | `PostgreSQL migrations, repository implementation, and live integration tests are in the workspace.` |
| Phase 3: App wiring and local tooling switch | `merged` | `2026-04-04` | `main` | `The crawler app, API app, Docker Compose, Make targets, and migration tooling now default to PostgreSQL.` |
| Phase 4: Legacy ClickHouse preservation pass | `merged` | `2026-04-04` | `main` | `ClickHouse code remains buildable and the docs label it as legacy rather than default.` |

## Immediate Next Slice

- keep future crawler and analytics work on the PostgreSQL path unless a new BNDD explicitly changes the backend default again
- keep BNDD-0007 and related runbooks aligned with the actual adapter stack, including the current `sqlx` pool and local PostgreSQL 18 container layout

## Explicit Agent Constraints

- keep shared crawler traits and domain types in `crates/btc-network`
- keep SQL, migrations, and driver code out of the shared crate
- keep ClickHouse preserved, but do not route new default work through it
- do not add backend-selection flags or generic dual-backend abstractions in this slice
- do not add TimescaleDB or other PostgreSQL extensions in this slice

## Verification

- `cargo test -p btc-network`
- `cargo test -p btc-network-postgres`
- `cargo test -p btc-network-api`
- `cargo test -p btc-network-crawler`
- `cargo test -p btc-network-clickhouse`
- `make test`
- `make security`
