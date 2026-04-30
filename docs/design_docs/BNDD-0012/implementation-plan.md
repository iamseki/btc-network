# BNDD-0012 Implementation Plan

Execution plan for [BNDD-0012](./BNDD-0012.md).

## Summary

Add dedicated unreachable-node state, exclude active unreachable endpoints from the normal crawler path, and provide a recovery subcommand that retries only unreachable endpoints.

## Progress Tracker

Status values:

- `pending`
- `in_progress`
- `reviewing`
- `merged`
- `blocked`

| Phase | Status | Last Updated | Branch or PR | Notes |
| --- | --- | --- | --- | --- |
| Phase 1: BNDD and schema | `reviewing` | `2026-04-26` | `current branch` | `Added BNDD-0012 plus unreachable_nodes migration.` |
| Phase 2: Normal crawler exclusion | `reviewing` | `2026-04-26` | `current branch` | `Normal crawler loads unreachable nodes into HashSet<String> and skips seeds/discoveries before enqueue.` |
| Phase 3: Terminal failure capture | `reviewing` | `2026-04-26` | `current branch` | `Retryable reachable endpoint failures requeue; terminal reachable endpoint failures record unreachable state after attempt budget exhaustion.` |
| Phase 4: Recovery path | `reviewing` | `2026-04-26` | `current branch` | `Added recover-unreachable crawler subcommand that processes only unreachable nodes and soft-deletes recovered rows.` |
| Phase 5: Docs and verification | `reviewing` | `2026-04-26` | `current branch` | `Crawler docs updated; smallest Rust test scopes run.` |

## Explicit Agent Constraints

- keep protocol parsing out of crawler binaries
- keep PostgreSQL-specific unreachable queries behind `CrawlerRepository`
- use in-memory membership for normal skip decisions
- do not add `last_tried` or other recovery scheduling state in this slice
- keep recovery isolated from normal discovered-peer fanout

## Phases

### Phase 1: BNDD And Schema

Targets:

- `docs/design_docs/BNDD-0012/BNDD-0012.md`
- `docs/design_docs/BNDD-0012/implementation-plan.md`
- `crates/btc-network-postgres/migrations/`
- `crates/btc-network-postgres/src/migrations/bundled.rs`

Done criteria:

- BNDD documents chosen design and tradeoff
- `unreachable_nodes` table exists
- migration creates the active unreachable-node state table

### Phase 2: Normal Crawler Exclusion

Targets:

- `crates/btc-network/src/crawler/mod.rs`
- `crates/btc-network/src/crawler/types.rs`
- `crates/btc-network/src/crawler/worker.rs`
- `crates/btc-network-postgres/src/repository/`

Done criteria:

- normal crawler loads unreachable nodes at startup
- skip lookup uses `HashSet<String>`
- seed and discovered-node enqueue paths skip active unreachable endpoints

### Phase 3: Terminal Failure Capture

Targets:

- `crates/btc-network/src/crawler/worker.rs`
- `crates/btc-network/src/crawler/mod.rs`
- `crates/btc-network-postgres/src/repository/unreachable.rs`

Done criteria:

- retryable reachable endpoint failures are requeued without terminal unreachable writes
- exhausted reachable endpoint failures create unreachable updates
- attempt budget default is `5`

### Phase 4: Recovery Path

Targets:

- `crates/btc-network/src/crawler/mod.rs`
- `apps/crawler/src/main.rs`
- `apps/crawler/Dockerfile`
- `Makefile`

Done criteria:

- recovery subcommand loads only unreachable endpoints
- recovery does not follow discovered peers
- successful recovery soft-deletes unreachable state and writes successful observation

### Phase 5: Docs And Verification

Targets:

- `docs/design_docs/README.md`
- `apps/crawler/README.md`
- `docs/agents/architecture-decisions.md`
- `crates/btc-network-postgres/tests/postgres_repository.rs`

Done criteria:

- design index references BNDD-0012
- operator docs mention normal skip and recovery command
- focused tests cover skip behavior and PostgreSQL unreachable-state updates

## Verification

- `cargo test -p btc-network`
- `cargo test -p btc-network-crawler`
- `cargo test -p btc-network-postgres`
