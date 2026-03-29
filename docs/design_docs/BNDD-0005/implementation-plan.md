# BNDD-0005 Implementation Plan

Execution plan for [BNDD-0005](./BNDD-0005.md).

## Summary

Implement durable crawler persistence in small slices that keep the functional core in `crates/btc-network` and push ClickHouse, MMDB lookups, and runtime orchestration details into adapters.

The intended happy path is:

1. collect a raw protocol-derived crawl result
2. normalize it into a `RawNodeObservation`
3. enrich eligible IPv4/IPv6 endpoints through `IpEnrichmentProvider`
4. assemble a `PersistedNodeObservation`
5. batch-write observations and checkpoints through `CrawlerRepository`

## How To Use This Plan

- Read [BNDD-0005.md](./BNDD-0005.md) first for the design truth
- Use this file to choose the next implementation slice
- Prefer one phase per PR unless the phase is too small to stand alone
- Do not skip to ClickHouse or UI work before the shared domain model is stable

## Progress Tracker

Use this table to keep rollout state in the repository so a new agent can recover context quickly.

Status values:
- `pending`
- `in_progress`
- `reviewing`
- `merged`
- `blocked`

Update rules:
- update `last_updated` whenever the phase state changes materially
- use `branch_or_pr` for the active branch name, PR number, or merge commit when helpful
- move a phase to `reviewing` when implementation is on an open PR
- move a phase to `merged` only when the work is on `main`

| Phase | Status | Last Updated | Branch or PR | Notes |
| --- | --- | --- | --- | --- |
| Phase 1: Shared Domain Model | `merged` | `2026-03-28` | `main` | `Domain types and pure observation helpers are merged.` |
| Phase 2: Shared Traits and Test Doubles | `merged` | `2026-03-28` | `main` | `Repository and enrichment traits plus test doubles are merged.` |
| Phase 3: Coordinator and Runtime Pipeline Refactor | `merged` | `2026-03-28` | `main` | `Coordinator flow, phase checkpoints, writer pipeline, overlay/routability fixes, and follow-up cancellation/checkpoint hardening are merged.` |
| Phase 4: ClickHouse Crate and Migrations | `reviewing` | `2026-03-28` | `feat/BNDD-0005-phase-4-clickhouse` | `ClickHouse adapter crate, migration runner, checked-in SQL migrations, and repository tests are on the Phase 4 branch.` |
| Phase 5: MMDB Enrichment Adapter | `pending` | `2026-03-28` | `` | `` |
| Phase 6: App Wiring | `pending` | `2026-03-28` | `` | `` |
| Phase 7: End-to-End Verification | `pending` | `2026-03-28` | `` | `` |

## Immediate Next Slice

- Finish review and merge of the ClickHouse adapter crate and checked-in migrations
- Start Phase 5 with the MMDB enrichment adapter after the storage adapter lands on `main`

## Explicit Agent Constraints

- Keep protocol parsing and session logic out of repository and adapter code
- Keep ClickHouse code out of `crates/btc-network`
- Keep MMDB loading and lookup code behind `IpEnrichmentProvider`
- Keep React, Tauri, and CLI code as adapters over shared workflow code
- Do not invent a separate delayed enrichment/backfill system in v1
- Keep `not applicable`, `unavailable`, and lookup failure distinguishable in the enrichment model
- Prefer small, reviewable PRs with clear verification at each step

## Phase 1: Shared Domain Model

Goal:
Define the pure crawler-persistence domain model in `crates/btc-network`.

Targets:
- `crates/btc-network/src/crawler/types.rs`
- `crates/btc-network/src/crawler/mod.rs`
- new small helper modules under `crates/btc-network/src/crawler/` if needed

Deliverables:
- `CrawlRunId`
- `CrawlPhase`
- `CrawlRunCheckpoint`
- `RawNodeObservation`
- `IpEnrichment`
- `PersistedNodeObservation`
- `StartCrawlRequest`
- `StopCrawlRequest`
- pure helpers for normalization, enrichment eligibility, and observation assembly

Done criteria:
- the shared model clearly separates protocol-derived fields from enrichment-derived fields
- overlay-network and non-routable endpoints are represented without fake geographic data
- pure helpers have focused unit tests

## Phase 2: Shared Traits and Test Doubles

Goal:
Introduce narrow shared interfaces before infrastructure adapters.

Targets:
- `crates/btc-network/src/crawler/`

Deliverables:
- `IpEnrichmentProvider`
- `CrawlerRepository`
- in-memory or mock implementations used only for tests

Done criteria:
- the shared workflow can be tested without ClickHouse
- the shared workflow can be tested without MMDB files

## Phase 3: Coordinator and Runtime Pipeline Refactor

Goal:
Reshape the existing crawler flow into the BNDD-0005 pipeline.

Targets:
- `crates/btc-network/src/crawler/mod.rs`
- `crates/btc-network/src/crawler/worker.rs`
- `crates/btc-network/src/crawler/lifecycle.rs`
- `crates/btc-network/src/crawler/node.rs`

Deliverables:
- explicit single-active-run coordinator behavior
- run phases: `bootstrap`, `crawling`, `draining`, `completed`, `failed`
- pipeline stages for raw observation, normalization, enrichment, enqueue, write
- checkpoint emission hooks

Done criteria:
- one active run is enforced in-process
- stop requests transition to draining
- the runtime can produce persisted-observation values without knowing ClickHouse details

## Phase 4: ClickHouse Crate and Migrations

Goal:
Add the storage adapter without polluting the shared crate.

Targets:
- new `crates/btc-network-clickhouse/`
- root workspace manifests as needed
- checked-in migrations under the new crate

Deliverables:
- ClickHouse repository implementation
- migration runner or explicit migration support code
- schema for `node_observations`, `crawler_run_checkpoints`, and `schema_migrations`
- analytics read for `count_nodes_by_asn`

Done criteria:
- streamed inserts and checkpoint writes work through `CrawlerRepository`
- the schema matches BNDD-0005 field semantics
- migrations are explicit and not tied to app startup

## Phase 5: MMDB Enrichment Adapter

Goal:
Add local IP enrichment behind the shared trait.

Targets:
- new enrichment adapter module or crate
- configuration plumbing for dataset paths

Deliverables:
- MMDB-backed `IpEnrichmentProvider`
- routable IPv4/IPv6 lookup support
- explicit outcomes for success, not applicable, unavailable, and lookup failure

Done criteria:
- ASN, country, and prefix come only from the enrichment adapter
- overlay-network endpoints bypass geographic lookup cleanly
- no remote download is required during normal crawl execution

## Phase 6: App Wiring

Goal:
Connect the shared workflow to the first runnable surface.

Targets:
- `apps/crawler/src/main.rs`
- any shared configuration plumbing needed in `crates/btc-network`

Deliverables:
- crawler app uses the shared coordinator workflow with repository and enrichment adapters
- runtime configuration covers concurrency, ClickHouse connection, and enrichment dataset paths

Done criteria:
- the runnable crawler path exercises the full happy path end to end
- app code remains an adapter and does not reimplement workflow logic

## Phase 7: End-to-End Verification

Goal:
Lock in the behavior with integration tests.

Targets:
- shared crate integration tests
- ClickHouse adapter integration tests

Required coverage:
- migrations apply and are recorded
- streamed batch inserts preserve observation and batch identity across retries
- the latest active run can recover from the last durable checkpoint
- latest verified nodes by ASN query works under repeated observations
- routable IPv4/IPv6 enrichment works before persistence
- overlay-network and non-routable endpoints persist without fake enrichment
- invalid control input is rejected

## Suggested PR Sequence

- PR 1: shared domain model and pure helpers
- PR 2: repository and enrichment traits plus tests
- PR 3: coordinator and runtime pipeline refactor
- PR 4: ClickHouse crate, schema, and repository implementation
- PR 5: MMDB enrichment adapter
- PR 6: app wiring and end-to-end tests

## Non-Goals For V1

- multi-instance crawler ownership
- a separate latest-state table or materialized view
- browser-side direct crawler control without the future API
- remote enrichment services or runtime dataset downloads
- raw SQL exposure to UI or agent-facing surfaces

## Verification

- shared Rust slices: `cargo test -p btc-network`
- adapter and workspace slices when justified: `make test`
- dependency and automation changes: `make security`
