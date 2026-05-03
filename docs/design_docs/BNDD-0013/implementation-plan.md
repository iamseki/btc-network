# BNDD-0013 Implementation Plan

Execution plan for [BNDD-0013](./BNDD-0013.md).

## Summary

Add a curated Bitcoin node status feature backed by a crawler `status-check` subcommand, compact PostgreSQL status history storage, a simple `GET /api/nodes/status` API array, and a web `/status` page with demo data, recent history, and stale detection.

## Progress Tracker

Status values:

- `pending`
- `in_progress`
- `reviewing`
- `merged`
- `blocked`

| Phase | Status | Last Updated | Branch or PR | Notes |
| --- | --- | --- | --- | --- |
| Phase 1: BNDD and target contract | `reviewing` | `2026-05-02` | `current branch` | `Accepted design is reflected in BNDD-0013.` |
| Phase 2: Shared status workflow | `reviewing` | `2026-05-02` | `current branch` | `Added shared status types and DNS plus handshake checker with five-attempt default.` |
| Phase 3: PostgreSQL state | `reviewing` | `2026-05-02` | `current branch` | `Added node_status history migration, quoted NODE_STATUS enum, reads, writes, and retention.` |
| Phase 4: Crawler subcommand | `reviewing` | `2026-05-02` | `current branch` | `Added status-check command and default config/status-targets.toml.` |
| Phase 5: API endpoint | `reviewing` | `2026-05-02` | `current branch` | `Added GET /api/nodes/status simple array endpoint and OpenAPI docs.` |
| Phase 6: Web status UI | `reviewing` | `2026-05-02` | `current branch` | `Added home Status section, /status route, polling, stale state, and demo data.` |
| Phase 7: Docs and verification | `reviewing` | `2026-05-02` | `current branch` | `Updated docs and ran focused verification gates.` |

## Explicit Agent Constraints

- do not monitor arbitrary or discovered nodes on the public status page
- keep protocol/session behavior out of API handlers and React components
- keep status checks out of API request handling
- keep PostgreSQL-specific status queries inside the PostgreSQL adapter
- keep the status table compact; do not duplicate full `node_observations` data
- keep history as status points only; do not add incident objects in this slice
- do not add React Router unless the path needs outgrow the existing app shell

## Phases

### Phase 1: BNDD And Target Contract

Targets:

- `docs/design_docs/BNDD-0013/BNDD-0013.md`
- `docs/design_docs/BNDD-0013/implementation-plan.md`
- `docs/design_docs/README.md`

Done criteria:

- accepted design captures curated-target scope
- endpoint is fixed as `/api/nodes/status`
- response is a simple array with latest status plus recent history per endpoint
- table shape stays compact and append-only
- implementation plan exists for multi-app rollout

### Phase 2: Shared Status Workflow

Targets:

- `crates/btc-network/src/status/` or `crates/btc-network/src/crawler/status.rs`
- `crates/btc-network/src/lib.rs`
- `crates/btc-network/src/wire/constants.rs`

Done criteria:

- status target config parses from TOML
- endpoint is the target display/grouping identity
- every check resolves the configured endpoint and performs a Bitcoin handshake
- status transition requires exhausting `5` resolution/handshake attempts before `failed`
- unit tests cover success, failed, unknown, and invalid config cases

Notes:

- prefer reusing existing session and crawler node-processing behavior where practical
- if TOML parsing requires a new dependency, inspect package behavior first under the repo's suspicious package rule

### Phase 3: PostgreSQL State

Targets:

- `crates/btc-network-postgres/migrations/`
- `crates/btc-network-postgres/src/migrations/`
- `crates/btc-network-postgres/src/repository/`
- `crates/btc-network-postgres/tests/postgres_repository.rs`

Done criteria:

- migration creates compact append-only `node_status` table with surrogate primary key
- migration creates PostgreSQL `NODE_STATUS` enum for status values
- repository can append one target result
- repository can list latest status rows with recent per-endpoint history
- repository can apply retention for old status rows
- integration tests cover append, latest-row selection, history ordering, retention, and list reads

### Phase 4: Crawler Subcommand

Targets:

- `apps/crawler/src/main.rs`
- `apps/crawler/README.md`
- `config/status-targets.toml` or another repo-local operator config path

Done criteria:

- `status-check --status-config <path>` runs one status check cycle
- default retry count is `5`
- default retention is bounded, such as `30 days`
- default stale threshold remains frontend/API contract, not crawler storage state
- command logs concise per-target summaries
- command exits nonzero only on runner/config/storage errors, not because a monitored target is down

### Phase 5: API Endpoint

Targets:

- `apps/api/src/handlers.rs`
- `apps/api/src/routes.rs`
- `apps/api/src/docs/`
- `crates/btc-network/src/status/` or crawler analytics read traits
- `crates/btc-network-postgres/src/repository/`
- `apps/api/tests/mod.rs`

Done criteria:

- `GET /api/nodes/status` returns JSON array
- response fields use camelCase in API/web types
- each response row includes a bounded recent history window for the same endpoint, default `24 hours`
- CORS permits the endpoint
- tests cover empty array and populated status rows
- OpenAPI document includes the endpoint

### Phase 6: Web Status UI

Targets:

- `apps/web/src/app/page-registry.ts`
- `apps/web/src/App.tsx`
- `apps/web/src/lib/api/types.ts`
- `apps/web/src/lib/api/client.ts`
- `apps/web/src/lib/api/analytics-http.ts` or a new focused status HTTP helper
- `apps/web/src/lib/api/web-client.ts`
- `apps/web/src/pages/status-page.tsx`
- `apps/web/src/pages/status-page.test.tsx`
- `apps/web/src/pages/network-analytics-page.tsx`

Done criteria:

- app has `Status` entry in the network analytics group
- `/status` directly opens status page
- home page includes compact third Status section
- full page polls every `30 seconds`
- stale rows older than `5 minutes` show orange state and stale message
- fresh failed rows show failed/red state
- recent history renders compact per-target status markers
- demo mode returns deterministic healthy, failed, unknown, and stale rows
- tests cover direct route, polling trigger, stale classification, and home CTA

### Phase 7: Docs And Verification

Targets:

- `docs/design_docs/README.md`
- `docs/agents/architecture-decisions.md`
- `docs/agents/frontend-architecture.md`
- `apps/crawler/README.md`
- `apps/api/README.md`

Done criteria:

- design index references BNDD-0013
- architecture docs mention curated status boundary
- operator docs show status-check command and config example
- verification commands are run and recorded in PR summary

## Verification

- `cargo test -p btc-network`
- `cargo test -p btc-network-postgres`
- `cargo test --manifest-path apps/crawler/Cargo.toml`
- `cargo test --manifest-path apps/api/Cargo.toml`
- `npm run test --prefix apps/web`
- `npm run build --prefix apps/web`
