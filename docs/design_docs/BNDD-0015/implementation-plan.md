# BNDD-0015 Implementation Plan

Execution plan for [BNDD-0015](./BNDD-0015.md).

## Summary

Add keyset pagination only where row-level scans are needed, and add explicit date or run bounds where aggregate queries would otherwise scan growing history. This is a breaking pre-production API change.

## Progress Tracker

Status values:

- `pending`
- `in_progress`
- `reviewing`
- `merged`
- `blocked`

| Phase | Status | Last Updated | Branch or PR | Notes |
| --- | --- | --- | --- | --- |
| Phase 1: BNDD and endpoint classification | `merged` | `2026-05-06` | `#36` | `BNDD status and index aligned with implementation.` |
| Phase 2: Last-run nodes keyset | `merged` | `2026-05-06` | `#36` | `Added node_observation_id, keyset query, page envelope, and token tests.` |
| Phase 3: Historical aggregate bounds | `merged` | `2026-05-06` | `#36` | `Historical ASN aggregation now requires bounded start/end window.` |
| Phase 4: API and OpenAPI updates | `merged` | `2026-05-06` | `#36` | `OpenAPI and guardrail tests keep pageToken/date params targeted.` |
| Phase 5: Web, demo, and docs | `merged` | `2026-05-06` | `#36` | `Web clients, demo pagination, /agents.md, and agent docs updated.` |

## Explicit Agent Constraints

- do not add pagination to every endpoint by default
- do not implement offset pagination
- do not remove endpoint-specific max limits
- do not auto-scan all pages from dashboard/home React components
- keep aggregate endpoints as top-N unless a full export use case exists
- prefer date or run bounds for historical aggregates over cursoring aggregate buckets
- add `BIGSERIAL` only where the chosen keyset endpoint needs a stable tie-breaker
- keep protocol parsing and crawler runtime behavior out of this work

## Phases

### Phase 1: BNDD And Endpoint Classification

Targets:

- `docs/design_docs/BNDD-0015/BNDD-0015.md`
- `docs/design_docs/BNDD-0015/implementation-plan.md`
- `docs/design_docs/README.md`
- `docs/agents/architecture-decisions.md`

Done criteria:

- BNDD distinguishes row scans from aggregate top-N reads
- no-backward-compatibility assumption is explicit
- implementation plan avoids blanket cursor rollout

### Phase 2: Last-Run Nodes Keyset

Targets:

- `crates/btc-network-postgres/migrations/`
- `crates/btc-network-postgres/src/migrations/bundled.rs`
- `crates/btc-network-postgres/src/repository/analytics.rs`
- `crates/btc-network/src/crawler/ports.rs`
- `apps/api/src/handlers/last_run/nodes.rs`
- `apps/api/tests/handlers/last_run_nodes.rs`

Done criteria:

- `node_observations` has `node_observation_id BIGSERIAL PRIMARY KEY`
- `last-run/nodes` supports `limit` plus opaque `pageToken`
- query uses keyset predicate aligned with `ORDER BY observed_at DESC, endpoint ASC, node_observation_id DESC`
- response includes `items` and `nextPageToken`
- tests cover first page, next page, invalid token, wrong endpoint token, zero limit, and max limit

### Phase 3: Historical Aggregate Bounds

Targets:

- `apps/api/src/handlers/historical/asns.rs`
- `crates/btc-network-postgres/src/repository/analytics.rs`
- `crates/btc-network/src/crawler/ports.rs`
- `apps/api/tests/handlers/historical_asns.rs`

Done criteria:

- historical ASN aggregation no longer performs unbounded all-history reads
- contract requires either a bounded `start`/`end` window or a run-scoped query
- max window is explicit and tested
- malformed ranges return `400 bad_request`
- `limit` remains a top-N cap

### Phase 4: API And OpenAPI Updates

Targets:

- `apps/api/src/handlers/`
- `apps/api/src/docs/mod.rs`
- `apps/api/tests/docs_routes/mod.rs`
- `apps/api/tests/handlers/limit_guardrails.rs`

Done criteria:

- OpenAPI shows `pageToken` only on keyset endpoints
- OpenAPI shows `start` and `end` only on date-bounded historical endpoints
- existing compact distribution endpoints stay limit-only
- guardrail tests reflect endpoint-specific strategy

### Phase 5: Web, Demo, And Docs

Targets:

- `apps/web/src/lib/api/types.ts`
- `apps/web/src/lib/api/analytics-http.ts`
- `apps/web/src/lib/api/web-client.ts`
- affected page tests
- `apps/api/src/docs/agents.md`
- `apps/api/README.md`
- `docs/agents/architecture-decisions.md`
- `docs/agents/frontend-architecture.md`
- `docs/design_docs/BNDD-0014/BNDD-0014.md`

Done criteria:

- web client handles `last-run/nodes` page envelope
- web pages request modest first pages and do not auto-scan all pages
- demo mode mimics `nextPageToken` only for paginated endpoint
- `/agents.md` tells agents to use date bounds for historical aggregates and `nextPageToken` only for row scans
- docs no longer imply every endpoint is cursor-paginated

## Verification

- `cargo test -p btc-network-api`
- `cargo test -p btc-network-postgres`
- `npm run test --prefix apps/web`
- `npm run build --prefix apps/web`

Optional after SQL changes:

- run `EXPLAIN` for `last-run/nodes` keyset query
- run `EXPLAIN` for historical ASN bounded window query
