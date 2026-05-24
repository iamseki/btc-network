# BNDD-0016 Implementation Plan

Execution plan for [BNDD-0016](./BNDD-0016.md).

## Summary

Start with a mocked web evidence surface for Sybil-oriented risk topics. Backend, storage, and public API work must wait for explicit human review and approval after the mocked UI proves the product shape.

## Progress Tracker

Status values:

- `pending`
- `in_progress`
- `reviewing`
- `merged`
- `blocked`

| Phase | Status | Last Updated | Branch or PR | Notes |
| --- | --- | --- | --- | --- |
| Phase 1: BNDD and boundaries | `reviewing` | `2026-05-07` | `docs/BNDD-0016-sybil-metrics` | `Defines metric scope, non-detection boundary, and rollout plan.` |
| Phase 2: Mocked web evidence surface | `merged` | `2026-05-24` | `#39` | `Risk article UI and Markdown-backed content workflow merged.` |
| Phase 3: Human approval gate | `merged` | `2026-05-24` | `conversation approval` | `Human approved continuing beyond the mocked UI, starting with Phase 4 shared read contract.` |
| Phase 4: Shared read contract | `reviewing` | `2026-05-24` | `feat/BNDD-0016-shared-read-contract` | `Adds report and typed signal models without PostgreSQL or API wiring.` |
| Phase 5: PostgreSQL aggregations | `blocked` | `2026-05-24` | `not-started` | `Blocked until Phase 4 shared read contract is merged or included in the active implementation branch.` |
| Phase 6: API and OpenAPI | `blocked` | `2026-05-24` | `not-started` | `Blocked until Phase 4 and Phase 5 are merged or included in the active implementation branch.` |

## Explicit Agent Constraints

- do not call these metrics Sybil detection
- do not emit attack claims from crawler data
- do not model `attackClaims` in the first response shape
- keep raw metrics as internal signal inputs, not a top-level API payload
- do not include response prose fields such as `interpretation`, `confidenceBoundary`, or `limitations`
- use typed signal fields instead of a generic `evidence[]` array until the API needs heterogeneous evidence
- ground every metric in persisted crawler fields
- avoid opaque scores and ML-style confidence
- keep queries scoped to one selected latest run
- do not add protocol parsing logic to API handlers or React components
- do not add materialized views until query cost is measured
- start with mocked web data only
- do not implement shared models, PostgreSQL queries, API handlers, or OpenAPI contract changes until a human explicitly approves Phase 3

## Phases

### Phase 1: BNDD And Boundaries

Targets:

- `docs/design_docs/BNDD-0016/BNDD-0016.md`
- `docs/design_docs/BNDD-0016/implementation-plan.md`
- `docs/design_docs/README.md`

Done criteria:

- BNDD distinguishes raw metrics, heuristic signals, and confirmed attack claims
- limitations around NAT, VPN, Tor, cloud concentration, and incomplete visibility are explicit
- first endpoint and response boundaries are documented
- design doc index status matches BNDD status

### Phase 2: Mocked Web Evidence Surface

Targets:

- `apps/web/src/pages/risk-page.tsx`
- `apps/web/src/pages/risk-page.test.tsx`
- `apps/web/src/App.tsx`
- `apps/web/src/App.test.tsx`
- `apps/web/src/app/page-registry.ts`
- `apps/web/src/app/page-registry.test.ts`
- `apps/web/src/pages/network-analytics-page.tsx`
- affected frontend docs

Done criteria:

- Risk page is a primary sidebar destination
- Risk page shows mocked Sybil-oriented evidence as the first growable topic card
- Network Analytics keeps Status and Crawler Runs as header-level sibling views instead of sidebar entries
- mocked typed signal values are visible near signal labels
- UI does not use attack, attacker, malicious, or controlled-by-one-entity language
- empty signal state copy exists for the future real API path
- demo/mock copy clearly distinguishes planned signals from live backend findings
- no backend, shared Rust model, PostgreSQL, API route, or OpenAPI implementation is added in this phase

### Phase 3: Human Approval Gate

Targets:

- mocked Risk page review
- BNDD-0016 response shape review
- implementation scope review for backend/API phases

Done criteria:

- a human explicitly approves moving beyond mocked web UI
- approved scope names which backend phases may start
- any requested response-shape changes are reflected in this BNDD before implementation
- implementation branch or PR is identified for the approved backend/API work

Until this phase is approved, agents must stop after frontend mock work and documentation updates.

### Phase 4: Shared Read Contract

Targets:

- `crates/btc-network/src/crawler/ports.rs`
- `crates/btc-network/src/crawler/analytics.rs` or nearest existing analytics model module
- shared serialization tests where existing read models are tested

Done criteria:

- `CrawlerAnalyticsReader` exposes a Sybil metrics report method
- shared models represent report context and typed heuristic signals
- signal levels are limited to `info`, `watch`, and `review`
- model docs warn that signals are not confirmed attacks
- model docs point interpretation and limitation copy to OpenAPI, agent docs, and frontend descriptors

Start condition:

- Phase 3 approval is complete.

### Phase 5: PostgreSQL Aggregations

Targets:

- `crates/btc-network-postgres/src/repository/analytics.rs`
- `crates/btc-network-postgres/src/repository/mod.rs`
- `crates/btc-network-postgres/tests/postgres_repository.rs`

Done criteria:

- latest run selection follows last-run phase filter semantics
- ASN, prefix, country, and software fingerprint aggregations are run-scoped
- HHI is computed from grouped counts
- uniformity signals use explicit thresholds and include typed threshold fields
- tests cover concentration, no-signal baseline, software uniformity, and missing enrichment

Start condition:

- Phase 3 approval is complete.
- Phase 4 shared read contract is merged or included in the active implementation branch.

### Phase 6: API And OpenAPI

Targets:

- `apps/api/src/handlers/last_run/`
- `apps/api/src/routes.rs`
- `apps/api/src/docs/mod.rs`
- `apps/api/tests/handlers/`
- `apps/api/tests/docs_routes/`
- `apps/api/src/docs/agents.md`

Done criteria:

- `GET /api/v1/network/last-run/sybil-metrics` returns report JSON
- response contains run context plus `signals`
- response does not contain top-level `rawMetrics`, `limitations`, `attackClaims`, `interpretation`, `confidenceBoundary`, or generic `evidence[]`
- response uses an internal signal cap instead of a public `limit` or pagination parameter
- bad phase parameters return `400 bad_request`
- OpenAPI documents metric definitions and non-detection boundary
- `/agents.md` tells agents not to treat signals as confirmed attacks

Start condition:

- Phase 3 approval is complete.
- Phase 4 shared read contract and Phase 5 PostgreSQL aggregations are merged or included in the active implementation branch.

## Verification

Phase 2:

- `npm run test --prefix apps/web`
- `npm run build --prefix apps/web`

Backend/API phases after Phase 3 approval:

- `cargo test -p btc-network`
- `cargo test -p btc-network-postgres`
- `cargo test -p btc-network-api`

Optional before accepting implementation:

- run `EXPLAIN` for the Sybil metrics aggregate queries against a realistic latest run
- document observed query cost if a new index or generated fingerprint key is proposed
