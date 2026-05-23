# BNDD-0016 Implementation Plan

Execution plan for [BNDD-0016](./BNDD-0016.md).

## Summary

Add one conservative, read-only Sybil-oriented metrics report for latest-run crawler analytics. The report exposes typed heuristic review signals derived from raw concentration metrics, while explicitly avoiding confirmed attack claims.

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
| Phase 2: Shared read contract | `pending` | `2026-05-23` | `docs/BNDD-0016-sybil-metrics` | `Add report and typed signal models; keep interpretation and limitation prose out of response models.` |
| Phase 3: PostgreSQL aggregations | `pending` | `2026-05-07` | `docs/BNDD-0016-sybil-metrics` | `Run-scoped aggregate queries for concentration and uniformity.` |
| Phase 4: API and OpenAPI | `pending` | `2026-05-07` | `docs/BNDD-0016-sybil-metrics` | `Add last-run sybil metrics endpoint and docs guardrails.` |
| Phase 5: Web evidence surface | `reviewing` | `2026-05-23` | `feat/BNDD-0016-risk-library` | `Render review signals as Risk library topic cards without attack language.` |

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

### Phase 2: Shared Read Contract

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

### Phase 3: PostgreSQL Aggregations

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

### Phase 4: API And OpenAPI

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

### Phase 5: Web Evidence Surface

Targets:

- `apps/web/src/lib/api/`
- `apps/web/src/components/analytics/`
- `apps/web/src/pages/risk-page.tsx`
- `apps/web/src/pages/network-analytics-page.tsx`
- affected page/component tests

Done criteria:

- Risk page shows Sybil-oriented evidence as the first growable topic card
- Network Analytics keeps Status and Crawler Runs as header-level sibling views instead of sidebar entries
- typed signal values are visible near signal labels
- UI does not use attack, attacker, malicious, or controlled-by-one-entity language
- empty signal state explains that no heuristic review signals crossed thresholds
- demo mode includes conservative sample data and limitations

## Verification

- `cargo test -p btc-network`
- `cargo test -p btc-network-postgres`
- `cargo test -p btc-network-api`
- `npm run test --prefix apps/web`
- `npm run build --prefix apps/web`

Optional before accepting implementation:

- run `EXPLAIN` for the Sybil metrics aggregate queries against a realistic latest run
- document observed query cost if a new index or generated fingerprint key is proposed
