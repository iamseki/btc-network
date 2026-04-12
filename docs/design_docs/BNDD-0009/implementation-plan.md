# BNDD-0009 Implementation Plan

Execution plan for [BNDD-0009](./BNDD-0009.md).

## Summary

Add dedicated connect admission control to the crawler, extend runtime pressure telemetry, keep docs and operator defaults aligned with the new control surfaces, and then add delayed retry requeueing as the fairness-oriented scheduling improvement.

## Progress Tracker

Status values:

- `pending`
- `in_progress`
- `reviewing`
- `merged`
- `blocked`

| Phase | Status | Last Updated | Branch or PR | Notes |
| --- | --- | --- | --- | --- |
| Phase 1: Shared crawler connect admission control | `reviewing` | `2026-04-12` | `current branch` | `Added max_in_flight_connects and wired the connect path through a dedicated semaphore so worker parallelism no longer equals outbound connect pressure.` |
| Phase 2: Runtime pressure telemetry expansion | `reviewing` | `2026-04-12` | `current branch` | `Progress summaries now expose connect-slot usage plus connectable task, retry, and failure counters alongside process and PostgreSQL runtime metrics.` |
| Phase 3: Operator config and documentation alignment | `reviewing` | `2026-04-12` | `current branch` | `Compose and crawler docs now describe separate worker/connect budgets, realistic local nofile defaults, and how to interpret the expanded pressure metrics.` |
| Phase 4: Delayed retry requeueing | `reviewing` | `2026-04-12` | `current branch` | `Retryable connect failures are requeued with delayed backoff metadata and owned by crawler task shutdown rather than detached runtime tasks.` |

## Immediate Next Slice

- add `max_in_flight_connects` to shared crawler config and CLI/Compose adapters
- guard the TCP connect path with a dedicated semaphore rather than using raw worker count as the connect budget
- add progress metrics for live connect-slot usage
- decide whether timeout and retry counters belong in `CrawlerStats` or a dedicated networking-pressure struct

## Explicit Agent Constraints

- keep connect admission logic in the shared crawler layer, not in Compose or CLI glue
- keep PostgreSQL-specific pool reporting behind repository/runtime adapter boundaries
- do not redesign crawler persistence schema for this slice
- do not add opaque adaptive controllers in the first implementation; prefer explicit operator-set knobs with observable effects
- when delayed retry requeueing is implemented, keep retry state minimal; prefer `attempt_count`, `last_attempt_at`, and `last_failure_classification` over richer scheduling state unless the simpler design proves inadequate
- keep diagnostics cheap enough to emit in periodic progress logs

## Phases

### Phase 1: Shared Crawler Connect Admission Control

Targets:

- `crates/btc-network/src/crawler/types.rs`
- `crates/btc-network/src/crawler/mod.rs`
- `crates/btc-network/src/crawler/node.rs`
- `apps/crawler/src/main.rs`

Done criteria:

- shared config includes `max_in_flight_connects`
- worker execution can stay highly parallel while the connect phase is separately bounded
- connect retries also consume connect permits
- tests cover the bounded-connect behavior

### Phase 2: Runtime Pressure Telemetry Expansion

Targets:

- `crates/btc-network/src/crawler/types.rs`
- `crates/btc-network/src/crawler/worker.rs`
- `crates/btc-network/src/crawler/node.rs`
- `crates/btc-network/src/crawler/lifecycle.rs`

Done criteria:

- periodic progress logs report live connect-slot usage
- timeout and retry pressure are visible in logs
- telemetry remains best-effort and does not fail the crawl when platform-specific runtime inspection is unavailable

### Phase 3: Operator Config And Documentation Alignment

Targets:

- `compose/crawler.yml`
- `apps/crawler/README.md`
- `docs/agents/architecture-decisions.md` only if boundary guidance changes

Done criteria:

- docs explain difference between worker concurrency and connect concurrency
- Compose defaults and examples reflect the new knob
- local operator guidance explains interaction between `nofile`, connect budget, timeout, and retries

### Phase 4: Delayed Retry Requeueing

Targets:

- `crates/btc-network/src/crawler/types.rs`
- `crates/btc-network/src/crawler/worker.rs`
- `crates/btc-network/src/crawler/node.rs`
- `crates/btc-network/src/crawler/mod.rs`

Done criteria:

- retryable connect failures are requeued for later consideration instead of sleeping inline inside the same worker
- retry state stays minimal and does not require duplicate scheduling truth such as stored `next_eligible_at`
- retry ceilings remain explicit and test-covered
- the resulting scheduler behavior improves frontier fairness and reduces repeated immediate retries against bad endpoints

## Verification

- `cargo test -p btc-network`
- `cargo test -p btc-network-crawler`
- `cargo test -p btc-network-postgres`

Additional validation during rollout:

- run crawler with high `max_concurrency` and lower `max_in_flight_connects`
- confirm progress summaries show bounded connect-slot usage
- confirm `tcp_syn_sent` does not scale linearly with total worker count once the connect budget is reached
- confirm delayed retry requeueing improves frontier fairness or retry pressure enough to justify its added scheduler complexity
