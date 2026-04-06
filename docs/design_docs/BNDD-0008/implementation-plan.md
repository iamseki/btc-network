# BNDD-0008 Implementation Plan

Execution plan for [BNDD-0008](./BNDD-0008.md).

## Summary

Shrink crawler restart state to the minimum durable payload needed for recovery, move that payload out of progress checkpoints, and keep PostgreSQL as the default storage backend for the resulting schema.

## Progress Tracker

Status values:

- `pending`
- `in_progress`
- `reviewing`
- `merged`
- `blocked`

| Phase | Status | Last Updated | Branch or PR | Notes |
| --- | --- | --- | --- | --- |
| Phase 1: Shared crawler recovery-state refactor | `reviewing` | `2026-04-05` | `current branch` | `The shared crawler now persists only the resumable workset, restores in-progress work as pending, rebuilds dedupe state from observations, removes checkpoint `resume_state`, and adds `checkpoint_interval`.` |
| Phase 2: PostgreSQL schema and repository rollout | `reviewing` | `2026-04-05` | `current branch` | `PostgreSQL migrations, repository methods, and integration tests now cover `crawler_run_recovery_points`, latest recovery-point reads, and observed-endpoint reconstruction.` |
| Phase 3: Operator and design-doc alignment | `reviewing` | `2026-04-05` | `current branch` | `The crawler CLI exposes `--checkpoint-interval-secs`, and the design docs plus local-operator docs now describe the split between progress checkpoints and recovery points.` |

## Immediate Next Slice

- land the branch and update this tracker from `reviewing` to `merged`
- add future storage telemetry only if real recovery payload growth becomes operationally relevant
- keep any further recovery-state changes behind this BNDD rather than reintroducing large blobs into checkpoints

## Explicit Agent Constraints

- keep recovery-state decisions in the shared crawler layer, not in app entrypoints
- keep PostgreSQL-specific SQL and migrations inside `crates/btc-network-postgres`
- do not reintroduce `resume_state` on `crawler_run_checkpoints`
- keep recovery semantics at-least-once unless a later BNDD explicitly pays the complexity cost for something stronger
- prefer shrinking state shape before tuning compression settings

## Verification

- `cargo test -p btc-network`
- `cargo test -p btc-network-postgres`
- `cargo test -p btc-network-crawler`
