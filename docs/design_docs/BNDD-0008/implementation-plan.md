# BNDD-0008 Implementation Plan

Execution history for [BNDD-0008](./BNDD-0008.md).

## Summary

The original rollout implemented durable crawler crash recovery, but that
design has since been deprecated. The crawler now restarts fresh instead of
recovering the latest active run.

## Progress Tracker

Status values:

- `pending`
- `in_progress`
- `reviewing`
- `merged`
- `blocked`

| Phase | Status | Last Updated | Branch or PR | Notes |
| --- | --- | --- | --- | --- |
| Phase 1: Shared crawler recovery-state refactor | `merged` | `2026-04-05` | `historical` | `Original recovery-frontier implementation landed.` |
| Phase 2: PostgreSQL schema and repository rollout | `merged` | `2026-04-05` | `historical` | `Historical recovery-point table and repository support landed.` |
| Phase 3: Operator and design-doc alignment | `merged` | `2026-04-05` | `historical` | `Docs and CLI knobs were aligned with recovery design.` |
| Phase 4: Recovery-path removal | `merged` | `2026-04-12` | `PR #21` | `Crawler startup recovery, recovery-point writes, and repository recovery APIs were removed. Historical migrations remain for compatibility.` |

## Current State

No further rollout work is planned under this BNDD.

Future crawler durability changes should use a new BNDD only if real operator
evidence shows that fresh-start reruns are no longer sufficient.
