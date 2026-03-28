# Design Docs

Opinionated rules for `BNDD` documents in this repository.

## Rules

- Use one directory per design doc.
- Keep one canonical entry file per doc directory: `BNDD-0001/BNDD-0001.md`.
- Update the main doc when the decision changes; do not leave the benchmark or assets as the only source of truth.
- Add a `Contents` section for any doc that is more than a short note.
- If a BNDD has code, scripts, diagrams, or benchmark files, keep them under that BNDD directory instead of the top-level `design_docs/`.
- If a BNDD is large enough to require a phased multi-PR rollout, add a sibling `implementation-plan.md`.
- When a sibling `implementation-plan.md` exists, add a short `Implementation Plan` section in the main BNDD that links to it.
- Keep the BNDD as the canonical design truth and keep `implementation-plan.md` execution-oriented: phases, file targets, done criteria, verification, and explicit constraints for agents.
- For active multi-PR work, include a small progress tracker in `implementation-plan.md` so a new agent can recover state from the repository without chat context.
- Prefer a simple table or checklist with phase, status, last-updated date, branch or PR, and notes.
- Treat the tracker as factual rollout state, not as a second design document.
- Prefer rollout statuses like `pending`, `in_progress`, `reviewing`, `merged`, and `blocked` so repository state reflects whether work is still being implemented or is already on a PR.
- Use `implementation-plan.md` when the work crosses multiple crates or apps, introduces multiple infrastructure adapters, or is too large to execute safely from the BNDD text alone.
- Keep the status in this index aligned with the `Status` field in the BNDD header table.

## Status

Use only the canonical status values below.

| Status | Description |
| --- | --- |
| `proposed` | The decision is still being evaluated and is not yet the settled repository direction. |
| `accepted` | The decision has been chosen and should guide implementation. |
| `implemented` | The decision is already reflected in the repository and is implemented in the project. |
| `rejected` | The option or proposal was evaluated and explicitly not adopted. |
| `deprecated` | The document is still useful for historical context, but it should no longer guide new work. |

## Index

| Code | Title | Status | Entry |
| --- | --- | --- | --- |
| `BNDD-0001` | `btc-network` | `implemented` | [BNDD-0001/BNDD-0001.md](./BNDD-0001/BNDD-0001.md) |
| `BNDD-0002` | `Benchmarking analytics storage for crawler observations` | `accepted` | [BNDD-0002/BNDD-0002.md](./BNDD-0002/BNDD-0002.md) |
| `BNDD-0003` | `Web and future API deployment strategy` | `implemented` | [BNDD-0003/BNDD-0003.md](./BNDD-0003/BNDD-0003.md) |
| `BNDD-0004` | `Agent runtime observability via OpenTelemetry Collector and Langfuse` | `rejected` | [BNDD-0004/BNDD-0004.md](./BNDD-0004/BNDD-0004.md) |
| `BNDD-0005` | `Durable crawler runtime and analytics persistence` | `accepted` | [BNDD-0005/BNDD-0005.md](./BNDD-0005/BNDD-0005.md) |
