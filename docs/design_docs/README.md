# Design Docs

Opinionated rules for `BNDD` documents in this repository.

## Rules

- Use one directory per design doc.
- Keep one canonical entry file per doc directory: `BNDD-0001/BNDD-0001.md`.
- Update the main doc when the decision changes; do not leave the benchmark or assets as the only source of truth.
- Add a `Contents` section for any doc that is more than a short note.
- If a BNDD has code, scripts, diagrams, or benchmark files, keep them under that BNDD directory instead of the top-level `design_docs/`.
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
