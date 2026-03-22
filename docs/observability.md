# Observability

The previous local agent observability experiment in this repository has been archived.

As of `2026-03-22`, the repository does not treat `Codex -> OpenTelemetry Collector -> self-hosted Langfuse` as a supported day-to-day workflow.

The experiment was able to prove technical ingestion, but it did not provide the UI and UX quality needed to understand agent behavior or to track latency, token usage, and cost well enough for routine use.

Codex OTEL export could be enabled, but the IDE extension still imposed enough practical limitations that the result did not meet the repository need.

For the historical decision record, see [BNDD-0004](./design_docs/BNDD-0004/BNDD-0004.md).

For the archived stack files, see [`docs/design_docs/BNDD-0004/observability/`](./design_docs/BNDD-0004/observability/README.md).

This may be revisited later with improved Codex support, Claude, or another solution.
