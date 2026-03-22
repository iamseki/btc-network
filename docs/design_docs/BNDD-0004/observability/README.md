# Archived Observability Experiment

This directory stores the archived March 2026 local observability experiment for agent runtime telemetry.

It is historical reference material only.

Current status:

- `BNDD-0004` is `rejected`
- this stack is not a supported day-to-day repository workflow
- the files remain here so the experiment can be revisited later

## Files

- `.env.example`
- `docker-compose.yml`
- `otel-collector-config.yaml`

A local `.env` may also exist on a developer machine, but it should remain local-only.

## What This Experiment Tried

The experiment wired:

```text
Codex
  -> OpenTelemetry Collector
  -> self-hosted Langfuse
```

The goal was better visibility into agent behavior, latency, token usage, and cost.

## Why It Is Archived

As of `2026-03-22`, the resulting experience was not good enough for routine use.

The main gaps were:

- weak UI and UX for understanding what the agent is doing
- insufficient practical visibility into latency, token usage, and cost in one place
- Codex IDE-extension limitations that made the setup less useful than hoped

See `../BNDD-0004.md` for the full rejection rationale.

## If You Want To Revisit It Later

Use this directory as the historical baseline.

If the tooling improves, or if Claude or another runtime offers a better observability story, this archive can be used as a starting point for a fresh design decision rather than as current guidance.
