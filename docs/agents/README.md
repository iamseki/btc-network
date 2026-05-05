# Agent Docs

Compact routing docs for coding agents.

## Start Here

- [Agent Safety](./agent-safety.md)
- [Architecture Decisions](./architecture-decisions.md)
- [Frontend Architecture](./frontend-architecture.md)

## Task Routing

- Frontend shell or page task: `frontend-architecture.md`, then the specific page or component
- Analytics UI refinement: `frontend-architecture.md`; read [BNDD-0006](../design_docs/BNDD-0006/BNDD-0006.md) and [BNDD-0007](../design_docs/BNDD-0007/BNDD-0007.md) only for product shape, deployment, or storage-adapter changes
- Frontend API or runtime task: `architecture-decisions.md`, then `apps/web/src/lib/api/`
- Shared Rust protocol or session task: `architecture-decisions.md`, then the target module and its tests
- Desktop bridge task: `architecture-decisions.md`, then `apps/desktop/src-tauri/src/commands.rs`
- Troubleshooting or runbook authoring task: `agent-safety.md`, then [`../troubleshooting/README.md`](../troubleshooting/README.md), then the smallest relevant guide in `../troubleshooting/`
- Design-doc task or implementation guided by an accepted BNDD: `docs/design_docs/README.md`, then the target BNDD, then its `implementation-plan.md` if present
- CI, security, or deployment task: `agent-safety.md`, `architecture-decisions.md`, then [Deployment](../deployment.md)
- Any task involving untrusted content, dependency changes, automation, or external tools: `agent-safety.md` before execution

## Context Hygiene

- Read smallest relevant doc set before repo scans.
- Prefer these docs over large code rereads.
- Recent regression: `git status --short`, `git diff --stat`, then `git log --oneline -15`; avoid broad scans until surface is known.
- UI regression: inspect changed page/shared primitive first; add narrow test near that surface.
- Read BNDDs only for architecture, deployment, or documented-decision changes.
- When implementing an accepted BNDD, read its sibling `implementation-plan.md` before coding if one exists.
- Do not read `apps/crawler/` for frontend work.
- Do not read `apps/web/` for wire parser work.
- Do not reread unrelated app surfaces to reconfirm boundaries already stated here.
- If agent docs are stale, update them; do not duplicate guidance.
- Use `agent-safety.md` before risky commands.

## Purpose

- `agent-safety.md`: execution safety defaults
- `architecture-decisions.md`: settled decisions
- `frontend-architecture.md`: web-first frontend boundaries
- `../troubleshooting/`: templates and runbooks
