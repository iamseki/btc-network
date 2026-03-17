# Agent Docs

Compact implementation-facing documentation for coding agents and maintainers.

## Start Here

- [Architecture Decisions](./architecture-decisions.md)
- [Frontend Architecture](./frontend-architecture.md)

## Task Routing

- Frontend shell or page task: `frontend-architecture.md`, then the specific page or component
- Frontend API or runtime task: `architecture-decisions.md`, then `apps/web/src/lib/api/`
- Shared Rust protocol or session task: `architecture-decisions.md`, then the target module and its tests
- Desktop bridge task: `architecture-decisions.md`, then `apps/desktop/src-tauri/src/commands.rs`
- CI, security, or deployment task: `architecture-decisions.md`, then [Deployment](../deployment.md)

## Context Hygiene

- Read the smallest relevant set before scanning the repository.
- Prefer these docs over rereading large code areas for routine work.
- Do not read BNDDs unless the task changes architecture, deployment strategy, or another documented decision.
- Do not read `apps/crawler/` for frontend work.
- Do not read `apps/web/` for wire parser work.
- Do not reread unrelated app surfaces just to confirm boundaries already stated here.

## Purpose

- `architecture-decisions.md` records compact settled repository decisions.
- `frontend-architecture.md` records the current web-first frontend direction and boundary rules.

These files are intentionally concise and optimized for implementation guidance rather than broader project narrative.
