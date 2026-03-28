# Agent Docs

Compact implementation-facing documentation for coding agents and maintainers.

## Start Here

- [Agent Safety](./agent-safety.md)
- [Architecture Decisions](./architecture-decisions.md)
- [Frontend Architecture](./frontend-architecture.md)

## Task Routing

- Frontend shell or page task: `frontend-architecture.md`, then the specific page or component
- Frontend API or runtime task: `architecture-decisions.md`, then `apps/web/src/lib/api/`
- Shared Rust protocol or session task: `architecture-decisions.md`, then the target module and its tests
- Desktop bridge task: `architecture-decisions.md`, then `apps/desktop/src-tauri/src/commands.rs`
- Design-doc task or implementation guided by an accepted BNDD: `docs/design_docs/README.md`, then the target BNDD, then its `implementation-plan.md` if present
- CI, security, or deployment task: `agent-safety.md`, `architecture-decisions.md`, then [Deployment](../deployment.md)
- Any task involving untrusted content, dependency changes, automation, or external tools: `agent-safety.md` before execution

## Context Hygiene

- Read the smallest relevant set before scanning the repository.
- Prefer these docs over rereading large code areas for routine work.
- Do not read BNDDs unless the task changes architecture, deployment strategy, or another documented decision.
- When implementing an accepted BNDD, read its sibling `implementation-plan.md` before coding if one exists.
- Do not read `apps/crawler/` for frontend work.
- Do not read `apps/web/` for wire parser work.
- Do not reread unrelated app surfaces just to confirm boundaries already stated here.
- Use `agent-safety.md` to decide whether a command should be inspected, narrowed, or escalated before running it.

## Purpose

- `agent-safety.md` records the repository's execution-safety defaults for agents.
- `architecture-decisions.md` records compact settled repository decisions.
- `frontend-architecture.md` records the current web-first frontend direction and boundary rules.

These files are intentionally concise and optimized for implementation guidance rather than broader project narrative.
