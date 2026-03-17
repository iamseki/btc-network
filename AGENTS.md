# AGENTS.md

Guidance for coding agents working in this repository.

Start with [docs/agents/README.md](/home/chseki/projects/personal/btc-network/docs/agents/README.md). It routes to the smallest relevant agent docs for the task.

## Project Summary

- Language: Rust (edition 2024)
- Core crate: `btc-network`
- Goal: a research-focused Bitcoin P2P implementation that prioritizes protocol correctness, deterministic parsing, and clear architectural boundaries

This is not a wallet, miner, or full node clone.

## Maintenance Rule

Prefer code that is easy to maintain.

- Choose pragmatic changes over speculative architecture
- Apply YAGNI: do not add abstractions, layers, or options before the project clearly needs them
- Apply KISS: prefer straightforward control flow, explicit types, and small focused helpers over clever reuse
- Add indirection only when it removes real duplication or protects an important boundary

## Communication Rule

When reporting work to the user:

- Be concise and direct
- State the outcome first
- Do not include unnecessary recap, filler, or repeated context
- Prefer short paragraphs over long structured writeups unless the task truly needs detail
- Mention commands and tests only when they materially help the user evaluate the result

## Open These First

Pick the smallest relevant set.

Frontend shell or page task:

- `docs/agents/README.md`
- `docs/agents/architecture-decisions.md`
- `docs/agents/frontend-architecture.md`
- `apps/web/src/App.tsx`
- the specific page or component being changed

Frontend API or runtime task:

- `docs/agents/README.md`
- `docs/agents/architecture-decisions.md`
- `apps/web/src/lib/api/client.ts`
- `apps/web/src/lib/api/types.ts`
- the relevant adapter (`tauri-client.ts` or `web-client.ts`)

Shared Rust protocol or session task:

- `docs/agents/README.md`
- `docs/agents/architecture-decisions.md`
- `crates/btc-network/src/lib.rs`
- the target module under `crates/btc-network/src/`
- the tests next to that module

Desktop bridge task:

- `docs/agents/README.md`
- `docs/agents/architecture-decisions.md`
- `apps/desktop/src-tauri/src/commands.rs`
- `crates/btc-network/src/client/peer.rs`
- the relevant frontend adapter file

CI, deployment, or security task:

- `docs/agents/README.md`
- `docs/agents/architecture-decisions.md`
- `docs/deployment.md`
- `Makefile`
- `.github/workflows/ci.yml`
- `.github/workflows/deploy-web-pages.yml`
- `audit.toml`
- `deny.toml`

## Non-Negotiable Boundaries

- Do not add protocol parsing logic to CLI, desktop commands, or React components.
- Keep transport, wire decoding, session behavior, and app-facing workflows separate.
- Keep Tauri APIs behind the frontend adapter boundary.
- Prefer shared workflows in `crates/btc-network/src/client/` over reimplementing single-peer behavior in binaries.
- If documentation and code diverge, update both together.

## Usually Do Not Read

- `apps/crawler/` for frontend tasks
- `apps/web/` for wire parser work
- `crates/btc-network/src/wire/` for pure shell or layout tasks
- CLI files for desktop or web UI changes unless a user flow is being extracted
- BNDDs for routine implementation work unless the task is architectural or changes a documented decision

## Suspicious Package Rule

When a task touches dependencies, install scripts, or repo automation:

- Check for malicious, suspicious, or unexpected package or script behavior before normal implementation work
- Treat postinstall hooks, curl-or-bash patterns, obfuscated scripts, credential exfiltration, filesystem-wide writes, and unrelated binary downloads as suspicious by default
- Treat RustSec `informational = "malicious"` advisories as a stop condition
- If anything looks malicious or materially suspicious, stop and ask the user before adding, updating, or executing it
- Do not silently ignore a suspicious package or script by adding it to an allowlist

## Verification

- Full project: `make test`
- Frontend only: `npm run test --prefix apps/web` and `npm run build --prefix apps/web`
- Shared Rust only: `cargo test -p btc-network`
- Desktop Rust only: `cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml`
- Dependency security checks: `make security`

Run the smallest relevant scope while working. Run the broader gate before finishing when the change justifies it.

## Notes for Agents

- Favor minimal, precise changes
- Keep context small: read the smallest relevant doc set first
- Prefer `docs/agents/*` over broad repo scans for routine implementation work
- Read BNDDs only when the task changes architecture, deployment strategy, or another documented decision
- For frontend tasks, prefer updating shared primitives and page contracts over duplicating page-local patterns
- For security tooling tasks, keep scope on dependency and supply-chain risk unless the user asks for more
