# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Rust Bitcoin P2P client with explicit separation of concerns:
- `src/wire/*` for protocol framing/decoding and payload builders
- `src/session.rs` for connection/session abstraction and handshake
- `src/bin/*` for orchestration entry points (`cli`, `crawler`, `listener`)

Detailed context lives in `.claude/rules/` (auto-loaded):
- `commands.md` — build, test, lint
- `architecture.md` — module boundaries, message pipeline, extension workflow
- `protocol.md` — handshake and message behavior (addrv2, getheaders, block paths)

## Token Efficiency Policy

Optimize for minimal token usage while maintaining correctness.

Guidelines:
- Be concise and direct.
- Avoid unnecessary explanations.
- Do not repeat the question.
- Provide only the final solution unless explicitly asked for reasoning.
- Prefer compact, idiomatic code.
- Avoid long introductions or summaries.
- If assumptions are needed, state them briefly in one line.
- If the answer exceeds 200 tokens, compress it further.
