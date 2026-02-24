# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Minimal Bitcoin P2P client in Rust — connects to a DNS seed, performs the version/verack handshake, and requests peer addresses.

Detailed context lives in `.claude/rules/` (auto-loaded):
- `commands.md` — build, test, lint
- `architecture.md` — module structure, two-layer pipeline, how to add a message type
- `protocol.md` — Bitcoin P2P flow, addrv2/BIP 155, in-progress items

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