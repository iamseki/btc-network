# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Rust Bitcoin P2P client with explicit separation of concerns:
- `crates/btc-network/src/wire/*` for protocol framing/decoding, script/tx modeling, and payload builders
- `crates/btc-network/src/session/*` for stateful peer protocol sequencing over a connected stream
- `crates/btc-network/src/client/*` for higher-level peer workflows and app-facing summaries
- `apps/*` for orchestration entry points (`cli`, `crawler`, `listener`, `desktop`, `web`)

Detailed context lives in `.claude/rules/` (auto-loaded):
- `commands.md` — build, test, lint
- `architecture.md` — module boundaries, message pipeline, extension workflow
- `protocol.md` — handshake and message behavior (addrv2, getheaders, getdata/block paths)

Recent protocol/project capabilities to preserve:
- CLI commands include: `ping`, `get-addr`, `get-headers`, `last-block-header`, `get-block`, `download-block`
- Block requests use witness inventory type (`MSG_WITNESS_BLOCK`) for SegWit-aware block payloads
- `download-block` writes raw P2P blocks to `blk-<first8>-<last6>.dat` in blk record format
- `TxOut::script_type()` and `ScriptType::exposes_pubkey_directly()` classify output locking scripts
- `TxIn::script_sig_type()` and `TxIn::exposed_pubkey()` classify/extract input-side scriptSig patterns (heuristic)
- First crawler design artifact is at `docs/crawler-first-design.png`

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
