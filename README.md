# btc-network [![CI](https://github.com/iamseki/btc-network/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/iamseki/btc-network/actions/workflows/ci.yml)

A minimal Bitcoin P2P client in Rust. Reference to the protocol: https://developer.bitcoin.org/devguide/p2p_network.html#connecting-to-peers

## Current Status 

| Feature               | Status |
| --------------------- | ------ |
| version / verack      | ✅      |
| BIP155 (`addrv2`)     | ✅      |
| getaddr               | ✅      |
| getheaders            | ✅      |
| header decoding       | ✅      |
| header hash (dSHA256) | ✅      |
| iterative tip sync    | ✅      |
| block download        | ✅      |
| inv/getdata           | ⏳      |


## Architecture

The implementation is intentionally layered:

```
TcpStream
   ↓
wire (btc message envelope + framing + decoding)
   ↓
session (handshake + state machine)
   ↓
orchestration (cli, crawler, etc)
```

## Frontend Status

The repository now includes a web-first frontend scaffold under `apps/web`.

Current frontend stack:

- React
- Vite
- TypeScript
- Tailwind CSS
- shadcn/ui-style component structure

Frontend architecture rules:

- The UI is web-first and should remain deployable as a normal SPA
- Tauri is planned as a thin desktop shell, not as the frontend architecture
- React components must not import Tauri APIs directly
- The frontend must talk to an application-facing client boundary (`client.ts`)
- Desktop-specific behavior must stay isolated behind the Tauri adapter
- The frontend must not call the CLI binary as an integration mechanism

Current frontend scope mirrors the CLI:

- Connection / handshake
- Peer tools (`ping`, `get-addr`)
- Headers (`get-headers`, `last-block-header`)
- Block explorer (`get-block`, `download-block`)

Design direction:

- Clean, minimal interface
- Black / carbon base with restrained Bitcoin gold accents
- Retro instrument-panel / terminal-console feel
- Avoid unnecessary dashboard chrome or decorative noise
- Keep effects subtle enough that protocol data stays primary

See also:

- `docs/frontend-architecture.md`
- `apps/web/README.md`

## btc-cli Usage

Minimal Bitcoin P2P CLI for interacting with a single peer.

### Available Commands

Ping a node:
- `make cli ARGS="--node seed.bitcoin.sipa.be:8333 ping"`

Request peer addresses:
- `make cli ARGS="--node seed.bitcoin.sipa.be:8333 get-addr"`

Fetch headers from genesis:
- `make cli ARGS="--node seed.bitcoin.sipa.be:8333 get-headers"`

Sync headers to peer tip:
- `make cli ARGS="--node seed.bitcoin.sipa.be:8333 last-block-header"` Example output executed at at 2026-02-26 04:00 AM BR: 
  ```
  Reached peer tip.
  Total headers fetched: 938408 // that should eventually match the start_height: 938408 response in handshake Version message
  Rounds: 470
  Elapsed: 545.45s
  Most recent block: 00000000000000000000772e80a1e5c0df1bc935b5f5c2cad5533234e068afde
  ```

Get Block info:
- make cli ARGS="--node seed.bitcoin.sipa.be:8333 get-block --hash 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

Genesis block output (it must have only the coinbase tx):
```
Block hash: 6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000
Tx count: 1
Size: 0.00 MB
tx.is_coinbase => true, tx: Transaction { version: 1, inputs: 1, outputs: 1, has_witness: false, size_bytes: 204, locktime: "block height 0" }
```

Download block:

- `make cli ARGS="--node seed.bitcoin.sipa.be:8333 download-block --hash 00000000000000000000772e80a1e5c0df1bc935b5f5c2cad5533234e068afde"`
- It downloads the block as raw serialized bytes from p2p protocol,  in a `blk-{first-8-bytes-hash}-{last-6-bytes-hash}.dat` file.

## Frontend Usage

Install frontend dependencies:

- `make web-install`

Run the web UI in development mode:

- `make web-dev`

Run frontend tests:

- `make web-test`

Build the frontend for production:

- `make web-build`

Notes:

- The current UI uses placeholder/mock adapter data while the Rust desktop bridge is being wired
- The next integration step is to expose shared Rust application workflows to the Tauri adapter
- Browser deployment remains a design goal, so UI code must stay portable

## Security Checks

The repository now includes dependency security checks for both Rust and npm.

Local commands:

- `make security-tools-install`
- `make security-rust`
- `make security-web`
- `make security`

What they run:

- `cargo audit` against RustSec advisories
- `cargo deny check advisories bans sources`
- `npm audit --prefix apps/web --audit-level=high`
- `npm audit signatures --prefix apps/web`

Policy/config files:

- `deny.toml`
- `audit.toml`

Scope note:

- These checks cover dependency and supply-chain risk
- They do not replace protocol correctness tests or implementation review
- Keep `cargo test` and the existing wire/session tests as separate required checks

## Crawler Usage

The crawler starts from Bitcoin DNS seed nodes and keeps exploring peers by:
1. Handshaking with a node
2. Requesting peer addresses (`getaddr`, accepting `addrv2`/`addr`)
3. Storing node state from the `version` response
4. Diffing discovered peers against a shared `queued_nodes` set

It deduplicates by `SocketAddr` (`ip:port`) using a set, so repeated addresses from different peers are not re-queued.

Run with defaults:

- `make crawler`
- `cargo run --bin crawler`

Run with custom limits/policies:

- `cargo run --bin crawler -- --max-concurrency 1000 --max-runtime-minutes 60 --idle-timeout-minutes 5`
- `cargo run --bin crawler -- --max-concurrency 500 --max-runtime-minutes 20 --idle-timeout-minutes 3 --verbose`

Available flags:

- `--max-concurrency`: max worker tasks (default: `1000`)
- `--max-runtime-minutes`: hard stop by runtime (default: `60`)
- `--idle-timeout-minutes`: stop when no new nodes are queued in this window (default: `5`)
- `--connect-timeout-secs`: TCP connect timeout per node (default: `30`)
- `--io-timeout-secs`: read/write timeout per node session (default: `10`)
- `--verbose`: print per-node failures/details

Crawler summary output includes:

- scheduled tasks
- successful handshakes
- failed tasks
- total queued nodes
- unique discovered nodes
- captured node states
- elapsed runtime

Graceful shutdown:

- `Ctrl+C` / `SIGINT`: crawler stops scheduling new nodes and waits current workers to finish
- `SIGTERM`: same graceful behavior
- `SIGKILL`: cannot be trapped by user-space processes, so graceful shutdown is not possible

Logging modes:

- Log level/filter:
  - `RUST_LOG=info` (default)
  - examples: `RUST_LOG=debug`

### Crawler Timing Debug Workflow

For repeatable timing analysis (worker lock timing + node I/O timing), use:

- `scripts/crawler_timing.sh`

Default run:

- `scripts/crawler_timing.sh`

Run for a fixed observation window (5 minutes):

- `scripts/crawler_timing.sh artifacts/crawler-timing-run-1 --timeout-minutes 5`

Run with custom crawler flags:

- `scripts/crawler_timing.sh artifacts/crawler-timing-run-2 --timeout-minutes 5 -- --max-concurrency 300 --idle-timeout-minutes 3`

What this script does:

1. Runs crawler with `--verbose`
2. If `--timeout-minutes N` is set, maps it to crawler policy `--max-runtime-minutes N`
3. Saves full structured logs to `crawler.log`
4. Extracts only timing events (`[crawler] worker timing`, `[crawler] node timing`) to `timing.ndjson`
5. Computes aggregate metrics (`n`, `avg`, `p95`, `max`) into `timing-summary.json`

Output files (inside chosen output dir):

- `crawler.log`: all crawler logs (JSON lines)
- `timing.ndjson`: only timing events, one JSON object per line
- `timing-summary.json`: aggregated metrics for quick comparison between runs

#### Why `ndjson` and not a single JSON file?

- `ndjson` (newline-delimited JSON) stores one event per line, which matches streaming logs.
- It is append-friendly and memory-efficient for large runs.
- Tools like `jq`, `grep`, and `awk` can process it incrementally without loading the full dataset.
- A single JSON array is better for small static payloads, but less practical for long-running log capture.

Crawler TODOs:

- Measure lock contention and `Mutex` impact with deterministic benchmarks/profiling before changing synchronization primitives.
- Introduce a repository layer for crawler persistence/state storage (currently in-memory only).

---

## AI Development Context

This project uses [Claude Code](https://claude.ai/code) for AI-assisted development. The context
files follow this layout:

```
CLAUDE.md                  # entry point — loaded automatically by Claude Code
.claude/
  rules/
    commands.md            # build, test, lint commands
    architecture.md        # module structure and design decisions
    protocol.md            # Bitcoin P2P specifics and in-progress state
  settings.local.json      # personal permission overrides — not committed
```

### Convention

- **`CLAUDE.md`** — concise project summary at the repo root. Always commit it.
- **`.claude/rules/*.md`** — topic-separated context files. All `.md` files here are
  auto-loaded by Claude Code; no imports needed. Commit these too.
- **`CLAUDE.local.md`** — personal scratchpad for notes you don't want to share
  (different machines, experiments). Add it to `.gitignore`.
- **`.claude/settings.local.json`** — per-machine permission grants (tool allow/deny lists).
  Never commit. The `.local.` suffix is the Claude Code convention for personal overrides.
- **`.claude/settings.json`** — shared project-level settings (hooks, allowed tools for CI).
  Safe to commit if you create it.

> You can also use `@path/to/file` inside any rules file to import additional context.
> Paths are relative to the file containing the import; imports chain up to 5 levels deep.

### Token / Context Hygiene

To reduce wasted context and repeated reasoning during AI-assisted work:

- Read only the files directly relevant to the task
- Prefer `AGENTS.md` and `docs/frontend-architecture.md` before scanning implementation files for frontend tasks
- For frontend work, start with `apps/web/src/App.tsx`, `apps/web/src/lib/api/`, and the relevant page/component files
- Avoid re-reading crawler or wire internals unless the task actually changes protocol behavior
- Update documentation when architecture decisions change so future turns do not need to rediscover them
- For dependency security tasks, start with `Makefile`, `.github/workflows/ci.yml`, `deny.toml`, and `audit.toml`
