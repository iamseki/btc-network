# btc-network

A minimal Bitcoin P2P client in Rust. Reference to the p: https://developer.bitcoin.org/devguide/p2p_network.html#connecting-to-peers

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
| block download        | ⏳      |
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
Connecting to seed.bitcoin.sipa.be:8333
Received (ignored): SendCmpct([0, 2, 0, 0, 0, 0, 0, 0, 0])
Received (ignored): FeeFilter([232, 3, 0, 0, 0, 0, 0, 0])
Block hash: 6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000
Tx count: 1
Size: 0.00 MB
```

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
