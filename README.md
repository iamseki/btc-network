# btc-network

A minimal Bitcoin P2P client in Rust. Connects to a DNS seed, performs the handshake, and requests peer addresses.

## How it works

```
send version → read version → send verack → read verack → send getaddr → loop until addr
```

Reference: https://developer.bitcoin.org/devguide/p2p_network.html#connecting-to-peers

---

## Architecture

### Two-layer message pipeline

```
TcpStream
   └─ wire::read_message()     →  RawMessage { command: Command, payload: Vec<u8> }
        └─ Message::try_from() →  Message::Version(VersionMessage) | Message::Inv(Vec<u8>) | ...
```

**Layer 1 — framing (`wire::read_message`)**: reads the 24-byte header and raw payload bytes. No interpretation, no checksum or magic validation.

**Layer 2 — decoding (`TryFrom<RawMessage> for Message`)**: dispatches on `Command` and calls `Decode::decode` for implemented messages. Unimplemented ones pass the raw `Vec<u8>` through.

### Why separate framing from decoding

- I/O errors and parse errors are distinct failure modes; separating them makes both easier to handle and test independently.
- `Decode` impls can be unit-tested against raw byte slices without a network connection.
- Adding a new message type only touches the decoding layer.

### The `Decode` trait

```rust
pub trait Decode: Sized {
    fn decode(payload: &[u8]) -> io::Result<Self>;
}
```

Each message payload type implements `Decode` independently. `TryFrom<RawMessage>` is the only place that connects a `Command` variant to its payload type.

---

## Implementing a new message type

1. `impl Decode for YourType` in `wire.rs`
2. In `TryFrom<RawMessage>`, change:
   ```rust
   Command::Foo => Ok(Message::Foo(raw.payload)),
   ```
   to:
   ```rust
   Command::Foo => Ok(Message::Foo(YourType::decode(&raw.payload)?)),
   ```
3. Change the `Message::Foo(Vec<u8>)` variant to `Message::Foo(YourType)`

---

## Current status

| Message    | Decoded |
|------------|---------|
| `version`  | ✅      |
| `verack`   | ✅      |
| `addr`     | ✅      |
| `addrv2`   | ✅      |
| all others | raw `Vec<u8>` — TODO |

---

## Claude Code

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
