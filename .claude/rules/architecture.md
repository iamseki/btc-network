## Architecture

### Module split

- **`src/wire/codec.rs`** — wire framing and transport helpers (`read_message`, `send_message`).
- **`src/wire/message.rs`** — `RawMessage`, `Command`, `Message`, `TryFrom<RawMessage>`, wire-domain structs.
- **`src/wire/decode.rs`** — binary decoding primitives and `Decode` impls for typed payloads.
- **`src/wire/payload.rs`** — outbound payload builders (`version`, `getheaders`, `getdata`, etc.).
- **`src/wire/constants.rs`** — protocol constants (network magic, version, genesis hash, DNS seeds).
- **`src/session.rs`** — `Session` abstraction, handshake flow, send/recv methods over `TcpStream`.
- **`src/bin/cli.rs`** — user-facing orchestration commands (`ping`, `get-addr`, `get-headers`, `last-block-header`, `get-block`).
- **`src/bin/crawler.rs`** — seed crawl flow for address discovery.
- **`src/bin/listener.rs`** — long-lived listener loop with ping->pong keepalive behavior.

### Two-layer message pipeline

```
TcpStream
   └─ wire::read_message()     → RawMessage { command, payload, magic, checksum }
        └─ Message::try_from() → Message::Version(...) | Message::Headers(...) | Message::Block(...) | ...
```

**Layer 1 — framing**: reads the 24-byte Bitcoin envelope and payload bytes.

**Layer 2 — decoding**: `TryFrom<RawMessage>` dispatches by `Command`.
- Implemented commands decode into typed variants (`Version`, `Addr`, `AddrV2`, `Headers`, `Block`).
- Others remain raw `Vec<u8>` variants until promoted to typed decode.

### Adding a new message type

1. Add/extend wire model in `src/wire/message.rs`:
   - `Command` mapping (`From<&[u8;12]>`, `as_bytes`)
   - `Message` variant
2. Add `impl Decode for YourType` in `src/wire/decode.rs` (if typed decode is desired).
3. Wire conversion in `impl TryFrom<RawMessage> for Message`:
   ```rust
   Command::Foo => Ok(Message::Foo(YourType::decode(&raw.payload)?)),
   ```
4. Add outbound payload builder in `src/wire/payload.rs` when needed.
5. Use from `Session` / `src/bin/*` orchestration without bypassing wire/session boundaries.

### Separation-of-concerns rule

- Keep protocol serialization/parsing inside `wire/*`.
- Keep connection/session state transitions in `session.rs`.
- Keep CLI/crawler/listener focused on orchestration and output.
- Avoid duplicating low-level decode logic in `src/bin/*`.
