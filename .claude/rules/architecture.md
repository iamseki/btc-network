## Architecture

### Module split

- **`src/wire.rs`** — framing and decoding layer. Owns `read_message` (reads a 24-byte header +
  payload from a `TcpStream`), the `Command` enum, the `Message` enum, the `Decode` trait, and
  all payload structs (`VersionMessage`, `NetAddr`, `AddrEntry`, `AddrV2Entry`, `AddrV2Addr`).
- **`src/main.rs`** — application logic. Owns `send_message`, `build_version_payload`, and the
  P2P handshake sequence. Uses `wire::read_message` and `wire::Message` for all inbound traffic.
- **`src/mod.rs`** — leftover file, not used by the binary (`main.rs` is the crate root).

### Two-layer message pipeline

```
TcpStream
   └─ wire::read_message()     →  RawMessage { command: Command, payload: Vec<u8> }
        └─ Message::try_from() →  Message::Version(VersionMessage) | Message::Inv(Vec<u8>) | …
```

**Layer 1 — framing**: reads the fixed 24-byte header and raw payload bytes. No interpretation,
no checksum or magic validation.

**Layer 2 — decoding**: `TryFrom<RawMessage>` dispatches on `Command` and calls `Decode::decode`
for implemented messages. Unimplemented ones hold the raw `Vec<u8>` with a TODO comment.

### Adding a new message type

1. `impl Decode for YourType` in `wire.rs`
2. In `TryFrom<RawMessage>`, change:
   ```rust
   Command::Foo => Ok(Message::Foo(raw.payload)),
   ```
   to:
   ```rust
   Command::Foo => Ok(Message::Foo(YourType::decode(&raw.payload)?)),
   ```
3. Change `Message::Foo(Vec<u8>)` to `Message::Foo(YourType)`
